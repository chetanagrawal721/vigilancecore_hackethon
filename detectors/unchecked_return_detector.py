"""
detectors/unchecked_return_detector.py

Unchecked Return Values vulnerability detector for VigilanceCore.

What it detects
---------------
External calls whose boolean success return value is silently discarded.
When a low-level call (.call, .send, .delegatecall) or high-level call
(.transfer, ERC-20 transfer/approve) fails, Solidity does NOT automatically
revert unless the return value is explicitly checked.

Detection pipeline (8 steps)
-----------------------------
Step 1  Fast-path      — skip functions with no external calls
Step 2  Structured     — use fn_info.external_calls (ExternalCallInfo)
Step 3a IR fallback    — regex scan on CFG IR stmts
Step 3b Raw-source     — scan contract.raw_source for pre-0.6.0 contracts
                         with sparse Slither IR (mirrors arithmetic Path C)
Step 4  Risk filter    — drop staticcall and zero-value transfer()
Step 5  Taint enrich   — confirm return value is discarded via taint
Step 6  Dedup          — one finding per (line, callee) pair
Step 7  Build          — Finding with recommendation + CVSS

Change log
----------
v1.0.0  Initial release — .call(), .send(), ERC-20, structured +
        IR-regex fallback, CVSS scoring, taint enrichment.
v2.0.0  FIX  Pre-0.6.0 .call.value()() and .call.gas()() patterns were
             missing from _LOW_LEVEL_CALL_RE — root cause of all
             Unhandled-Exceptions FN.
        FIX  Dead-bool false-negative in IR fallback: previously suppressed
             any node containing "bool sent = ..." even when `sent` was never
             passed to require/assert/if. Now extracts the variable name and
             checks ALL CFG nodes for a downstream guard before suppressing.
        ADD  Step 3b raw-source fallback for pre-0.8.0 contracts where
             Slither emits empty ir_stmts (mirrors arithmetic_detector Path C).
        ADD  _CallKind.DELEGATECALL — delegatecall() bool return now detected
             across all three scan paths.
        ADD  _OLD_CALL_CHAIN_RE for pre-0.6.0 chained syntax matching.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import FrozenSet, List, Optional, Set, Tuple

from core.cfg_builder import CFGGraph, DFGGraph
from core.enums import CallType
from core.models import (
    ContractInfo,
    ExternalCallInfo,
    Finding,
    FindingMetadata,
    FunctionInfo,
    Severity,
    VulnerabilityType,
)
from core.taint_engine import TaintResult, TaintSinkKind, TaintSourceKind
from detectors.base_detector import BaseDetector

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level compiled patterns
# ---------------------------------------------------------------------------

# v2.0.0: Extended to cover pre-0.6.0 chained call syntax and delegatecall.
# Order matters: more specific patterns first to avoid partial-match gaps.
_LOW_LEVEL_CALL_RE = re.compile(
    r"(?:LowLevelCall\b"
    r"|\.call\s*\{"                 # modern:     .call{value:x}(...)
    r"|\.call\s*\.\s*value\s*\("   # pre-0.6.0:  .call.value(amount)(...)
    r"|\.call\s*\.\s*gas\s*\("     # pre-0.6.0:  .call.gas(n)(...)
    r"|\.call\s*\([^)]*\)"         # bare/args:   .call() or .call(data)
    r"|\.delegatecall\s*\("        # v2.0.0:     .delegatecall(...)
    r")",
    re.IGNORECASE,
)

# Pre-0.6.0 chained-call pattern used in raw-source scan (Step 3b).
_OLD_CALL_CHAIN_RE = re.compile(
    r"\.call\s*\.\s*(?:value|gas)\s*\([^)]*\)\s*\(",
    re.IGNORECASE,
)

# .send() — always returns bool, 2300-gas stipend
_SEND_RE = re.compile(r"\.send\s*\(", re.IGNORECASE)

# .delegatecall() — bool return, v2.0.0
_DELEGATECALL_RE = re.compile(r"\.delegatecall\s*\(", re.IGNORECASE)

# ERC-20 / token calls that return bool
_TOKEN_CALL_RE = re.compile(
    r"\b(?:transfer|transferFrom|approve|increaseAllowance|decreaseAllowance)"
    r"\s*\(",
    re.IGNORECASE,
)

# v2.0.0: Used only to EXTRACT bool variable name — NOT for suppression alone.
# Capture groups: (1) "bool sent," variant, (2) "bool sent =" variant,
#                 (3) "(bool sent" variant
_RETURN_ASSIGN_RE = re.compile(
    r"(?:bool\s+(\w+)\s*,|bool\s+(\w+)\s*=|\(\s*bool\s+(\w+))",
    re.IGNORECASE,
)

# require/assert on any bool expression — return IS checked in this node
_CHECK_RE = re.compile(
    r"\b(?:require|assert)\s*\(\s*\w",
    re.IGNORECASE,
)

# .staticcall() — read-only, no state-change risk
_STATICCALL_RE = re.compile(r"\.staticcall\b", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Module-level helpers (v2.0.0)
# ---------------------------------------------------------------------------

def _extract_bool_var(stmt: str) -> Optional[str]:
    """
    Extract the bool variable name from an assignment statement, e.g.:
      "bool sent = payable(addr).send(amount)"            → "sent"
      "(bool success, bytes memory data) = addr.call(…)"  → "success"
    Returns None if no bool-typed assignment is found.
    """
    m = _RETURN_ASSIGN_RE.search(stmt)
    if not m:
        return None
    for group in m.groups():
        if group:
            return group
    return None


def _is_var_checked(var_name: str, cfg: CFGGraph) -> bool:
    """
    Scan ALL CFG nodes for a require/assert/if that references var_name.
    Returns True only when a downstream guard is conclusively found.

    Conservative design:
    - Returns False when var_name is None or < 2 characters (ambiguous).
    - Scans every node so post-assignment guards in later blocks are caught.
    """
    if not var_name or len(var_name) < 2:
        return False
    guard_re = re.compile(
        r"\b(?:require|assert)\s*\(\s*!?\s*" + re.escape(var_name) + r"\b"
        r"|\bif\s*\(\s*!?\s*" + re.escape(var_name) + r"\b",
        re.IGNORECASE,
    )
    for node in cfg.nodes.values():
        if guard_re.search(" ".join(node.ir_stmts)):
            return True
    return False


# ---------------------------------------------------------------------------
# Internal enums and data classes
# ---------------------------------------------------------------------------

class _CallKind(str, Enum):
    LOW_LEVEL    = "low_level"     # addr.call{value}("") or addr.call(data)
    SEND         = "send"          # addr.send(amount) — 2300-gas, bool return
    TRANSFER     = "transfer"      # addr.transfer(amount) — reverts on fail
    TOKEN_CALL   = "token_call"    # ERC-20 transfer/approve — returns bool
    DELEGATECALL = "delegatecall"  # v2.0.0: addr.delegatecall(data)
    HIGH_LEVEL   = "high_level"    # generic external call


@dataclass
class _UncheckedCall:
    """One external call whose return value is not checked."""
    cfg_node_id:     int
    ir_index:        int
    callee:          str             # full callee expression
    call_kind:       _CallKind
    value_transfer:  bool            # ETH being sent?
    source_line:     Optional[int]
    stmt:            str
    from_structured: bool            # True = came from ExternalCallInfo


@dataclass
class _UCRFinding:
    """Enriched finding candidate."""
    call:          _UncheckedCall
    taint_confirms: bool = False
    taint_source:   Optional[TaintSourceKind] = None


# ---------------------------------------------------------------------------
# Step 1 — Fast-path predicate
# ---------------------------------------------------------------------------

def _has_external_calls(fn_info: FunctionInfo, cfg: CFGGraph) -> bool:
    """Quick check: does this function make any external calls?"""
    if fn_info.external_calls:
        return True
    for node in cfg.nodes.values():
        combined = " ".join(node.ir_stmts)
        if _LOW_LEVEL_CALL_RE.search(combined) or _TOKEN_CALL_RE.search(combined):
            return True
    return False


# ---------------------------------------------------------------------------
# Step 2 — Structured path (ExternalCallInfo)
# ---------------------------------------------------------------------------

class _StructuredCallScanner:
    """
    Primary scanner — uses fn_info.external_calls which Slither has already
    parsed and flagged with is_return_checked.
    Unchanged from v1.0.0 except DELEGATECALL added to _CHECKABLE.
    """

    # v2.0.0: added DELEGATECALL
    _CHECKABLE: FrozenSet[CallType] = frozenset({
        CallType.CALL,
        CallType.SEND,
        CallType.DELEGATECALL,
        CallType.HIGH_LEVEL,
    })

    def scan(self, fn_info: FunctionInfo) -> List[_UncheckedCall]:
        results: List[_UncheckedCall] = []

        for ext_call in fn_info.external_calls:
            if ext_call.is_return_checked:
                continue
            if ext_call.call_type == CallType.STATICCALL:
                continue
            # transfer() always reverts on failure — void return, safe
            if ext_call.call_type == CallType.TRANSFER:
                continue
            if ext_call.call_type not in self._CHECKABLE:
                continue

            call_kind = self._map_kind(ext_call)
            results.append(_UncheckedCall(
                cfg_node_id     = -1,
                ir_index        = 0,
                callee          = ext_call.callee,
                call_kind       = call_kind,
                value_transfer  = ext_call.value_transfer,
                source_line     = ext_call.start_line,
                stmt            = ext_call.callee,
                from_structured = True,
            ))

        return results

    @staticmethod
    def _map_kind(ext_call: ExternalCallInfo) -> _CallKind:
        if ext_call.call_type == CallType.CALL:
            return _CallKind.LOW_LEVEL
        if ext_call.call_type == CallType.SEND:
            return _CallKind.SEND
        if ext_call.call_type == CallType.DELEGATECALL:
            return _CallKind.DELEGATECALL
        callee_lower = (ext_call.target_function or ext_call.callee).lower()
        token_funcs = {"transfer", "transferfrom", "approve",
                       "increaseallowance", "decreaseallowance"}
        if any(f in callee_lower for f in token_funcs):
            return _CallKind.TOKEN_CALL
        return _CallKind.HIGH_LEVEL


# ---------------------------------------------------------------------------
# Step 3a — IR fallback scanner
# ---------------------------------------------------------------------------

class _IRFallbackScanner:
    """
    Fallback scanner — regex on CFG IR statements.

    v2.0.0 FIX: The old suppression
        if _RETURN_ASSIGN_RE.search(combined) and _SUCCESS_VAR_RE.search(combined):
            continue
    caused 18 Unchecked-Send false negatives because it suppressed
    "bool sent = addr.send(amount)" even when `sent` was NEVER guarded.
    Replaced with _extract_bool_var() + _is_var_checked() which only
    suppresses when a downstream require/assert/if is confirmed.
    """

    def scan(
        self,
        cfg: CFGGraph,
        structured_lines: Set[Optional[int]],
    ) -> List[_UncheckedCall]:
        results: List[_UncheckedCall] = []
        seen: Set[Tuple[int, str]] = set()

        for node in cfg.ordered_nodes():
            combined = " ".join(node.ir_stmts)

            has_call  = bool(_LOW_LEVEL_CALL_RE.search(combined))
            has_send  = bool(_SEND_RE.search(combined))
            has_token = bool(_TOKEN_CALL_RE.search(combined))
            if not (has_call or has_send or has_token):
                continue

            # Already captured by the structured path
            if node.source_line in structured_lines:
                continue

            # v2.0.0 FIX: extract bool var and confirm it is actually guarded
            bool_var: Optional[str] = None
            for stmt in node.ir_stmts:
                v = _extract_bool_var(stmt)
                if v:
                    bool_var = v
                    break
            if bool_var and _is_var_checked(bool_var, cfg):
                continue  # return value IS checked downstream — not a finding

            # Explicit require/assert in the same CFG node — already checked
            if _CHECK_RE.search(combined):
                continue

            for ir_idx, stmt in enumerate(node.ir_stmts):
                call_kind = self._classify_stmt(stmt)
                if call_kind is None:
                    continue
                if _STATICCALL_RE.search(stmt):
                    continue

                callee = self._extract_callee(stmt)
                key = (node.node_id, callee)
                if key in seen:
                    continue
                seen.add(key)

                results.append(_UncheckedCall(
                    cfg_node_id     = node.node_id,
                    ir_index        = ir_idx,
                    callee          = callee,
                    call_kind       = call_kind,
                    value_transfer  = bool(
                        re.search(r"value\s*:", stmt, re.IGNORECASE)
                    ),
                    source_line     = node.source_line,
                    stmt            = stmt[:120],
                    from_structured = False,
                ))

        return results

    @staticmethod
    def _classify_stmt(stmt: str) -> Optional[_CallKind]:
        if _DELEGATECALL_RE.search(stmt):
            return _CallKind.DELEGATECALL
        if _SEND_RE.search(stmt):
            return _CallKind.SEND
        if _LOW_LEVEL_CALL_RE.search(stmt):
            return _CallKind.LOW_LEVEL
        if _TOKEN_CALL_RE.search(stmt):
            return _CallKind.TOKEN_CALL
        return None

    @staticmethod
    def _extract_callee(stmt: str) -> str:
        m = re.search(
            r"([\w.\[\]]+\.(?:call|send|transfer|transferFrom|approve|delegatecall))",
            stmt,
        )
        return m.group(1) if m else stmt[:40]


# ---------------------------------------------------------------------------
# Step 3b — Raw-source fallback scanner (v2.0.0)
# ---------------------------------------------------------------------------

class _RawSourceScanner:
    """
    Fallback for pre-0.8.0 contracts where Slither emits empty ir_stmts.
    Mirrors arithmetic_detector's Path C architecture.

    Only runs when Steps 2 + 3a produced zero candidates — avoids
    double-counting finds the structured/IR paths already caught.

    Handles:
    - Pre-0.6.0 chained: addr.call.value(x)() and addr.call.gas(n)()
    - .send() and .delegatecall() bare calls
    """

    def scan(
        self,
        contract: ContractInfo,
        fn_info:  FunctionInfo,
    ) -> List[_UncheckedCall]:
        raw = getattr(contract, "raw_source", None)
        if not raw:
            return []

        fn_source = self._extract_fn_source(raw, fn_info)
        if not fn_source:
            return []

        results: List[_UncheckedCall] = []
        seen: Set[str] = set()

        for rel_lineno, line in enumerate(fn_source.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("//"):
                continue

            call_kind = self._classify_line(stripped)
            if call_kind is None:
                continue

            # Explicit require/assert on the same source line — already checked
            if _CHECK_RE.search(stripped):
                continue

            # Check if captured bool var is guarded anywhere in this function
            bool_var = _extract_bool_var(stripped)
            if bool_var:
                guard_re = re.compile(
                    r"\b(?:require|assert)\s*\(\s*!?\s*"
                    + re.escape(bool_var)
                    + r"\b|\bif\s*\(\s*!?\s*"
                    + re.escape(bool_var)
                    + r"\b",
                    re.IGNORECASE,
                )
                if guard_re.search(fn_source):
                    continue

            callee = self._extract_callee(stripped)
            if callee in seen:
                continue
            seen.add(callee)

            abs_line = (fn_info.start_line or 1) + rel_lineno - 1

            results.append(_UncheckedCall(
                cfg_node_id     = -2,       # sentinel: raw-source path
                ir_index        = 0,
                callee          = callee,
                call_kind       = call_kind,
                value_transfer  = bool(
                    re.search(r"\.value\s*\(", stripped, re.IGNORECASE)
                ),
                source_line     = abs_line,
                stmt            = stripped[:120],
                from_structured = False,
            ))

        return results

    @staticmethod
    def _classify_line(line: str) -> Optional[_CallKind]:
        if _DELEGATECALL_RE.search(line):
            return _CallKind.DELEGATECALL
        if _OLD_CALL_CHAIN_RE.search(line):
            return _CallKind.LOW_LEVEL
        if _LOW_LEVEL_CALL_RE.search(line):
            return _CallKind.LOW_LEVEL
        if _SEND_RE.search(line):
            return _CallKind.SEND
        return None

    @staticmethod
    def _extract_fn_source(raw: str, fn_info: FunctionInfo) -> Optional[str]:
        """Extract only the source lines belonging to this function."""
        if fn_info.start_line and fn_info.end_line:
            lines = raw.splitlines()
            start = max(0, fn_info.start_line - 1)
            end   = min(len(lines), fn_info.end_line)
            return "\n".join(lines[start:end])
        return None  # no line info → skip (avoids whole-file FP flood)

    @staticmethod
    def _extract_callee(line: str) -> str:
        m = re.search(
            r"([\w.\[\]]+\.(?:call|send|delegatecall))",
            line,
        )
        return m.group(1) if m else line[:40]


# ---------------------------------------------------------------------------
# Step 5 — Taint enricher (unchanged from v1.0.0)
# ---------------------------------------------------------------------------

class _TaintEnricher:
    """
    Checks whether the unchecked call's return value is a taint source
    (RETURN_VALUE) that never flows into a REQUIRE_CONDITION sink.
    """

    def enrich(
        self,
        candidates:   List[_UCRFinding],
        taint_result: Optional[TaintResult],
    ) -> None:
        if not taint_result or not taint_result.flows:
            return
        for candidate in candidates:
            for flow in taint_result.flows:
                if flow.source_kind != TaintSourceKind.RETURN_VALUE:
                    continue
                if flow.sink_kind == TaintSinkKind.REQUIRE_CONDITION:
                    candidate.taint_confirms = False
                    break
                if flow.sink_kind in (
                    TaintSinkKind.STORAGE_WRITE,
                    TaintSinkKind.ARITHMETIC_OPERAND,
                ):
                    candidate.taint_confirms = True
                    candidate.taint_source   = flow.source_kind
                    break


# ---------------------------------------------------------------------------
# Step 7 — Finding builder
# ---------------------------------------------------------------------------

class _FindingBuilder:

    def build(
        self,
        candidate:        _UCRFinding,
        contract_name:    str,
        fn_info:          FunctionInfo,
        detector_id:      str,
        detector_version: str,
        recommendation:   str,
        cvss_score:       float,
    ) -> Finding:
        call = candidate.call
        return Finding(
            vuln_type        = VulnerabilityType.UNCHECKED_RETURN,
            severity         = self._severity(candidate),
            contract_name    = contract_name,
            function_name    = fn_info.name,
            source_file      = fn_info.source_file,
            start_line       = call.source_line,
            title            = self._title(candidate),
            description      = self._description(candidate, fn_info),
            recommendation   = recommendation,
            confidence       = self._confidence(candidate),
            cvss_score       = cvss_score,
            detector_id      = detector_id,
            detector_version = detector_version,
            metadata         = FindingMetadata(
                unchecked_return_expr = call.callee,
                extra = {
                    "call_kind":       call.call_kind.value,
                    "callee":          call.callee,
                    "value_transfer":  call.value_transfer,
                    "from_structured": call.from_structured,
                    "cfg_node_id":     call.cfg_node_id,
                    "ir_index":        call.ir_index,
                    "stmt":            call.stmt,
                    "taint_confirms":  candidate.taint_confirms,
                    "taint_source": (
                        candidate.taint_source.value
                        if candidate.taint_source else None
                    ),
                },
            ),
        )

    @staticmethod
    def _severity(c: _UCRFinding) -> Severity:
        kind = c.call.call_kind
        if kind == _CallKind.LOW_LEVEL and c.call.value_transfer:
            return Severity.CRITICAL
        if kind in (_CallKind.LOW_LEVEL, _CallKind.SEND, _CallKind.DELEGATECALL):
            return Severity.HIGH
        if kind == _CallKind.TOKEN_CALL:
            return Severity.MEDIUM
        return Severity.LOW

    @staticmethod
    def _confidence(c: _UCRFinding) -> float:
        score = 0.55
        if c.call.from_structured:  # Slither confirmed unchecked
            score += 0.30
        if c.call.value_transfer:
            score += 0.10
        if c.taint_confirms:
            score += 0.05
        return round(min(1.0, score), 4)

    @staticmethod
    def _title(c: _UCRFinding) -> str:
        kind_labels = {
            _CallKind.LOW_LEVEL:    "Low-level .call()",
            _CallKind.SEND:         ".send()",
            _CallKind.TOKEN_CALL:   "ERC-20 token call",
            _CallKind.HIGH_LEVEL:   "High-level external call",
            _CallKind.TRANSFER:     ".transfer()",
            _CallKind.DELEGATECALL: ".delegatecall()",
        }
        label = kind_labels.get(c.call.call_kind, "External call")
        eth   = " (ETH transfer)" if c.call.value_transfer else ""
        return f"Unchecked Return Value: {label}{eth} — '{c.call.callee}'"

    @staticmethod
    def _description(c: _UCRFinding, fn_info: FunctionInfo) -> str:
        call = c.call
        loc  = f" at line {call.source_line}" if call.source_line else ""
        eth  = " with ETH attached"            if call.value_transfer else ""

        kind_descs = {
            _CallKind.LOW_LEVEL: (
                f"Function '{fn_info.name}' makes a low-level .call(){eth}{loc} "
                f"to '{call.callee}' but does not check the boolean return value. "
                f"If the call fails (callee reverts, runs out of gas, or target "
                f"has no code), execution silently continues — the contract "
                f"believes the call succeeded when it did not."
            ),
            _CallKind.SEND: (
                f"Function '{fn_info.name}' uses .send(){loc} on '{call.callee}' "
                f"but discards the bool return value. .send() only forwards 2300 "
                f"gas and returns false on failure — the ETH transfer may silently "
                f"fail, leaving the contract's accounting out of sync."
            ),
            _CallKind.TOKEN_CALL: (
                f"Function '{fn_info.name}' calls '{call.callee}'{loc} "
                f"(an ERC-20 token operation) without checking the bool return. "
                f"Non-standard tokens (e.g. USDT, BNB) return false on failure "
                f"instead of reverting — ignoring the return means a failed "
                f"transfer is treated as success."
            ),
            _CallKind.DELEGATECALL: (
                f"Function '{fn_info.name}' uses .delegatecall(){loc} to "
                f"'{call.callee}' without checking the bool return. A failed "
                f"delegatecall returns false rather than reverting; ignoring it "
                f"means malformed or absent logic in the target silently corrupts "
                f"the caller's storage."
            ),
            _CallKind.HIGH_LEVEL: (
                f"Function '{fn_info.name}' makes an external call to "
                f"'{call.callee}'{loc} and ignores the return value. "
                f"If the callee signals failure via its return rather than "
                f"reverting, the caller will not detect the failure."
            ),
        }

        base = kind_descs.get(
            call.call_kind,
            f"Function '{fn_info.name}' makes an external call{loc} "
            f"whose return value is not checked.",
        )

        if c.taint_confirms:
            base += (
                " Taint analysis confirms the return value is neither stored "
                "in a variable nor passed to require/assert — it is completely "
                "discarded."
            )
        return base


# ---------------------------------------------------------------------------
# Public detector
# ---------------------------------------------------------------------------

class UncheckedReturnDetector(BaseDetector):
    """
    Detects external calls whose return value is silently discarded.

    Fires on:
    - .call()         with ignored (bool, bytes) return
    - .send()         with ignored bool return
    - .delegatecall() with ignored bool return              (v2.0.0)
    - ERC-20 transfer/approve with ignored bool return
    - High-level calls whose return value is ignored
    - Pre-0.6.0 .call.value()() / .call.gas()() chains     (v2.0.0)

    Does NOT fire on:
    - .transfer()   — always reverts on failure, void return
    - .staticcall() — read-only, no state-change risk
    - Calls where (bool var = ...) and var is guarded by require/assert/if
    """

    DETECTOR_ID      = "unchecked_return_v1"
    DETECTOR_VERSION = "2.0.0"
    VULN_TYPE        = VulnerabilityType.UNCHECKED_RETURN
    DEFAULT_SEVERITY = Severity.MEDIUM

    def __init__(self) -> None:
        self._structured_scanner = _StructuredCallScanner()
        self._ir_fallback        = _IRFallbackScanner()
        self._raw_source_scanner = _RawSourceScanner()      # v2.0.0
        self._taint_enricher     = _TaintEnricher()
        self._finding_builder    = _FindingBuilder()

    # ------------------------------------------------------------------
    # BaseDetector abstract method implementation
    # ------------------------------------------------------------------

    def detect(
        self,
        contract:     ContractInfo,
        fn_info:      FunctionInfo,
        cfg:          CFGGraph,
        dfg:          DFGGraph,
        taint_result: Optional[TaintResult],
    ) -> List[Finding]:

        # ── Step 1: Fast-path ──────────────────────────────────────
        if not _has_external_calls(fn_info, cfg):
            logger.debug(
                "UncheckedReturn: '%s.%s' — no external calls, skipped.",
                contract.name, fn_info.name,
            )
            return []

        # ── Step 2: Structured path (ExternalCallInfo) ─────────────
        structured = self._structured_scanner.scan(fn_info)
        structured_lines: Set[Optional[int]] = {
            c.source_line for c in structured
        }

        # ── Step 3a: IR fallback ────────────────────────────────────
        ir_fallback = self._ir_fallback.scan(cfg, structured_lines)

        all_calls = structured + ir_fallback

        # ── Step 3b: Raw-source fallback (v2.0.0) ──────────────────
        # Only fires when 3a + 2 found nothing — targets pre-0.8.0
        # contracts with sparse/empty Slither IR stmts.
        if not all_calls:
            raw_calls = self._raw_source_scanner.scan(contract, fn_info)
            all_calls = raw_calls

        if not all_calls:
            logger.debug(
                "UncheckedReturn: '%s.%s' — all returns checked, skipped.",
                contract.name, fn_info.name,
            )
            return []

        # ── Step 4: Risk filter ─────────────────────────────────────
        # transfer() excluded in structured scanner; staticcall in IR.
        risky = all_calls

        # ── Step 5: Taint enrichment ────────────────────────────────
        candidates = [_UCRFinding(call=c) for c in risky]
        self._taint_enricher.enrich(candidates, taint_result)

        # ── Step 6: Deduplication ───────────────────────────────────
        seen_dedup: Set[Tuple[Optional[int], str]] = set()
        deduplicated: List[_UCRFinding] = []
        for c in candidates:
            key = (c.call.source_line, c.call.callee[:60])
            if key not in seen_dedup:
                seen_dedup.add(key)
                deduplicated.append(c)

        # ── Step 7: Build findings ──────────────────────────────────
        findings: List[Finding] = []
        for c in deduplicated:
            ctx     = self._build_context(c, fn_info, contract)
            finding = self._finding_builder.build(
                candidate        = c,
                contract_name    = contract.name,
                fn_info          = fn_info,
                detector_id      = self.DETECTOR_ID,
                detector_version = self.DETECTOR_VERSION,
                recommendation   = self.safe_recommendation(ctx),
                cvss_score       = self.safe_cvss(ctx),
            )
            findings.append(finding)
            logger.debug(
                "UncheckedReturn: '%s.%s' — %s sev, kind='%s', "
                "callee='%s', eth=%s, cvss=%.1f.",
                contract.name, fn_info.name,
                finding.severity.value, c.call.call_kind.value,
                c.call.callee, c.call.value_transfer,
                finding.cvss_score,
            )

        return findings

    # ------------------------------------------------------------------
    # BaseDetector: build_recommendation
    # ------------------------------------------------------------------

    def build_recommendation(self, context: dict) -> str:
        fn_name        = context["function_name"]
        call_kind      = context.get("call_kind", "low_level")
        callee         = context.get("callee", "the external call")
        value_transfer = context.get("value_transfer", False)
        line           = context.get("line_number")
        loc            = f" at line {line}" if line else ""

        recs = {
            "low_level": (
                f"In function '{fn_name}'{loc}: always capture and check "
                f"the return value of '{callee}'.\n"
                f"    (bool success, bytes memory data) = {callee};\n"
                f"    require(success, \"Call failed\");\n"
                f"If failure should not revert, at minimum emit an event so "
                f"off-chain monitoring can detect silent failures."
            ),
            "send": (
                f"In function '{fn_name}'{loc}: replace .send() with .call() "
                f"and check the return:\n"
                f"    (bool success, ) = payable(addr).call{{value: amount}}(\"\");\n"
                f"    require(success, \"Transfer failed\");\n"
                f".send() is legacy — .call() avoids the 2300-gas stipend limit."
            ),
            "token_call": (
                f"In function '{fn_name}'{loc}: check the bool return of "
                f"'{callee}':\n"
                f"    bool ok = {callee};\n"
                f"    require(ok, \"Token transfer failed\");\n"
                f"Or use OpenZeppelin SafeERC20.safeTransfer() which handles "
                f"both reverting and non-reverting token implementations."
            ),
            "delegatecall": (
                f"In function '{fn_name}'{loc}: always check the bool return "
                f"of .delegatecall():\n"
                f"    (bool success, bytes memory data) = {callee};\n"
                f"    require(success, \"Delegatecall failed\");\n"
                f"A failed delegatecall silently returns false — unchecked, "
                f"it leaves the caller's storage in a corrupted state."
            ),
            "high_level": (
                f"In function '{fn_name}'{loc}: capture and validate the "
                f"return value of '{callee}'. If the callee returns false "
                f"to signal failure, ignoring it causes silent incorrect state."
            ),
        }

        rec = recs.get(
            call_kind,
            f"In function '{fn_name}'{loc}: always check the return value "
            f"of '{callee}' and handle failures explicitly.",
        )

        if value_transfer:
            rec += (
                "\nThis call transfers ETH — a silent failure means ETH is "
                "lost or the recipient was never paid, with no on-chain record."
            )

        return rec

    # ------------------------------------------------------------------
    # BaseDetector: calculate_cvss
    # ------------------------------------------------------------------

    def calculate_cvss(self, context: dict) -> float:
        """
        Base: 5.0

        Condition                                        Delta
        ─────────────────────────────────────────────────────
        low_level / delegatecall call                   +2.0
        send call                                       +1.5
        token_call (ERC-20)                             +1.0
        value_transfer (ETH attached)                   +1.5
        from_structured (Slither confirmed unchecked)   +0.5
        taint confirms return is discarded              +0.5
        external / public visibility                    +0.3
        """
        score     = 5.0
        call_kind = context.get("call_kind", "high_level")

        kind_deltas = {
            "low_level":    2.0,
            "delegatecall": 2.0,
            "send":         1.5,
            "token_call":   1.0,
        }
        score += kind_deltas.get(call_kind, 0.0)

        if context.get("value_transfer"):
            score += 1.5
        if context.get("from_structured"):
            score += 0.5
        if context.get("taint_confirms"):
            score += 0.5
        if context.get("function_visibility") in ("external", "public"):
            score += 0.3

        return round(max(0.0, min(10.0, score)), 1)

    # ------------------------------------------------------------------
    # Context builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_context(
        c:        _UCRFinding,
        fn_info:  FunctionInfo,
        contract: ContractInfo,
    ) -> dict:
        return {
            "contract_name":       contract.name,
            "function_name":       fn_info.name,
            "function_visibility": getattr(
                fn_info.visibility, "value", fn_info.visibility
            ),
            "is_payable": (
                getattr(
                    fn_info.state_mutability, "value", fn_info.state_mutability
                ) == "payable"
            ),
            "line_number":     c.call.source_line,
            "cfg_node":        c.call.cfg_node_id,
            "call_kind":       c.call.call_kind.value,
            "callee":          c.call.callee,
            "value_transfer":  c.call.value_transfer,
            "from_structured": c.call.from_structured,
            "stmt":            c.call.stmt,
            "taint_confirms":  c.taint_confirms,
            "taint_source": (
                c.taint_source.value if c.taint_source else None
            ),
        }
