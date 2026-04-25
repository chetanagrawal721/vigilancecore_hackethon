"""
detectors/delegatecall_detector.py

Delegatecall vulnerability detector for VigilanceCore.

What it detects
---------------
Dangerous uses of delegatecall where the call target is controllable
by an external actor, or where delegatecall is used in upgrade patterns
without sufficient guards — giving an attacker the ability to execute
arbitrary code inside YOUR contract's storage context.

Why this matters
----------------
delegatecall is unique among Ethereum call types:

  Normal .call()         — runs callee code in CALLEE's storage context
  .delegatecall()        — runs callee code in CALLER's storage context

This means if an attacker controls the target of a delegatecall, they
can run ANY code — including selfdestruct, storage wipes, ownership
transfers — and it all executes against YOUR contract's state and balance.

The Parity Multisig hack (2017) — $30M lost — was a delegatecall to a
library whose initialiser could be called by anyone, wiping ownership.

Three risk vectors covered
--------------------------
  Vector 1 — User-controlled target
    The delegatecall target comes from msg.data, calldata, a function
    parameter, or a user-writable storage slot. Attacker picks the
    implementation address → arbitrary code execution in your storage.

      function forward(address impl, bytes calldata data) external {
          impl.delegatecall(data);   // ← impl is user-supplied
      }

  Vector 2 — Unguarded upgrade function
    A setImplementation() / upgradeTo() function that updates the
    delegatecall target has no access control. Any caller can point
    the proxy to a malicious implementation.

      function upgradeTo(address newImpl) external {   // no onlyOwner!
          implementation = newImpl;
      }

  Vector 3 — Delegatecall in a loop or to address(0)
    delegatecall inside a loop is gas-dangerous and the zero-address
    check being absent means a misconfigured proxy silently no-ops every
    call instead of reverting loudly.

Detection pipeline (7 steps)
-----------------------------
  Step 1  Fast-path    — skip if no delegatecall in IR or external calls
  Step 2  Structured   — use fn_info.external_calls for confirmed calls
  Step 3  IR scan      — regex fallback for unresolved delegatecalls
  Step 4  Target taint — is the target user-controlled (taint source)?
  Step 5  Guard check  — is there an access control modifier / require?
  Step 6  Dedup        — one finding per (node, target_expr) pair
  Step 7  Build        — Finding with safe_recommendation + safe_cvss

Change log
----------
  v1.0.0  Initial release — covers user-controlled target, unguarded
          upgrade, delegatecall to zero address, delegatecall in loop.
          Structured ExternalCallInfo path + IR regex fallback.
          Taint enrichment, CVSS scoring.
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

# delegatecall in IR statements
_DELEGATECALL_RE = re.compile(
    r"\bdelegatecall\b",
    re.IGNORECASE,
)

# User-supplied / tainted target patterns
_USER_TARGET_RE = re.compile(
    r"\b(?:msg\.data|_impl|impl|target|addr|logic|delegate"
    r"|implementation|newImpl|_target|_logic|_address)\b",
    re.IGNORECASE,
)

# Upgrade-related function names
_UPGRADE_FN_RE = re.compile(
    r"\b(?:upgradeTo|upgradeToAndCall|_upgradeTo|setImplementation"
    r"|setLogic|setDelegate|updateImplementation|changeImplementation"
    r"|migrate|migrateImplementation)\b",
    re.IGNORECASE,
)

# Zero-address check presence
_ZERO_ADDR_RE = re.compile(
    r"address\s*\(\s*0\s*\)"
    r"|!=\s*address\s*\(\s*0\s*\)"
    r"|require\s*\([^)]*!=\s*address",
    re.IGNORECASE,
)

# Access control modifiers — same set as access_control_detector
_ACCESS_MOD_RE = re.compile(
    r"\b(?:onlyOwner|onlyAdmin|onlyGovernance|onlyRole"
    r"|onlyOperator|onlyController|requiresAuth"
    r"|onlyProxy|ifAdmin|_checkOwner|_onlyOwner)\b",
    re.IGNORECASE,
)

# Access check in IR — require(msg.sender == owner) pattern
_ACCESS_CHECK_RE = re.compile(
    r"(?:require|assert)\s*\([^)]*msg\.sender"
    r"|msg\.sender\s*==\s*\w+"
    r"|\w+\s*==\s*msg\.sender",
    re.IGNORECASE,
)

# Loop body markers
_LOOP_LABEL_RE = re.compile(
    r"\b(?:BEGIN_LOOP|END_LOOP|IF_LOOP|FOR_LOOP|WHILE|DO_WHILE|LOOP)\b",
    re.IGNORECASE,
)

# calldata / msg.data forwarded — common proxy pattern that is risky
_CALLDATA_FWD_RE = re.compile(
    r"\bmsg\.data\b|\bcalldata\b|\b_data\b|\bdata\b",
    re.IGNORECASE,
)

# Attacker-controllable taint sources
_ATTACKER_SOURCES: FrozenSet[TaintSourceKind] = frozenset({
    TaintSourceKind.MSG_SENDER,
    TaintSourceKind.MSG_VALUE,
    TaintSourceKind.FUNCTION_PARAM,
    TaintSourceKind.CALLDATA,
    TaintSourceKind.STORAGE_READ,
})


# ---------------------------------------------------------------------------
# Internal enums and data classes
# ---------------------------------------------------------------------------

class _DelegateVector(str, Enum):
    USER_CONTROLLED  = "user_controlled_target"   # target from user input
    UNGUARDED_UPGRADE = "unguarded_upgrade"        # upgrade fn, no access check
    IN_LOOP          = "delegatecall_in_loop"      # inside a loop (gas/logic risk)
    ZERO_ADDR        = "missing_zero_check"        # no address(0) guard
    UNGUARDED        = "unguarded_delegatecall"    # no access check on caller


@dataclass
class _DelegateCall:
    """One delegatecall found in the function."""
    cfg_node_id:     int
    ir_index:        int
    target_expr:     str             # the target address expression
    data_expr:       Optional[str]   # the calldata being forwarded
    vector:          _DelegateVector
    has_access_guard: bool           # modifier or require(msg.sender...) present
    has_zero_check:  bool            # address(0) guard present
    in_loop:         bool
    source_line:     Optional[int]
    stmt:            str
    from_structured: bool


@dataclass
class _DelegateFinding:
    """Enriched finding candidate."""
    call:           _DelegateCall
    taint_confirms: bool                      = False
    taint_source:   Optional[TaintSourceKind] = None


# ---------------------------------------------------------------------------
# Step 1 — Fast-path predicate
# ---------------------------------------------------------------------------

def _has_delegatecall(fn_info: FunctionInfo, cfg: CFGGraph) -> bool:
    """Quick check: any delegatecall in this function?"""
    for ext in fn_info.external_calls:
        if ext.call_type == CallType.DELEGATECALL:
            return True
    for node in cfg.nodes.values():
        if _DELEGATECALL_RE.search(" ".join(node.ir_stmts)):
            return True
    return False


# ---------------------------------------------------------------------------
# Guard checker (shared between Step 2 and Step 3)
# ---------------------------------------------------------------------------

def _has_access_guard(fn_info: FunctionInfo, cfg: CFGGraph) -> bool:
    """
    Returns True if the function has a recognised access control guard:
      - a modifier whose name matches _ACCESS_MOD_RE
      - a require(msg.sender == ...) anywhere in the CFG
    """
    for mod in fn_info.modifiers:
        if _ACCESS_MOD_RE.search(mod):
            return True
    for node in cfg.nodes.values():
        combined = " ".join(node.ir_stmts)
        if _ACCESS_CHECK_RE.search(combined):
            return True
    return False


def _has_zero_check(cfg: CFGGraph) -> bool:
    """Returns True if any node contains an address(0) guard."""
    for node in cfg.nodes.values():
        if _ZERO_ADDR_RE.search(" ".join(node.ir_stmts)):
            return True
    return False


def _in_loop_body(cfg_node_id: int, cfg: CFGGraph) -> bool:
    """Check whether a given node id sits inside a loop construct."""
    in_loop    = False
    loop_depth = 0
    for node in cfg.ordered_nodes():
        label = (node.label or "").upper()
        if _LOOP_LABEL_RE.search(label) and "END" not in label:
            loop_depth += 1
            in_loop = True
        if node.node_id == cfg_node_id and in_loop:
            return True
        if "END_LOOP" in label:
            loop_depth = max(0, loop_depth - 1)
            if loop_depth == 0:
                in_loop = False
    return False


# ---------------------------------------------------------------------------
# Step 2 — Structured scanner (ExternalCallInfo)
# ---------------------------------------------------------------------------

class _StructuredScanner:
    """Primary scanner — uses parsed ExternalCallInfo objects."""

    def scan(
        self,
        fn_info:          FunctionInfo,
        cfg:              CFGGraph,
        access_guard:     bool,
        zero_check:       bool,
    ) -> List[_DelegateCall]:
        results: List[_DelegateCall] = []

        for ext in fn_info.external_calls:
            if ext.call_type != CallType.DELEGATECALL:
                continue

            target      = ext.callee or "unknown"
            is_user_tgt = bool(_USER_TARGET_RE.search(target))
            in_loop     = False  # structured path has no node id; use False

            vector = self._classify(
                fn_info, target, is_user_tgt, access_guard, zero_check
            )

            results.append(_DelegateCall(
                cfg_node_id      = -1,
                ir_index         = 0,
                target_expr      = target,
                data_expr        = None,
                vector           = vector,
                has_access_guard = access_guard,
                has_zero_check   = zero_check,
                in_loop          = in_loop,
                source_line      = ext.start_line,
                stmt             = ext.callee,
                from_structured  = True,
            ))

        return results

    @staticmethod
    def _classify(
        fn_info:      FunctionInfo,
        target:       str,
        is_user_tgt:  bool,
        access_guard: bool,
        zero_check:   bool,
    ) -> _DelegateVector:
        """Choose the most severe applicable vector."""
        if is_user_tgt:
            return _DelegateVector.USER_CONTROLLED
        if _UPGRADE_FN_RE.search(fn_info.name) and not access_guard:
            return _DelegateVector.UNGUARDED_UPGRADE
        if not zero_check:
            return _DelegateVector.ZERO_ADDR
        if not access_guard:
            return _DelegateVector.UNGUARDED
        return _DelegateVector.UNGUARDED   # fallback


# ---------------------------------------------------------------------------
# Step 3 — IR fallback scanner
# ---------------------------------------------------------------------------

class _IRScanner:
    """Fallback scanner — regex on IR statements."""

    def scan(
        self,
        cfg:              CFGGraph,
        fn_info:          FunctionInfo,
        structured_lines: Set[Optional[int]],
        access_guard:     bool,
        zero_check:       bool,
    ) -> List[_DelegateCall]:
        results: List[_DelegateCall]     = []
        seen:    Set[Tuple[int, str]]    = set()

        for node in cfg.ordered_nodes():
            combined = " ".join(node.ir_stmts)
            if not _DELEGATECALL_RE.search(combined):
                continue
            if node.source_line in structured_lines:
                continue

            node_in_loop = _in_loop_body(node.node_id, cfg)

            for ir_idx, stmt in enumerate(node.ir_stmts):
                if not _DELEGATECALL_RE.search(stmt):
                    continue

                target     = self._extract_target(stmt)
                data_expr  = self._extract_data(stmt)
                is_user_tgt = bool(_USER_TARGET_RE.search(target))

                vector = self._classify(
                    fn_info, target, is_user_tgt,
                    access_guard, zero_check, node_in_loop,
                )

                key = (node.node_id, target[:40])
                if key in seen:
                    continue
                seen.add(key)

                results.append(_DelegateCall(
                    cfg_node_id      = node.node_id,
                    ir_index         = ir_idx,
                    target_expr      = target,
                    data_expr        = data_expr,
                    vector           = vector,
                    has_access_guard = access_guard,
                    has_zero_check   = zero_check,
                    in_loop          = node_in_loop,
                    source_line      = node.source_line,
                    stmt             = stmt[:120],
                    from_structured  = False,
                ))

        return results

    @staticmethod
    def _extract_target(stmt: str) -> str:
        m = re.search(
            r"([\w.[\]]+)\s*\.\s*delegatecall\b"
            r"|([\w.[\]]+)\s*,\s*delegatecall",
            stmt, re.IGNORECASE,
        )
        if m:
            return m.group(1) or m.group(2) or "unknown"
        # Slither IR sometimes: delegatecall(target, data)
        m2 = re.search(r"delegatecall\s*\(\s*([\w.[\]]+)", stmt, re.IGNORECASE)
        return m2.group(1) if m2 else "unknown"

    @staticmethod
    def _extract_data(stmt: str) -> Optional[str]:
        m = re.search(r"delegatecall\s*\([^,]+,\s*([\w.[\]]+)", stmt, re.IGNORECASE)
        return m.group(1) if m else None

    @staticmethod
    def _classify(
        fn_info:      FunctionInfo,
        target:       str,
        is_user_tgt:  bool,
        access_guard: bool,
        zero_check:   bool,
        in_loop:      bool,
    ) -> _DelegateVector:
        if is_user_tgt:
            return _DelegateVector.USER_CONTROLLED
        if _UPGRADE_FN_RE.search(fn_info.name) and not access_guard:
            return _DelegateVector.UNGUARDED_UPGRADE
        if in_loop:
            return _DelegateVector.IN_LOOP
        if not zero_check:
            return _DelegateVector.ZERO_ADDR
        if not access_guard:
            return _DelegateVector.UNGUARDED
        return _DelegateVector.UNGUARDED


# ---------------------------------------------------------------------------
# Step 4 — Taint enricher
# ---------------------------------------------------------------------------

class _TaintEnricher:
    """
    Confirms whether the delegatecall TARGET is tainted by attacker-
    controlled input — the most dangerous case.
    """

    def enrich(
        self,
        candidates:   List[_DelegateFinding],
        taint_result: Optional[TaintResult],
    ) -> None:
        if not taint_result or not taint_result.flows:
            return
        for candidate in candidates:
            for flow in taint_result.flows:
                if flow.sink_kind != TaintSinkKind.DELEGATECALL_TARGET:
                    continue
                if flow.source_kind not in _ATTACKER_SOURCES:
                    continue
                # Match by node id if available
                if (candidate.call.cfg_node_id != -1 and
                        flow.cfg_node_id != candidate.call.cfg_node_id):
                    continue
                candidate.taint_confirms = True
                candidate.taint_source   = flow.source_kind
                break


# ---------------------------------------------------------------------------
# Step 7 — Finding builder
# ---------------------------------------------------------------------------

class _FindingBuilder:

    def build(
        self,
        candidate:        _DelegateFinding,
        contract_name:    str,
        fn_info:          FunctionInfo,
        detector_id:      str,
        detector_version: str,
        recommendation:   str,
        cvss_score:       float,
    ) -> Finding:
        call = candidate.call
        return Finding(
            vuln_type        = VulnerabilityType.DELEGATECALL,
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
                delegatecall_target = call.target_expr,
                extra               = {
                    "vector":           call.vector.value,
                    "target_expr":      call.target_expr,
                    "data_expr":        call.data_expr,
                    "has_access_guard": call.has_access_guard,
                    "has_zero_check":   call.has_zero_check,
                    "in_loop":          call.in_loop,
                    "from_structured":  call.from_structured,
                    "cfg_node_id":      call.cfg_node_id,
                    "stmt":             call.stmt,
                    "taint_confirms":   candidate.taint_confirms,
                    "taint_source":     (
                        candidate.taint_source.value
                        if candidate.taint_source else None
                    ),
                },
            ),
        )

    @staticmethod
    def _severity(c: _DelegateFinding) -> Severity:
        """
        Severity table:
          CRITICAL — user-controlled target (arbitrary code execution)
          CRITICAL — unguarded upgrade function (implementation hijack)
          HIGH     — delegatecall with no access guard
          MEDIUM   — delegatecall in loop, or missing zero-address check
          LOW      — guarded delegatecall, minor concern
        """
        v = c.call.vector
        if v in (
            _DelegateVector.USER_CONTROLLED,
            _DelegateVector.UNGUARDED_UPGRADE,
        ):
            return Severity.CRITICAL
        if v == _DelegateVector.UNGUARDED:
            return Severity.HIGH
        if v in (_DelegateVector.IN_LOOP, _DelegateVector.ZERO_ADDR):
            return Severity.MEDIUM
        return Severity.LOW

    @staticmethod
    def _confidence(c: _DelegateFinding) -> float:
        score = 0.60
        if c.call.from_structured:
            score += 0.20
        if c.call.vector in (
            _DelegateVector.USER_CONTROLLED,
            _DelegateVector.UNGUARDED_UPGRADE,
        ):
            score += 0.15
        if c.taint_confirms:
            score += 0.05
        return round(min(1.0, score), 4)

    @staticmethod
    def _title(c: _DelegateFinding) -> str:
        vector_titles = {
            _DelegateVector.USER_CONTROLLED:   (
                f"Delegatecall to user-controlled target '{c.call.target_expr}'"
            ),
            _DelegateVector.UNGUARDED_UPGRADE: (
                f"Unguarded upgrade function — delegatecall target writable by anyone"
            ),
            _DelegateVector.IN_LOOP: (
                f"Delegatecall inside loop — gas and logic risk"
            ),
            _DelegateVector.ZERO_ADDR: (
                f"Delegatecall to '{c.call.target_expr}' — no address(0) guard"
            ),
            _DelegateVector.UNGUARDED: (
                f"Unguarded delegatecall to '{c.call.target_expr}'"
            ),
        }
        return vector_titles.get(c.call.vector, "Dangerous delegatecall usage")

    @staticmethod
    def _description(c: _DelegateFinding, fn_info: FunctionInfo) -> str:
        call = c.call
        loc  = f" at line {call.source_line}" if call.source_line else ""

        descs = {
            _DelegateVector.USER_CONTROLLED: (
                f"Function '{fn_info.name}' uses delegatecall{loc} where "
                f"the target address '{call.target_expr}' is derived from "
                f"user-supplied input. delegatecall executes the target's code "
                f"inside THIS contract's storage context — meaning the attacker's "
                f"contract can call selfdestruct, overwrite owner, drain funds, "
                f"or corrupt any state variable. This is a full arbitrary code "
                f"execution vulnerability within your contract's identity."
            ),
            _DelegateVector.UNGUARDED_UPGRADE: (
                f"Function '{fn_info.name}' appears to be an upgrade function{loc} "
                f"that sets the delegatecall implementation target, but has no "
                f"access control guard. Any caller can redirect all delegatecalls "
                f"to a malicious implementation, gaining full control of the proxy "
                f"contract's storage and funds."
            ),
            _DelegateVector.IN_LOOP: (
                f"Function '{fn_info.name}' executes delegatecall{loc} inside "
                f"a loop. Each iteration performs a full external call, making "
                f"gas costs unpredictable and potentially unbounded. If the loop "
                f"count is user-influenced, this is also a DoS vector."
            ),
            _DelegateVector.ZERO_ADDR: (
                f"Function '{fn_info.name}' executes delegatecall{loc} to "
                f"'{call.target_expr}' without checking for the zero address. "
                f"If the target slot is uninitialised (address(0)), the call "
                f"silently succeeds but does nothing — masking critical failures "
                f"in proxy initialisation or upgrade sequences."
            ),
            _DelegateVector.UNGUARDED: (
                f"Function '{fn_info.name}' executes delegatecall{loc} to "
                f"'{call.target_expr}' without access control. While the target "
                f"may be a fixed implementation address, any external caller "
                f"can trigger this delegation — which runs implementation code "
                f"in the context of this contract's storage."
            ),
        }

        base = descs.get(
            call.vector,
            f"Function '{fn_info.name}' uses delegatecall{loc} in a "
            f"potentially dangerous way."
        )

        if c.taint_confirms:
            src = c.taint_source.value if c.taint_source else "external input"
            base += (
                f" Taint analysis confirms the delegatecall target is "
                f"reachable from attacker-controlled input ({src})."
            )
        return base


# ---------------------------------------------------------------------------
# Public detector
# ---------------------------------------------------------------------------

class DelegatecallDetector(BaseDetector):
    """
    Detects dangerous delegatecall patterns in four vectors:
      1. User-controlled target (arbitrary code execution)
      2. Unguarded upgrade function (implementation hijack)
      3. Delegatecall in loop (gas/logic risk)
      4. Missing zero-address guard (silent no-op on uninitialised proxy)

    Does NOT fire on:
      - Delegatecall with confirmed access guard to a known fixed address
        (standard OpenZeppelin proxy pattern — guarded and address checked)
      - Library calls resolved at compile time (not runtime delegatecall)
    """

    DETECTOR_ID      = "delegatecall_v1"
    DETECTOR_VERSION = "1.0.0"
    VULN_TYPE        = VulnerabilityType.DELEGATECALL
    DEFAULT_SEVERITY = Severity.HIGH

    def __init__(self) -> None:
        self._structured_scanner = _StructuredScanner()
        self._ir_scanner         = _IRScanner()
        self._taint_enricher     = _TaintEnricher()
        self._finding_builder    = _FindingBuilder()

    # ------------------------------------------------------------------
    # BaseDetector abstract method implementations
    # ------------------------------------------------------------------

    def detect(
        self,
        contract:     ContractInfo,
        fn_info:      FunctionInfo,
        cfg:          CFGGraph,
        dfg:          DFGGraph,
        taint_result: Optional[TaintResult],
    ) -> List[Finding]:

        # ── Step 1: Fast-path ─────────────────────────────────────────
        if not _has_delegatecall(fn_info, cfg):
            logger.debug(
                "Delegatecall: '%s.%s' — no delegatecall, skipped.",
                contract.name, fn_info.name,
            )
            return []

        # ── Pre-compute shared guards ─────────────────────────────────
        access_guard = _has_access_guard(fn_info, cfg)
        zero_check   = _has_zero_check(cfg)

        # ── Step 2: Structured path ───────────────────────────────────
        structured = self._structured_scanner.scan(
            fn_info, cfg, access_guard, zero_check
        )

        structured_lines: Set[Optional[int]] = {
            c.source_line for c in structured
        }

        # ── Step 3: IR fallback ───────────────────────────────────────
        fallback = self._ir_scanner.scan(
            cfg, fn_info, structured_lines, access_guard, zero_check
        )

        all_calls = structured + fallback
        if not all_calls:
            logger.debug(
                "Delegatecall: '%s.%s' — delegatecall found but fully guarded.",
                contract.name, fn_info.name,
            )
            return []

        # ── Skip safe patterns ────────────────────────────────────────
        # A delegatecall that is: guarded + zero-checked + not user-target
        # + not in a loop = standard OZ proxy. Skip it.
        risky = [
            c for c in all_calls
            if not (
                c.has_access_guard
                and c.has_zero_check
                and not _USER_TARGET_RE.search(c.target_expr)
                and not c.in_loop
                and c.vector not in (
                    _DelegateVector.USER_CONTROLLED,
                    _DelegateVector.UNGUARDED_UPGRADE,
                )
            )
        ]

        if not risky:
            logger.debug(
                "Delegatecall: '%s.%s' — all delegatecalls are standard "
                "guarded proxy pattern, skipped.",
                contract.name, fn_info.name,
            )
            return []

        # ── Step 4: Taint enrichment ──────────────────────────────────
        candidates = [_DelegateFinding(call=c) for c in risky]
        self._taint_enricher.enrich(candidates, taint_result)

        # ── Step 5 (guard check already done above) ───────────────────

        # ── Step 6: Deduplication ─────────────────────────────────────
        seen:         Set[Tuple[int, str]] = set()
        deduplicated: List[_DelegateFinding] = []
        for c in candidates:
            key = (c.call.cfg_node_id, c.call.target_expr[:60])
            if key not in seen:
                seen.add(key)
                deduplicated.append(c)

        # ── Step 7: Build findings ────────────────────────────────────
        findings: List[Finding] = []
        for c in deduplicated:
            context = self._build_context(c, fn_info, contract)
            finding = self._finding_builder.build(
                candidate        = c,
                contract_name    = contract.name,
                fn_info          = fn_info,
                detector_id      = self.DETECTOR_ID,
                detector_version = self.DETECTOR_VERSION,
                recommendation   = self.safe_recommendation(context),
                cvss_score       = self.safe_cvss(context),
            )
            findings.append(finding)
            logger.debug(
                "Delegatecall: '%s.%s' — %s severity, vector='%s', "
                "target='%s', taint=%s, cvss=%.1f.",
                contract.name, fn_info.name,
                finding.severity.value, c.call.vector.value,
                c.call.target_expr, c.taint_confirms,
                finding.cvss_score,
            )

        return findings

    def build_recommendation(self, context: dict) -> str:
        fn_name      = context["function_name"]
        vector       = context.get("vector", "unguarded_delegatecall")
        target       = context.get("target_expr", "the target")
        line         = context.get("line_number")

        loc = f" at line {line}" if line else ""

        recs = {
            "user_controlled_target": (
                f"In function '{fn_name}'{loc}: NEVER pass a user-supplied "
                f"address as the target of delegatecall. "
                f"Fix options:\n"
                f"  1. Maintain a whitelist of approved implementation addresses "
                f"in contract storage and validate the target against it.\n"
                f"  2. Store the implementation address in a privileged slot "
                f"(EIP-1967) and only allow the owner to update it via a "
                f"separate guarded setter:\n"
                f"     bytes32 private constant IMPL_SLOT = keccak256(\"eip1967.proxy.implementation\");\n"
                f"  3. If forwarding is required, use a fixed implementation "
                f"slot and never expose the target as a parameter."
            ),
            "unguarded_upgrade": (
                f"In function '{fn_name}'{loc}: add an access control guard "
                f"to prevent arbitrary callers from changing the implementation:\n"
                f"  modifier onlyOwner() {{\n"
                f"      require(msg.sender == owner, \"Not owner\"); _;\n"
                f"  }}\n"
                f"  function upgradeTo(address newImpl) external onlyOwner {{\n"
                f"      require(newImpl != address(0), \"Zero address\");\n"
                f"      _implementation = newImpl;\n"
                f"  }}\n"
                f"Consider using OpenZeppelin's UUPSUpgradeable or "
                f"TransparentUpgradeableProxy for a battle-tested upgrade pattern."
            ),
            "delegatecall_in_loop": (
                f"In function '{fn_name}'{loc}: remove delegatecall from "
                f"the loop body. Each delegatecall is a full external call — "
                f"placing it in a loop makes gas costs unbounded and introduces "
                f"reentrancy-like risks. Refactor to batch data preparation "
                f"before a single delegatecall, or redesign the loop logic."
            ),
            "missing_zero_check": (
                f"In function '{fn_name}'{loc}: add a zero-address guard "
                f"before delegatecall to '{target}':\n"
                f"  require({target} != address(0), \"Implementation not set\");\n"
                f"  (bool ok,) = {target}.delegatecall(data);\n"
                f"  require(ok, \"Delegatecall failed\");\n"
                f"An uninitialised implementation slot silently no-ops all calls."
            ),
            "unguarded_delegatecall": (
                f"In function '{fn_name}'{loc}: restrict who can trigger "
                f"this delegatecall with an access control modifier:\n"
                f"  require(msg.sender == owner, \"Not authorised\");\n"
                f"Also verify the target address is the expected implementation "
                f"and add a zero-address check."
            ),
        }

        return recs.get(
            vector,
            f"In function '{fn_name}'{loc}: review delegatecall to "
            f"'{target}'. Ensure the target is not user-controlled, "
            f"is guarded by access control, and is checked for address(0)."
        )

    def calculate_cvss(self, context: dict) -> float:
        """
        Base: 7.0

        ┌──────────────────────────────────────────────┬───────┐
        │ Condition                                    │ Delta │
        ├──────────────────────────────────────────────┼───────┤
        │ user_controlled_target                       │ +3.0  │
        │ unguarded_upgrade                            │ +2.5  │
        │ unguarded_delegatecall                       │ +1.5  │
        │ delegatecall_in_loop                         │ +0.5  │
        │ missing_zero_check                           │ +0.3  │
        │ taint confirms target from attacker input    │ +0.5  │
        │ external / public visibility                 │ +0.3  │
        │ has_access_guard                             │ −2.0  │
        │ has_zero_check                               │ −0.5  │
        └──────────────────────────────────────────────┴───────┘
        """
        score        = 7.0
        vector       = context.get("vector", "unguarded_delegatecall")
        access_guard = context.get("has_access_guard", False)
        zero_check   = context.get("has_zero_check", False)

        vector_deltas = {
            "user_controlled_target":     3.0,
            "unguarded_upgrade":          2.5,
            "unguarded_delegatecall":     1.5,
            "delegatecall_in_loop":       0.5,
            "missing_zero_check":         0.3,
        }
        score += vector_deltas.get(vector, 0.0)

        if context.get("taint_confirms"):
            score += 0.5
        if context.get("function_visibility") in ("external", "public"):
            score += 0.3
        if access_guard:
            score -= 2.0
        if zero_check:
            score -= 0.5

        return round(max(0.0, min(10.0, score)), 1)

    # ------------------------------------------------------------------
    # Context builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_context(
        c:        _DelegateFinding,
        fn_info:  FunctionInfo,
        contract: ContractInfo,
    ) -> dict:
        return {
            "contract_name":       contract.name,
            "function_name":       fn_info.name,
            "function_visibility": getattr(fn_info.visibility, "value",
                                           fn_info.visibility),
            "is_payable":          (
                getattr(fn_info.state_mutability, "value",
                        fn_info.state_mutability) == "payable"
            ),
            "line_number":         c.call.source_line,
            "cfg_node":            c.call.cfg_node_id,
            "vector":              c.call.vector.value,
            "target_expr":         c.call.target_expr,
            "data_expr":           c.call.data_expr,
            "has_access_guard":    c.call.has_access_guard,
            "has_zero_check":      c.call.has_zero_check,
            "in_loop":             c.call.in_loop,
            "from_structured":     c.call.from_structured,
            "stmt":                c.call.stmt,
            "taint_confirms":      c.taint_confirms,
            "taint_source":        (
                c.taint_source.value if c.taint_source else None
            ),
        }