"""
detectors/txorigin_detector.py

tx.origin Authentication vulnerability detector for VigilanceCore.

What it detects
---------------
Use of tx.origin for authentication — any require/assert/if condition
that compares tx.origin against an owner, admin, or trusted address
to gate access to a function.

Why this matters
----------------
tx.origin is the ORIGINAL sender of the ENTIRE transaction chain —
the externally owned account (EOA) that first signed the transaction.
msg.sender is the IMMEDIATE caller — which could be another contract.

The phishing attack vector:
  1. Owner (Alice) is tricked into calling Attacker's contract.
  2. Attacker's contract calls Victim contract's protected function.
  3. Inside Victim: tx.origin == Alice (passes), msg.sender == Attacker (ignored).
  4. require(tx.origin == owner) PASSES — auth bypassed.

Contexts detected
-----------------
  A — require(tx.origin == owner)         → AUTH_CHECK
  B — if (tx.origin != admin) revert()    → IF_GATE
  C — authorised = (tx.origin == owner)   → STATE_WRITE
  D — return tx.origin == owner           → RETURN_CMP
  E — address user = tx.origin            → BARE_READ (filtered unless near owner var)

Detection pipeline
------------------
  Step 1  Fast-path   — skip if tx.origin never appears in function IR
  Step 2  Usage scan  — find every IR statement containing tx.origin
  Step 3  Classify    — auth_check / if_gate / state_write / return_cmp / bare_read
  Step 4  Risk filter — drop pure informational reads
  Step 5  Taint enrich— confirm tx.origin flows into a security sink
  Step 6  Dedup       — one finding per (node, context) pair
  Step 7  Build       — Finding with recommendation + cvss

Change log
----------
v1.0.0  Initial release.
v1.1.0  10 production bugs fixed (regex, modifier detection, taint, dedup).
v1.2.0  Hardened FindingMetadata construction; normalised VulnerabilityType usage.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import FrozenSet, List, Optional, Set, Tuple

from core.cfg_builder import CFGGraph, DFGGraph
from core.models import (
    ContractInfo,
    Finding,
    FunctionInfo,
    Severity,
    VulnerabilityType,
)
from core.taint_engine import TaintResult, TaintSinkKind, TaintSourceKind
from detectors.base_detector import BaseDetector

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional imports — graceful degradation if FindingMetadata is unavailable
# ---------------------------------------------------------------------------
try:
    from core.models import FindingMetadata as _FindingMetadata
    _HAS_FINDING_METADATA = True
except ImportError:
    _HAS_FINDING_METADATA = False

# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

_TXORIGIN_RE = re.compile(r"\btx\.origin\b", re.IGNORECASE)

# Extended RHS/LHS to [\w.\[\]()] — catches member access and mapping lookups
_AUTH_CMP_RE = re.compile(
    r"tx\.origin\s*[!=]=\s*[\w.\[\]()]+"
    r"|[\w.\[\]()]+\s*[!=]=\s*tx\.origin",
    re.IGNORECASE,
)

# One-level nesting-aware require/assert pattern
_REQUIRE_TXORIGIN_RE = re.compile(
    r"\b(?:require|assert)\s*\((?:[^)(]|\([^)]*\))*tx\.origin",
    re.IGNORECASE,
)

_IF_TXORIGIN_RE = re.compile(r"\bif\b[^;]*tx\.origin", re.IGNORECASE)

# State write — tx.origin on RHS of assignment (LHS is impossible in Solidity)
_STATE_WRITE_RE = re.compile(
    r"\w[\w\[\].]*\s*[-+*/]?=\s*[^;]*tx\.origin",
    re.IGNORECASE,
)

_RETURN_CMP_RE = re.compile(r"\breturn\b[^;]*tx\.origin", re.IGNORECASE)
_MSG_SENDER_RE = re.compile(r"\bmsg\.sender\b", re.IGNORECASE)

_OWNER_VAR_RE = re.compile(
    r"\b(?:owner|admin|deployer|governance|operator|controller"
    r"|manager|superuser|root|authority)\b",
    re.IGNORECASE,
)

# Used in _is_risky() to suppress BARE_READ inside event emissions
_EVENT_EMIT_RE = re.compile(r"\bemit\b|\bLog\b", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Internal enums and dataclasses
# ---------------------------------------------------------------------------


class _TxOriginContext(str, Enum):
    AUTH_CHECK  = "auth_check"   # require/assert(tx.origin == owner)
    IF_GATE     = "if_gate"      # if (tx.origin != admin) revert()
    STATE_WRITE = "state_write"  # authorised = (tx.origin == owner)
    RETURN_CMP  = "return_cmp"   # return tx.origin == owner
    BARE_READ   = "bare_read"    # address user = tx.origin


@dataclass
class _TxOriginUsage:
    cfg_node_id:   int
    ir_index:      int
    context:       _TxOriginContext
    stmt:          str
    source_line:   Optional[int]
    has_owner_var: bool   # owner/admin variable nearby
    has_msg_sender: bool  # msg.sender also present (partial mitigation)
    is_in_modifier: bool  # inside a modifier (wider blast radius)


@dataclass
class _TxOriginFinding:
    usage:         _TxOriginUsage
    taint_confirms: bool = False
    taint_source:  Optional[TaintSourceKind] = None


# ---------------------------------------------------------------------------
# Step 1 — Fast-path predicate
# ---------------------------------------------------------------------------


def _has_txorigin(cfg: CFGGraph) -> bool:
    for node in cfg.nodes.values():
        if _TXORIGIN_RE.search(" ".join(node.ir_stmts)):
            return True
    return False


# ---------------------------------------------------------------------------
# Steps 2 + 3 — Usage finder and classifier
# ---------------------------------------------------------------------------


class _UsageFinder:

    def find(self, cfg: CFGGraph, fn_info: FunctionInfo) -> List[_TxOriginUsage]:
        usages: List[_TxOriginUsage] = []

        is_modifier: bool = bool(getattr(fn_info, "is_modifier", False))
        if not is_modifier:
            fn_type = str(getattr(fn_info, "function_type", "")).lower()
            is_modifier = "modifier" in fn_type and fn_type != "functiontype.constructor"

        for node in cfg.ordered_nodes():
            if not _TXORIGIN_RE.search(" ".join(node.ir_stmts)):
                continue

            label_upper = (node.label or "").upper()
            stmts = node.ir_stmts

            for ir_idx, stmt in enumerate(stmts):
                if not _TXORIGIN_RE.search(stmt):
                    continue

                context = self._classify(stmt, label_upper, ir_idx)

                window_start = max(0, ir_idx - 2)
                window_end   = min(len(stmts), ir_idx + 3)
                nearby = " ".join(stmts[window_start:window_end])

                usages.append(_TxOriginUsage(
                    cfg_node_id    = node.node_id,
                    ir_index       = ir_idx,
                    context        = context,
                    stmt           = stmt[:120],
                    source_line    = node.source_line,
                    has_owner_var  = bool(_OWNER_VAR_RE.search(nearby)),
                    has_msg_sender = bool(_MSG_SENDER_RE.search(stmt)),
                    is_in_modifier = is_modifier,
                ))

        return usages

    @staticmethod
    def _classify(stmt: str, label_upper: str, ir_idx: int) -> _TxOriginContext:
        if _REQUIRE_TXORIGIN_RE.search(stmt):
            return _TxOriginContext.AUTH_CHECK

        is_branch_cond = ir_idx == 0 and "IF" in label_upper
        if _AUTH_CMP_RE.search(stmt) and (is_branch_cond or _IF_TXORIGIN_RE.search(stmt)):
            return _TxOriginContext.IF_GATE

        if _AUTH_CMP_RE.search(stmt):
            return _TxOriginContext.AUTH_CHECK

        if _RETURN_CMP_RE.search(stmt):
            return _TxOriginContext.RETURN_CMP

        if _STATE_WRITE_RE.search(stmt):
            return _TxOriginContext.STATE_WRITE

        return _TxOriginContext.BARE_READ


# ---------------------------------------------------------------------------
# Step 4 — Risk filter
# ---------------------------------------------------------------------------

_SECURITY_CONTEXTS: FrozenSet[_TxOriginContext] = frozenset({
    _TxOriginContext.AUTH_CHECK,
    _TxOriginContext.IF_GATE,
    _TxOriginContext.STATE_WRITE,
    _TxOriginContext.RETURN_CMP,
})


def _is_risky(usage: _TxOriginUsage) -> bool:
    if usage.context in _SECURITY_CONTEXTS:
        return True
    # BARE_READ: only flag when auth intent is clear and not an event emission
    return usage.has_owner_var and not _EVENT_EMIT_RE.search(usage.stmt)


# ---------------------------------------------------------------------------
# Step 5 — Taint enricher
# ---------------------------------------------------------------------------


class _TaintEnricher:

    def enrich(
        self,
        candidates: List[_TxOriginFinding],
        taint_result: Optional[TaintResult],
    ) -> None:
        if not taint_result or not taint_result.flows:
            return

        for candidate in candidates:
            for flow in taint_result.flows:
                if flow.source_kind != TaintSourceKind.TX_ORIGIN:
                    continue

                # Prefer source_node_id (where tx.origin was read); fall back to cfg_node_id
                source_node = getattr(
                    flow, "source_node_id",
                    getattr(flow, "cfg_node_id", None),
                )
                if source_node is not None and source_node != candidate.usage.cfg_node_id:
                    continue

                if flow.sink_kind in (
                    TaintSinkKind.REQUIRE_CONDITION,
                    TaintSinkKind.STORAGE_WRITE,
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
        candidate:         _TxOriginFinding,
        contract_name:     str,
        fn_info:           FunctionInfo,
        detector_id:       str,
        detector_version:  str,
        recommendation:    str,
        cvss_score:        float,
    ) -> Finding:
        u = candidate.usage

        kwargs = dict(
            vuln_type        = VulnerabilityType.TX_ORIGIN,
            severity         = self._severity(candidate),
            contract_name    = contract_name,
            function_name    = fn_info.name,
            source_file      = fn_info.source_file,
            start_line       = u.source_line,
            title            = self._title(candidate),
            description      = self._description(candidate, fn_info),
            recommendation   = recommendation,
            confidence       = self._confidence(candidate),
            cvss_score       = cvss_score,
            detector_id      = detector_id,
            detector_version = detector_version,
        )

        # Attach FindingMetadata only if the class is available and accepts these kwargs
        if _HAS_FINDING_METADATA:
            try:
                kwargs["metadata"] = _FindingMetadata(
                    extra={
                        "context":        u.context.value,
                        "has_owner_var":  u.has_owner_var,
                        "has_msg_sender": u.has_msg_sender,
                        "is_in_modifier": u.is_in_modifier,
                        "cfg_node_id":    u.cfg_node_id,
                        "ir_index":       u.ir_index,
                        "stmt":           u.stmt,
                        "taint_confirms": candidate.taint_confirms,
                        "taint_source": (
                            candidate.taint_source.value
                            if candidate.taint_source else None
                        ),
                    }
                )
            except Exception:
                pass  # FindingMetadata schema mismatch — skip metadata silently

        return Finding(**kwargs)

    @staticmethod
    def _severity(c: _TxOriginFinding) -> Severity:
        ctx = c.usage.context

        # Modifier-level auth — blast radius covers every function using it
        if c.usage.is_in_modifier and ctx in (
            _TxOriginContext.AUTH_CHECK, _TxOriginContext.IF_GATE
        ):
            return Severity.CRITICAL

        if ctx in (_TxOriginContext.AUTH_CHECK, _TxOriginContext.IF_GATE) and c.usage.has_owner_var:
            return Severity.MEDIUM if c.usage.has_msg_sender else Severity.HIGH

        if ctx in (
            _TxOriginContext.AUTH_CHECK,
            _TxOriginContext.IF_GATE,
            _TxOriginContext.STATE_WRITE,
            _TxOriginContext.RETURN_CMP,
        ):
            return Severity.MEDIUM

        return Severity.LOW

    @staticmethod
    def _confidence(c: _TxOriginFinding) -> float:
        score = 0.65
        if c.usage.context in (_TxOriginContext.AUTH_CHECK, _TxOriginContext.IF_GATE):
            score += 0.20
        if c.usage.has_owner_var:
            score += 0.10
        if c.taint_confirms:
            score += 0.05
        if c.usage.has_msg_sender:
            score -= 0.05
        return round(min(1.0, max(0.0, score)), 4)

    @staticmethod
    def _title(c: _TxOriginFinding) -> str:
        labels = {
            _TxOriginContext.AUTH_CHECK:  "tx.origin used in authentication require/assert",
            _TxOriginContext.IF_GATE:     "tx.origin used in if-gate access control",
            _TxOriginContext.STATE_WRITE: "tx.origin stored to state variable",
            _TxOriginContext.RETURN_CMP:  "tx.origin used in return comparison",
            _TxOriginContext.BARE_READ:   "tx.origin read for authentication intent",
        }
        label = labels.get(c.usage.context, "tx.origin misuse")
        mod   = " (in modifier)" if c.usage.is_in_modifier else ""
        return f"tx.origin Authentication: {label}{mod}"

    @staticmethod
    def _description(c: _TxOriginFinding, fn_info: FunctionInfo) -> str:
        u   = c.usage
        loc = f" at line {u.source_line}" if u.source_line else ""

        descs = {
            _TxOriginContext.AUTH_CHECK: (
                f"Function '{fn_info.name}' uses tx.origin in a require/assert{loc} "
                f"to authenticate the caller. An attacker can trick the owner into calling "
                f"a malicious intermediary contract, which then calls this function. "
                f"tx.origin == owner passes (the original EOA), but msg.sender is the "
                f"attacker's contract — the auth check is bypassed."
            ),
            _TxOriginContext.IF_GATE: (
                f"Function '{fn_info.name}' uses tx.origin in an if-condition{loc} "
                f"to gate access. An intermediate malicious contract inherits tx.origin "
                f"from the tricked owner, bypassing the gate."
            ),
            _TxOriginContext.STATE_WRITE: (
                f"Function '{fn_info.name}' stores tx.origin into contract state{loc}. "
                f"Downstream logic using this stored value for access control is exploitable "
                f"via the same phishing vector."
            ),
            _TxOriginContext.RETURN_CMP: (
                f"Function '{fn_info.name}' returns a tx.origin comparison{loc}. "
                f"Any caller using this return value for access decisions is vulnerable — "
                f"tx.origin can be spoofed via an intermediary."
            ),
            _TxOriginContext.BARE_READ: (
                f"Function '{fn_info.name}' reads tx.origin{loc} near an owner/admin "
                f"variable. If used for access control, it is exploitable via a phishing intermediary."
            ),
        }

        base = descs.get(
            u.context,
            f"Function '{fn_info.name}' uses tx.origin{loc} in a security-sensitive context."
        )

        if u.has_msg_sender:
            base += (
                " Note: msg.sender is also present — if BOTH are required, risk is reduced, "
                "but tx.origin is still incorrect for authentication and should be removed."
            )
        if u.is_in_modifier:
            base += (
                " This usage is inside a modifier — every function that applies this modifier "
                "inherits the vulnerability."
            )
        if c.taint_confirms:
            base += " Taint analysis confirms tx.origin flows into a security-sensitive sink."

        return base


# ---------------------------------------------------------------------------
# Public detector
# ---------------------------------------------------------------------------


class TxOriginDetector(BaseDetector):
    """
    Detects use of tx.origin for authentication or access control.

    Fires on:
      - require(tx.origin == owner)         AUTH_CHECK
      - if (tx.origin != admin) revert()    IF_GATE
      - authorised = (tx.origin == owner)   STATE_WRITE
      - return tx.origin == owner           RETURN_CMP
      - tx.origin near owner/admin var      BARE_READ (filtered)

    Does NOT fire on:
      - tx.origin inside event emissions (informational)
      - tx.origin with no comparison and no owner var nearby
      - Constructors (tx.origin == deployer is an accepted deployment pattern)
    """

    DETECTOR_ID      = "txorigin_v1"
    DETECTOR_VERSION = "1.2.0"
    VULN_TYPE        = VulnerabilityType.TX_ORIGIN
    DEFAULT_SEVERITY = Severity.MEDIUM

    def __init__(self) -> None:
        self._usage_finder    = _UsageFinder()
        self._taint_enricher  = _TaintEnricher()
        self._finding_builder = _FindingBuilder()

    # ------------------------------------------------------------------
    # BaseDetector abstract method
    # ------------------------------------------------------------------

    def detect(
        self,
        contract:     ContractInfo,
        fn_info:      FunctionInfo,
        cfg:          CFGGraph,
        dfg:          DFGGraph,
        taint_result: Optional[TaintResult],
    ) -> List[Finding]:

        # Step 1: Fast-path
        if not _has_txorigin(cfg):
            return []

        # Skip constructors — tx.origin == deployer is an accepted deployment pattern
        if fn_info.is_constructor:
            return []

        # Steps 2 + 3: Find and classify usages
        usages = self._usage_finder.find(cfg, fn_info)
        if not usages:
            return []

        # Step 4: Risk filter
        risky = [u for u in usages if _is_risky(u)]
        if not risky:
            return []

        # Step 5: Taint enrichment
        candidates = [_TxOriginFinding(usage=u) for u in risky]
        self._taint_enricher.enrich(candidates, taint_result)

        # Step 6: Deduplication — one finding per (cfg_node, context) pair
        seen: Set[Tuple[int, str]] = set()
        deduplicated: List[_TxOriginFinding] = []
        for c in candidates:
            key = (c.usage.cfg_node_id, c.usage.context.value)
            if key not in seen:
                seen.add(key)
                deduplicated.append(c)

        # Step 7: Build findings
        findings: List[Finding] = []
        for c in deduplicated:
            ctx = self._build_context(c, fn_info, contract)
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
                "TxOrigin: '%s.%s' — %s severity, context='%s', "
                "owner_var=%s, msg_sender=%s, taint=%s, cvss=%.1f.",
                contract.name, fn_info.name,
                finding.severity.value, c.usage.context.value,
                c.usage.has_owner_var, c.usage.has_msg_sender,
                c.taint_confirms, finding.cvss_score,
            )

        return findings

    def build_recommendation(self, context: dict) -> str:
        fn_name        = context.get("function_name", "unknown")
        ctx            = context.get("context", "auth_check")
        has_msg_sender = context.get("has_msg_sender", False)
        is_in_modifier = context.get("is_in_modifier", False)
        line           = context.get("line_number")
        loc            = f" at line {line}" if line else ""

        if ctx in ("auth_check", "if_gate"):
            rec = (
                f"In function '{fn_name}'{loc}: replace tx.origin with msg.sender:\n"
                f"  // WRONG\n"
                f"  require(tx.origin == owner, \"Not owner\");\n\n"
                f"  // CORRECT\n"
                f"  require(msg.sender == owner, \"Not owner\");\n\n"
                f"msg.sender is the immediate caller and correctly blocks malicious "
                f"intermediary contracts. tx.origin reflects only the original EOA "
                f"and is bypassable via phishing."
            )
        elif ctx == "state_write":
            rec = (
                f"In function '{fn_name}'{loc}: do not store tx.origin for later "
                f"authentication. Store msg.sender instead, or check msg.sender "
                f"directly at the point of access control."
            )
        elif ctx == "return_cmp":
            rec = (
                f"In function '{fn_name}'{loc}: replace tx.origin comparison:\n"
                f"  return msg.sender == owner;  // instead of tx.origin"
            )
        else:
            rec = (
                f"In function '{fn_name}'{loc}: avoid using tx.origin for any "
                f"security decision. Use msg.sender instead."
            )

        if has_msg_sender:
            rec += (
                "\n\nNote: msg.sender is also present. If this is an intentional "
                "dual-check, remove tx.origin entirely — msg.sender alone is correct."
            )
        if is_in_modifier:
            rec += (
                "\n\nThis is inside a modifier — fixing it here automatically "
                "fixes every function that applies this modifier."
            )
        return rec

    def calculate_cvss(self, context: dict) -> float:
        """
        Base: 6.0
        auth_check / if_gate          +2.0
        state_write / return_cmp      +1.0
        has_owner_var                 +0.5
        is_in_modifier                +1.5
        taint_confirms                +0.5
        external / public visibility  +0.3
        has_msg_sender (mitigation)   -1.0
        Max (clamped to 10.0)
        """
        score = 6.0
        ctx = context.get("context", "bare_read")

        ctx_deltas = {
            "auth_check":  2.0,
            "if_gate":     2.0,
            "state_write": 1.0,
            "return_cmp":  1.0,
        }
        score += ctx_deltas.get(ctx, 0.0)

        if context.get("has_owner_var"):
            score += 0.5
        if context.get("is_in_modifier"):
            score += 1.5
        if context.get("taint_confirms"):
            score += 0.5
        if context.get("function_visibility") in ("external", "public"):
            score += 0.3
        if context.get("has_msg_sender"):
            score -= 1.0

        return round(max(0.0, min(10.0, score)), 1)

    @staticmethod
    def _build_context(
        c:        _TxOriginFinding,
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
                getattr(fn_info.state_mutability, "value", fn_info.state_mutability)
                == "payable"
            ),
            "line_number":    c.usage.source_line,
            "cfg_node":       c.usage.cfg_node_id,
            "context":        c.usage.context.value,
            "has_owner_var":  c.usage.has_owner_var,
            "has_msg_sender": c.usage.has_msg_sender,
            "is_in_modifier": c.usage.is_in_modifier,
            "stmt":           c.usage.stmt,
            "taint_confirms": c.taint_confirms,
            "taint_source": (
                c.taint_source.value if c.taint_source else None
            ),
        }