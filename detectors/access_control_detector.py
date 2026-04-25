"""
detectors/access_control_detector.py

Access control vulnerability detector for VigilanceCore.

Change log:
  v1.0.0  Initial release
  v1.1.0  FIX  O(N²) → O(N) node iteration
          FIX  Word-boundary regex on privileged vars and modifiers
          FIX  visibility safe extraction via getattr
          FIX  ir_stmts joined once per node
          IMP  Early exit on modifier detection
          IMP  cfg.ordered_nodes() used consistently
          IMP  Context-aware CVSS with taint, proxy, economic multiplier
  v1.2.0  FIX  _SensitiveOperationFinder uses \b word-boundary per-sv regex
                — eliminates coowner, ownerMapping false positives
          FIX  _REVERT_GUARD_RE extended to detect custom error declarations
                (error Unauthorized(); if (...) revert Unauthorized();)
          FIX  Proxy detection uses proxy/upgradeable/erc1967/uups pattern
                — TransparentUpgradeableProxy, UUPSUpgradeable now detected
          IMP  CVSS exploitability factor extended:
                external + payable combination gets additional +0.2
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import FrozenSet, List, Optional, Set, Tuple

from core.cfg_builder import CFGGraph, DFGGraph
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

# Word-boundary privileged variable names
_PRIVILEGED_VAR_RE = re.compile(
    r"\b(?:owner|admin|operator|controller|governance|paused|"
    r"whitelist|blacklist|minter|burner|vault|treasury|"
    r"implementation|pendingOwner|superUser|manager|"
    r"proxyAdmin|upgrader|guardian)\b",
    re.IGNORECASE,
)

# Governance-critical variable keywords for CVSS scoring
_GOVERNANCE_VAR_RE = re.compile(
    r"\b(?:owner|admin|governance|implementation|proxyadmin|upgrader|guardian)\b",
    re.IGNORECASE,
)

# Privileged IR operation patterns
_PRIVILEGED_OP_RE = re.compile(
    r"(?:selfdestruct\b|SelfDestruct\b|"
    r"delegatecall\b|"
    r"upgradeTo\b|upgradeToAndCall\b|_upgradeTo\b|"
    r"setOwner\b|transferOwnership\b|renounceOwnership\b|"
    r"mint\b|_mint\b|burn\b|_burn\b|"
    r"pause\b|_pause\b|unpause\b|_unpause\b|"
    r"withdraw\b|emergencyWithdraw\b|rescueTokens\b)",
    re.IGNORECASE,
)

# Word-boundary access modifier names
_ACCESS_MODIFIER_RE = re.compile(
    r"\b(?:onlyOwner|onlyAdmin|onlyRole|onlyMinter|onlyBurner|"
    r"requiresAuth|onlyGovernance|onlyOperator|onlyController|"
    r"onlySuperUser|onlyManager|onlyAuthorized|restricted|"
    r"onlyProxyAdmin|onlyUpgrader|onlyGuardian)\b",
    re.IGNORECASE,
)

# msg.sender equality/inequality checks
_SENDER_CHECK_RE = re.compile(
    r"(?:"
    r"require\s*\(\s*msg\.sender\s*==|"
    r"require\s*\(\s*\w+\s*==\s*msg\.sender|"
    r"require\s*\(\s*msg\.sender\s*!=|"
    r"msg\.sender\s*==\s*\w+|"
    r"msg\.sender\s*!=\s*\w+|"
    r"if\s*\(\s*msg\.sender\s*!=|"
    r"hasRole\s*\(.*msg\.sender|"
    r"_checkRole\s*\(.*msg\.sender|"
    r"isOwner\s*\(\s*msg\.sender|"
    r"_isAuthorized\s*\(.*msg\.sender"
    r")",
    re.IGNORECASE,
)

# FIX v1.2.0: Extended to detect modern Solidity custom error patterns:
#   error Unauthorized();
#   error NotOwner();
#   if (msg.sender != owner) revert Unauthorized();
#   revert NotOwner();
_REVERT_GUARD_RE = re.compile(
    r"(?:"
    # Classic revert with string
    r"revert\s*\(\s*[\"'].*(?:owner|auth|access|denied|forbidden).*[\"']\s*\)|"
    # Named revert — old style: revert Unauthorized()
    r"revert\s+\b(?:Unauthorized|NotOwner|AccessDenied|Forbidden|"
    r"OnlyOwner|NotAdmin|NotAuthorized|CallerNotOwner|Restricted)\b|"
    # FIX v1.2.0: Custom error declaration
    r"error\s+\b(?:Unauthorized|NotOwner|AccessDenied|Forbidden|"
    r"OnlyOwner|NotAdmin|NotAuthorized|CallerNotOwner|Restricted)\b"
    r")",
    re.IGNORECASE,
)

# FIX v1.2.0: Proxy detection — covers all common proxy base contract names
_PROXY_BASE_RE = re.compile(
    r"(?:proxy|upgradeable|erc1967|uups)",
    re.IGNORECASE,
)

# Destructive operations — always score maximum
_DESTRUCTIVE_OPS: FrozenSet[str] = frozenset({
    "selfdestruct", "SelfDestruct",
})

# Upgrade operations
_UPGRADE_OPS: FrozenSet[str] = frozenset({
    "upgradeTo", "upgradeToAndCall", "_upgradeTo",
})

# Asset-impact operations
_ASSET_OPS: FrozenSet[str] = frozenset({
    "withdraw", "emergencyWithdraw", "rescueTokens",
    "mint", "_mint",
    "burn", "_burn",
})


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _sv_name(v: object) -> str:
    """Normalise state variable to str whether string or StateVariable."""
    if hasattr(v, "name"):
        return str(v.name)          # type: ignore[union-attr]
    return str(v)


def _visibility(fn_info: FunctionInfo) -> str:
    """
    Safely extract visibility string from FunctionInfo.
    Handles both Visibility enum and plain string gracefully.
    """
    return getattr(fn_info.visibility, "value", fn_info.visibility)


def _is_proxy_contract(contract: ContractInfo) -> bool:
    """
    FIX v1.2.0: Detect proxy/upgradeable contracts by base contract names.

    Covers:
      ERC1967Proxy, TransparentUpgradeableProxy, UUPSUpgradeable,
      BeaconProxy, ProxyAdmin, UpgradeableBeacon, and any future
      proxy base that contains proxy/upgradeable/erc1967/uups.
    """
    return any(
        _PROXY_BASE_RE.search(b) for b in contract.base_contracts
    )


# ---------------------------------------------------------------------------
# Internal data classes
# ---------------------------------------------------------------------------

@dataclass
class _SensitiveOperation:
    """A detected privileged operation within a function's CFG."""
    cfg_node_id:    int
    operation:      str
    state_var:      Optional[str]
    ir_stmt:        Optional[str]
    source_line:    Optional[int]
    is_state_write: bool


@dataclass
class _AccessViolation:
    """
    A sensitive operation confirmed to have no access check.

    Invariant at construction:
      sensitive_op present in the function
      AND no reliable access check covers the function
    """
    operation:           _SensitiveOperation
    has_any_modifier:    bool
    has_sender_check:    bool
    has_revert_guard:    bool
    taint_confirms:      bool                      = False
    taint_source:        Optional[TaintSourceKind] = None


# ---------------------------------------------------------------------------
# Step 1 — Sensitive operation finder
# ---------------------------------------------------------------------------

class _SensitiveOperationFinder:
    """
    Locates privileged operations inside a function's CFG.

    O(N) — nodes iterated once. Both state variable writes and IR
    patterns are checked inside the same single pass over nodes.

    FIX v1.2.0: per-state-variable word-boundary check using
    re.search(rf"\b{re.escape(sv)}\b", combined, re.IGNORECASE).
    Eliminates false positives from substrings:
      owner  → no longer matches coowner, ownerMapping, ownerBalance
      admin  → no longer matches adminFee, adminPanel
    """

    def find(
        self,
        fn_info: FunctionInfo,
        cfg:     CFGGraph,
    ) -> List[_SensitiveOperation]:
        ops:  List[_SensitiveOperation] = []
        seen: Set[Tuple[int, str]]      = set()

        sv_written: Set[str]     = {_sv_name(v) for v in fn_info.state_vars_written}
        privileged_svs: Set[str] = {
            sv for sv in sv_written if _PRIVILEGED_VAR_RE.search(sv)
        }

        for node in cfg.ordered_nodes():
            combined = " ".join(node.ir_stmts)

            # Strategy A — privileged state variable writes
            for sv in privileged_svs:
                # FIX v1.2.0: word-boundary check — not plain substring
                if not re.search(
                    rf"\b{re.escape(sv)}\b", combined, re.IGNORECASE
                ):
                    continue
                key = (node.node_id, sv)
                if key in seen:
                    continue
                seen.add(key)
                ops.append(_SensitiveOperation(
                    cfg_node_id    = node.node_id,
                    operation      = f"write to '{sv}'",
                    state_var      = sv,
                    ir_stmt        = combined[:120],
                    source_line    = node.source_line,
                    is_state_write = True,
                ))

            # Strategy B — IR operation patterns
            for stmt in node.ir_stmts:
                m = _PRIVILEGED_OP_RE.search(stmt)
                if not m:
                    continue
                op_name = m.group(0).strip()
                key = (node.node_id, op_name)
                if key in seen:
                    continue
                seen.add(key)
                ops.append(_SensitiveOperation(
                    cfg_node_id    = node.node_id,
                    operation      = op_name,
                    state_var      = None,
                    ir_stmt        = stmt[:120],
                    source_line    = node.source_line,
                    is_state_write = False,
                ))

        return ops


# ---------------------------------------------------------------------------
# Step 2 — Access check finder
# ---------------------------------------------------------------------------

class _AccessCheckFinder:
    """
    Detects access control checks present in a function.

    Three check types — independent:
      1. Modifier-based  — fn_info.modifiers contains access modifier
      2. Sender check    — ir_stmts contains msg.sender check
      3. Revert guard    — ir_stmts contains named revert or custom error

    Early-exits on modifier detection — strongest signal, no CFG needed.
    Uses cfg.ordered_nodes() for deterministic iteration.

    FIX v1.2.0: _REVERT_GUARD_RE now also matches custom error declarations
    (error Unauthorized()) so modern Solidity patterns are detected.
    """

    def find(
        self,
        fn_info: FunctionInfo,
        cfg:     CFGGraph,
    ) -> Tuple[bool, bool, bool]:
        """Returns (has_access_modifier, has_sender_check, has_revert_guard)."""

        has_modifier = self._check_modifiers(fn_info)
        if has_modifier:
            return True, False, False

        has_sender_check = False
        has_revert_guard = False

        for node in cfg.ordered_nodes():
            combined = " ".join(node.ir_stmts)

            if not has_sender_check and _SENDER_CHECK_RE.search(combined):
                has_sender_check = True

            if not has_revert_guard and _REVERT_GUARD_RE.search(combined):
                has_revert_guard = True

            if has_sender_check and has_revert_guard:
                break

        return has_modifier, has_sender_check, has_revert_guard

    @staticmethod
    def _check_modifiers(fn_info: FunctionInfo) -> bool:
        return any(_ACCESS_MODIFIER_RE.search(mod) for mod in fn_info.modifiers)


# ---------------------------------------------------------------------------
# Step 3 — Violation checker
# ---------------------------------------------------------------------------

class _ViolationChecker:
    """
    Violation = sensitive op present AND no access check AND public/external.
    Internal/private functions skipped entirely.
    """

    _PUBLIC_VISIBILITIES: FrozenSet[str] = frozenset({"external", "public"})

    def check(
        self,
        fn_info:          FunctionInfo,
        ops:              List[_SensitiveOperation],
        has_modifier:     bool,
        has_sender_check: bool,
        has_revert_guard: bool,
    ) -> List[_AccessViolation]:
        if _visibility(fn_info) not in self._PUBLIC_VISIBILITIES:
            return []
        if has_modifier or has_sender_check or has_revert_guard:
            return []
        return [
            _AccessViolation(
                operation        = op,
                has_any_modifier = has_modifier,
                has_sender_check = has_sender_check,
                has_revert_guard = has_revert_guard,
            )
            for op in ops
        ]


# ---------------------------------------------------------------------------
# Step 5 — Taint enricher
# ---------------------------------------------------------------------------

class _TaintEnricher:
    """
    Confirms whether msg.sender flows into a conditional near the operation.
    Confidence modifier — not a detection requirement.
    """

    _SENDER_SOURCES: FrozenSet[TaintSourceKind] = frozenset({
        TaintSourceKind.MSG_SENDER,
    })
    _CONDITION_SINKS: FrozenSet[TaintSinkKind] = frozenset({
        TaintSinkKind.REQUIRE_CONDITION,
    })

    def enrich(
        self,
        violations:   List[_AccessViolation],
        taint_result: Optional[TaintResult],
    ) -> None:
        if not taint_result or not taint_result.flows:
            return
        for violation in violations:
            for flow in taint_result.flows:
                if flow.source_kind not in self._SENDER_SOURCES:
                    continue
                if flow.sink_kind not in self._CONDITION_SINKS:
                    continue
                if flow.cfg_node_id == violation.operation.cfg_node_id:
                    violation.taint_confirms = True
                    violation.taint_source   = flow.source_kind
                    break


# ---------------------------------------------------------------------------
# Step 7 — Finding builder
# ---------------------------------------------------------------------------

class _FindingBuilder:
    """
    Converts _AccessViolation into Finding.
    Receives recommendation and cvss_score from safe_recommendation()
    and safe_cvss() — never generates them internally.

    Severity matrix:
    ┌──────────────────────────────────────────────────────────┬──────────┐
    │ Condition                                                │ Severity │
    ├──────────────────────────────────────────────────────────┼──────────┤
    │ selfdestruct / upgrade / transferOwnership + no check    │ CRITICAL │
    │ owner/admin state write + no check + payable             │ CRITICAL │
    │ owner/admin state write + no check                       │ HIGH     │
    │ mint / burn / pause / withdraw + no check                │ HIGH     │
    │ other privileged op + no check                           │ MEDIUM   │
    └──────────────────────────────────────────────────────────┴──────────┘

    Confidence:
      Base 0.80  + taint(+0.15) + payable(+0.05)
      Clamped [0.50, 1.00]
    """

    _BASE      = 0.80
    _P_TAINT   = 0.15
    _P_PAYABLE = 0.05
    _MIN       = 0.50
    _MAX       = 1.00

    _CRITICAL_OPS: FrozenSet[str] = frozenset({
        "selfdestruct", "SelfDestruct",
        "upgradeTo", "upgradeToAndCall", "_upgradeTo",
        "transferOwnership", "renounceOwnership",
    })
    _HIGH_OPS: FrozenSet[str] = frozenset({
        "mint", "_mint", "burn", "_burn",
        "pause", "_pause", "unpause", "_unpause",
        "withdraw", "emergencyWithdraw", "rescueTokens",
    })

    def build(
        self,
        violation:        _AccessViolation,
        contract_name:    str,
        fn_info:          FunctionInfo,
        detector_id:      str,
        detector_version: str,
        vuln_type:        VulnerabilityType,
        recommendation:   str,
        cvss_score:       float,
        is_payable:       bool,
    ) -> Finding:
        return Finding(
            vuln_type        = vuln_type,
            severity         = self._severity(violation, is_payable),
            contract_name    = contract_name,
            function_name    = fn_info.name,
            source_file      = fn_info.source_file,
            start_line       = violation.operation.source_line,
            title            = self._title(violation, fn_info),
            description      = self._description(violation, fn_info),
            recommendation   = recommendation,
            confidence       = self._confidence(violation, is_payable),
            cvss_score       = cvss_score,
            detector_id      = detector_id,
            detector_version = detector_version,
            metadata         = FindingMetadata(extra={
                "operation":           violation.operation.operation,
                "state_var":           violation.operation.state_var,
                "ir_stmt":             violation.operation.ir_stmt,
                "cfg_node_id":         violation.operation.cfg_node_id,
                "is_state_write":      violation.operation.is_state_write,
                "has_any_modifier":    violation.has_any_modifier,
                "has_sender_check":    violation.has_sender_check,
                "has_revert_guard":    violation.has_revert_guard,
                "taint_confirms":      violation.taint_confirms,
                "taint_source":        (
                    violation.taint_source.value
                    if violation.taint_source else None
                ),
            },
    ), )

    def _severity(self, v: _AccessViolation, is_payable: bool) -> Severity:
        op = v.operation.operation
        if any(op.startswith(c) for c in self._CRITICAL_OPS):
            return Severity.CRITICAL
        if v.operation.is_state_write:
            return Severity.CRITICAL if is_payable else Severity.HIGH
        if any(op.startswith(h) for h in self._HIGH_OPS):
            return Severity.HIGH
        return Severity.MEDIUM

    def _confidence(self, v: _AccessViolation, is_payable: bool) -> float:
        score = self._BASE
        if v.taint_confirms:
            score += self._P_TAINT
        if is_payable:
            score += self._P_PAYABLE
        return max(self._MIN, min(self._MAX, round(score, 4)))

    @staticmethod
    def _title(v: _AccessViolation, fn_info: FunctionInfo) -> str:
        return (
            f"Access Control: '{fn_info.name}' performs "
            f"{v.operation.operation} without any access restriction"
        )

    @staticmethod
    def _description(v: _AccessViolation, fn_info: FunctionInfo) -> str:
        parts: List[str] = [
            f"Function '{fn_info.name}' performs a privileged operation "
            f"({v.operation.operation})"
        ]
        if v.operation.source_line:
            parts.append(f"at line {v.operation.source_line}")
        parts.append(
            "without any access control check. "
            "No access modifier, no msg.sender check, "
            "and no named revert guard was detected. "
            "Any external address can call this function."
        )
        if v.taint_confirms:
            parts.append(
                "Taint analysis confirms msg.sender data does not "
                "flow into any conditional check before this operation."
            )
        return " ".join(parts)


# ---------------------------------------------------------------------------
# Public detector
# ---------------------------------------------------------------------------

class AccessControlDetector(BaseDetector):
    """
    Detects missing access control on privileged functions.

    Implements the full BaseDetector contract:
      detect()               — 7-step pipeline
      build_recommendation() — operation-specific, data-driven
      calculate_cvss()       — context-aware risk scoring
    """

    DETECTOR_ID      = "access_control_v1"
    DETECTOR_VERSION = "1.2.0"
    VULN_TYPE        = VulnerabilityType.ACCESS_CONTROL
    DEFAULT_SEVERITY = Severity.HIGH

    def __init__(self) -> None:
        self._op_finder       = _SensitiveOperationFinder()
        self._check_finder    = _AccessCheckFinder()
        self._violation_check = _ViolationChecker()
        self._taint_enricher  = _TaintEnricher()
        self._finding_builder = _FindingBuilder()

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

        if not fn_info.state_vars_written and not cfg.nodes:
            return []

        if _visibility(fn_info) not in ("external", "public"):
            return []

        is_payable = (
            getattr(fn_info.state_mutability, "value", fn_info.state_mutability)
            == "payable"
        )

        # ── Step 1: Find sensitive operations ─────────────────────────
        ops = self._op_finder.find(fn_info, cfg)
        if not ops:
            logger.debug(
                "AccessControl: '%s.%s' — no sensitive operations found.",
                contract.name, fn_info.name,
            )
            return []

        # ── Step 2: Find access checks ────────────────────────────────
        has_modifier, has_sender_check, has_revert_guard = (
            self._check_finder.find(fn_info, cfg)
        )

        # ── Step 3: Violation check ───────────────────────────────────
        violations = self._violation_check.check(
            fn_info, ops,
            has_modifier, has_sender_check, has_revert_guard,
        )
        if not violations:
            logger.debug(
                "AccessControl: '%s.%s' — access check present, no violation.",
                contract.name, fn_info.name,
            )
            return []

        # ── Step 5: Taint enrichment ──────────────────────────────────
        self._taint_enricher.enrich(violations, taint_result)

        # ── Step 6: Deduplication ─────────────────────────────────────
        seen:         Set[Tuple[int, str]]   = set()
        deduplicated: List[_AccessViolation] = []
        for v in violations:
            key = (v.operation.cfg_node_id, v.operation.operation)
            if key not in seen:
                seen.add(key)
                deduplicated.append(v)

        # ── Step 7: Build findings ────────────────────────────────────
        findings: List[Finding] = []
        for v in deduplicated:
            context = self._build_context(
                v, fn_info, contract, is_payable, len(deduplicated)
            )
            finding = self._finding_builder.build(
                violation        = v,
                contract_name    = contract.name,
                fn_info          = fn_info,
                detector_id      = self.DETECTOR_ID,
                detector_version = self.DETECTOR_VERSION,
                vuln_type        = self.VULN_TYPE,
                recommendation   = self.safe_recommendation(context),
                cvss_score       = self.safe_cvss(context),
                is_payable       = is_payable,
            )
            findings.append(finding)
            logger.debug(
                "AccessControl: '%s.%s' — %s severity, conf=%.2f, "
                "cvss=%.1f, op='%s', node=%d.",
                contract.name, fn_info.name,
                finding.severity.value, finding.confidence,
                finding.cvss_score,
                v.operation.operation, v.operation.cfg_node_id,
            )

        return findings

    def build_recommendation(self, context: dict) -> str:
        fn_name    = context["function_name"]
        op         = context.get("sensitive_operation", "a privileged operation")
        sv         = context.get("state_var_modified")
        line       = context.get("line_number")
        is_payable = context.get("is_payable", False)

        loc     = f" at line {line}" if line is not None else ""
        op_lower = op.lower()
        sv_lower = (sv or "").lower()

        rec = (
            f"In function '{fn_name}'{loc}: {op} is performed "
            f"without any access control check. "
            f"Any external address can trigger this operation. "
        )

        if "selfdestruct" in op_lower:
            rec += (
                f"selfdestruct is irreversible and permanently destroys "
                f"the contract. Restrict '{fn_name}' with 'onlyOwner' "
                f"immediately."
            )
        elif "upgrade" in op_lower:
            rec += (
                f"Proxy upgrades replace contract logic entirely. "
                f"Add 'onlyOwner' or OpenZeppelin's 'onlyProxyAdmin' "
                f"modifier to '{fn_name}'."
            )
        elif "mint" in op_lower:
            rec += (
                f"Unrestricted minting inflates token supply. "
                f"Use OpenZeppelin AccessControl with a dedicated "
                f"MINTER_ROLE or add 'onlyOwner' to '{fn_name}'."
            )
        elif "burn" in op_lower:
            rec += (
                f"Unrestricted burning destroys tokens. "
                f"Restrict '{fn_name}' with a BURNER_ROLE or 'onlyOwner'."
            )
        elif "withdraw" in op_lower:
            rec += (
                f"Unrestricted withdrawal drains contract funds. "
                f"Add 'onlyOwner' or require(msg.sender == owner) "
                f"to '{fn_name}'."
            )
        elif "pause" in op_lower or "unpause" in op_lower:
            rec += (
                f"Pause functions must be restricted to trusted admins. "
                f"Add 'onlyOwner' or a PAUSER_ROLE check to '{fn_name}'."
            )
        elif sv and any(k in sv_lower for k in ("owner", "admin", "governance")):
            rec += (
                f"Add an 'onlyOwner' modifier or "
                f"require(msg.sender == owner, \"Not owner\") "
                f"at the top of '{fn_name}' to restrict "
                f"who can modify '{sv}'."
            )
        elif sv and any(k in sv_lower for k in ("paused", "whitelist", "blacklist")):
            rec += (
                f"Add an 'onlyAdmin' modifier or an explicit "
                f"require(msg.sender == admin) check to restrict "
                f"modification of '{sv}'."
            )
        else:
            rec += (
                f"Restrict access to '{fn_name}' with an appropriate "
                f"modifier (e.g. 'onlyOwner') or an explicit "
                f"require(msg.sender == authorizedAddress) check."
            )

        if is_payable:
            rec += (
                f" '{fn_name}' is also payable — an unrestricted payable "
                f"privileged function allows an attacker to both execute "
                f"the operation and send ETH in the same call."
            )

        return rec

    def calculate_cvss(self, context: dict) -> float:
        """
        Context-aware CVSS for one access control finding.

        Base: 8.0

        ┌──────────────────────────────────────────────────────┬───────┐
        │ Condition                                            │ Delta │
        ├──────────────────────────────────────────────────────┼───────┤
        │ selfdestruct                                         │  10.0 │ (immediate return)
        │ upgrade operation                                    │ +2.0  │
        │ governance variable (owner/admin/impl/proxy)         │ +1.2  │
        │ withdraw / emergencyWithdraw                         │ +0.8  │
        │ mint / _mint                                         │ +0.8  │
        │ burn / _burn                                         │ +0.5  │
        │ external or public visibility                        │ +0.3  │
        │ is_payable                                           │ +0.3  │
        │ external + payable combination                       │ +0.2  │
        │ contract_is_proxy                                    │ +0.7  │
        │ taint confirms                                       │ +0.5  │
        │ taint_source == msg_value                            │ +0.1  │
        │ num_sensitive_ops > 1                                │ +0.4  │
        │ no modifier AND no sender check (exploitability)     │ +0.6  │
        │ asset impact multiplier (withdraw/mint)              │ ×1.1  │
        ├──────────────────────────────────────────────────────┼───────┤
        │ has_access_modifier (strongest mitigation)           │ −1.5  │
        │ has_msg_sender_check (medium mitigation)             │ −0.9  │
        │ has_revert_guard (weakest mitigation)                │ −0.4  │
        └──────────────────────────────────────────────────────┴───────┘
        Final score clamped to [0.0, 10.0].
        """
        score      = 8.0
        op         = context.get("sensitive_operation", "").lower()
        sv         = (context.get("state_var_modified") or "").lower()
        visibility = context.get("function_visibility", "")
        is_payable = context.get("is_payable", False)

        # Destructive override
        if "selfdestruct" in op:
            return 10.0

        if "upgrade" in op:
            score += 2.0

        if _GOVERNANCE_VAR_RE.search(sv):
            score += 1.2

        if "withdraw" in op:
            score += 0.8
        if "mint" in op:
            score += 0.8
        if "burn" in op:
            score += 0.5

        # Attack surface
        if visibility in ("external", "public"):
            score += 0.3

        if is_payable:
            score += 0.3

        # FIX v1.2.0: external + payable combination — attacker sends ETH
        # to trigger privileged execution in same call
        if is_payable and visibility == "external":
            score += 0.2

        # Proxy risk
        if context.get("contract_is_proxy"):
            score += 0.7

        # Taint
        if context.get("taint_confirms"):
            score += 0.5
            if context.get("taint_source") == "msg_value":
                score += 0.1

        # Multi-operation escalation
        if context.get("num_sensitive_ops", 1) > 1:
            score += 0.4

        # Exploitability — fully unprotected
        if (
            not context.get("has_access_modifier")
            and not context.get("has_msg_sender_check")
        ):
            score += 0.6

        # Economic multiplier
        if "withdraw" in op or "mint" in op:
            score *= 1.1

        # Mitigation weighting — strongest to weakest
        if context.get("has_access_modifier"):
            score -= 1.5
        elif context.get("has_msg_sender_check"):
            score -= 0.9
        elif context.get("has_revert_guard"):
            score -= 0.4

        return round(max(0.0, min(10.0, score)), 1)

    # ------------------------------------------------------------------
    # Context builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_context(
        v:                 _AccessViolation,
        fn_info:           FunctionInfo,
        contract:          ContractInfo,
        is_payable:        bool,
        num_sensitive_ops: int,
    ) -> dict:
        """Single source of truth for safe_recommendation() and safe_cvss()."""
        return {
            "contract_name":        contract.name,
            "function_name":        fn_info.name,
            "function_visibility":  _visibility(fn_info),
            "is_payable":           is_payable,
            "sensitive_operation":  v.operation.operation,
            "state_var_modified":   v.operation.state_var,
            "line_number":          v.operation.source_line,
            "cfg_node_id":          v.operation.cfg_node_id,
            "ir_stmt":              v.operation.ir_stmt,
            "is_state_write":       v.operation.is_state_write,
            "has_access_modifier":  v.has_any_modifier,
            "has_msg_sender_check": v.has_sender_check,
            "has_revert_guard":     v.has_revert_guard,
            "taint_confirms":       v.taint_confirms,
            "taint_source":         (
                v.taint_source.value if v.taint_source else None
            ),
            "num_sensitive_ops":    num_sensitive_ops,
            # FIX v1.2.0: full proxy detection using _is_proxy_contract()
            "contract_is_proxy":    _is_proxy_contract(contract),
        }
