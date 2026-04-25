"""
detectors/business_logic.py

Business Logic vulnerability detector for VigilanceCore.

Detects design-level flaws in economic and functional logic.
Uses VigilanceCore FunctionInfo + CFGNode API exclusively — no raw Slither
objects are accessed anywhere in this file.

Patterns detected:
  1. CEI violation — ETH/token transfer with no subsequent state update
  2. Precision loss — integer division before multiplication
  3. Missing balance guard — transfer without require(balance >= amount)

Change log:
  v1.0.0 — Initial implementation using Slither native Node API (broken —
            crashed on every function with 'state_vars_written' AttributeError
            because business_logic.py was passed VigilanceCore CFGNode objects
            but accessed Slither Node attributes).
  v2.0.0 — Full port to VigilanceCore API:
            - detect() signature matches BaseDetector exactly (5 params)
            - Uses fn_info.state_vars_written (FunctionInfo tuple) for state-
              write checks instead of node.state_vars_written (Slither Node)
            - Uses fn_info.external_calls (ExternalCallInfo) for call detection
            - Uses fn_info.visibility (Visibility enum) for visibility checks
            - CFG IR text / optype scan used only as fallback
            - No Slither imports remain
"""
from __future__ import annotations

import logging
import re
from typing import ClassVar, Dict, List, Optional, Set

from core.cfg_builder import CFGGraph, DFGGraph
from core.enums import CallType, Severity, VulnerabilityType, Visibility
from core.models import ContractInfo, Finding, FindingMetadata, FunctionInfo
from core.taint_engine import TaintResult
from detectors.base_detector import BaseDetector

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# IR optype sets — matched against CFGNode.ir_op_types
# ---------------------------------------------------------------------------
_TRANSFER_OPTYPES: frozenset[str] = frozenset({"Transfer", "Send"})

# ---------------------------------------------------------------------------
# Regex patterns — matched against CFGNode.ir_stmts strings
# ---------------------------------------------------------------------------

# ETH / token transfer in IR text
_TRANSFER_STMT_RE = re.compile(
    r"\.(?:transfer|send)\s*\(|\bTransfer\b|\bSend\b",
    re.IGNORECASE,
)
_TOKEN_TRANSFER_RE = re.compile(
    r"\b(?:transfer|transferFrom|safeTransfer|safeTransferFrom)\s*\(",
    re.IGNORECASE,
)

# State-write heuristic fallback (IR text)
_ASSIGN_STMT_RE = re.compile(r"\b\w+\s*=\s*\w|\bAssignment\b", re.IGNORECASE)

# Guard detection
_REQUIRE_RE = re.compile(r"\b(?:require|assert)\s*\(", re.IGNORECASE)
_BALANCE_EXPR_RE = re.compile(
    r"\b(?:balance[s]?|amount|value|fund|wei|ether)\b.*[><=!]",
    re.IGNORECASE,
)

# Division / multiplication pattern in a single IR stmt
_DIV_ASSIGN_RE = re.compile(r"^(\w+)\s*=.*?(\w+)\s*/\s*(\w+)")


class BusinessLogicDetector(BaseDetector):
    """
    Detects business logic vulnerabilities in Solidity contract functions.

    Uses FunctionInfo structured data as primary source:
      - fn_info.state_vars_written  → state-write check (tuple of StateVariable)
      - fn_info.external_calls      → call detection (tuple of ExternalCallInfo)
      - fn_info.visibility          → Visibility enum (not a raw string)
    CFG IR scan is the fallback when structured data is insufficient.
    """

    DETECTOR_ID:      ClassVar[str]               = "business_logic_v2"
    DETECTOR_VERSION: ClassVar[str]               = "2.0.0"
    VULN_TYPE:        ClassVar[VulnerabilityType]  = VulnerabilityType.LOGIC_ERROR
    DEFAULT_SEVERITY: ClassVar[Severity]           = Severity.HIGH
    NEEDS_STATELESS_ANALYSIS: ClassVar[bool]       = False

    # ------------------------------------------------------------------
    # Public entry-point
    # ------------------------------------------------------------------

    def detect(
        self,
        contract: ContractInfo,
        fn_info: FunctionInfo,
        cfg: CFGGraph,
        dfg: DFGGraph,
        taint_result: Optional[TaintResult],
    ) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self._check_missing_state_update(contract, fn_info, cfg))
        findings.extend(self._check_precision_loss(contract, fn_info, cfg))
        findings.extend(self._check_missing_balance_guard(contract, fn_info, cfg))
        return findings

    # ------------------------------------------------------------------
    # Check 1 — CEI violation: transfer with no state update
    # ------------------------------------------------------------------

    def _check_missing_state_update(
        self,
        contract: ContractInfo,
        fn_info: FunctionInfo,
        cfg: CFGGraph,
    ) -> List[Finding]:
        # Only public/external functions are exploitable externally
        if fn_info.visibility not in (Visibility.PUBLIC, Visibility.EXTERNAL):
            return []

        # ---- Detect ETH/token transfer ----
        # Primary: fn_info.external_calls (structured ExternalCallInfo)
        has_transfer = any(
            ec.call_type in (CallType.TRANSFER, CallType.SEND, CallType.CALL)
            and ec.value_transfer
            for ec in fn_info.external_calls
        )
        transfer_line: Optional[int] = None

        # Fallback: CFG IR optype / text scan
        if not has_transfer:
            for node in cfg.nodes.values():
                if set(node.ir_op_types) & _TRANSFER_OPTYPES:
                    has_transfer = True
                    transfer_line = node.source_line
                    break
                combined = " ".join(node.ir_stmts)
                if _TRANSFER_STMT_RE.search(combined) or _TOKEN_TRANSFER_RE.search(combined):
                    has_transfer = True
                    transfer_line = node.source_line
                    break

        if not has_transfer:
            return []

        # ---- Detect state writes ----
        # Primary: fn_info.state_vars_written (tuple[StateVariable, ...])
        # This is the key fix — previously used node.state_vars_written (Slither
        # attribute that does NOT exist on VigilanceCore CFGNode).
        has_state_write = bool(fn_info.state_vars_written)

        # Fallback: CFG IR optype / text scan
        if not has_state_write:
            for node in cfg.nodes.values():
                if "Assignment" in node.ir_op_types:
                    has_state_write = True
                    break
                combined = " ".join(node.ir_stmts)
                if _ASSIGN_STMT_RE.search(combined):
                    has_state_write = True
                    break

        if has_state_write:
            return []

        return [Finding(
            vuln_type=VulnerabilityType.LOGIC_ERROR,
            severity=Severity.HIGH,
            contract_name=contract.name,
            function_name=fn_info.name,
            start_line=transfer_line or fn_info.start_line,
            title=f"CEI Violation — No State Update After Transfer in `{fn_info.name}`",
            description=(
                f"`{fn_info.name}` in `{contract.name}` transfers ETH or tokens "
                f"but does not write any state variable. This violates the "
                f"Checks-Effects-Interactions pattern and may expose the function "
                f"to re-entrancy or double-spend attacks."
            ),
            recommendation=(
                "Apply Checks-Effects-Interactions — update all state BEFORE the call:\n"
                "  balances[msg.sender] -= amount;  // Effect first\n"
                "  payable(msg.sender).transfer(amount);  // Interaction last"
            ),
            confidence=0.65,
            detector_id=self.DETECTOR_ID,
            detector_version=self.DETECTOR_VERSION,
            metadata=FindingMetadata(extra={"pattern": "cei_violation"}),
        )]

    # ------------------------------------------------------------------
    # Check 2 — Precision loss: division before multiplication
    # ------------------------------------------------------------------

    def _check_precision_loss(
        self,
        contract: ContractInfo,
        fn_info: FunctionInfo,
        cfg: CFGGraph,
    ) -> List[Finding]:
        findings: List[Finding] = []
        # varname → source line of the division that produced it
        div_vars: Dict[str, int] = {}

        for node in cfg.ordered_nodes():
            line = node.source_line or 0
            for stmt in node.ir_stmts:
                stmt = stmt.strip()

                # Record variable produced by integer division
                if "/" in stmt:
                    m = _DIV_ASSIGN_RE.match(stmt)
                    if m:
                        lval = m.group(1)
                        div_vars[lval] = line

                # Check if a previously-divided variable is now multiplied
                if "*" in stmt:
                    for var, div_line in list(div_vars.items()):
                        mul_re = re.compile(
                            rf"\b{re.escape(var)}\b.*\*|\*.*\b{re.escape(var)}\b"
                        )
                        if mul_re.search(stmt):
                            findings.append(Finding(
                                vuln_type=VulnerabilityType.LOGIC_ERROR,
                                severity=Severity.MEDIUM,
                                contract_name=contract.name,
                                function_name=fn_info.name,
                                start_line=line,
                                title=(
                                    f"Precision Loss — Division Before Multiplication "
                                    f"in `{fn_info.name}`"
                                ),
                                description=(
                                    f"`{fn_info.name}` divides `{var}` at line {div_line} "
                                    f"then multiplies the truncated result at line {line}. "
                                    f"Integer division truncates toward zero, causing "
                                    f"precision loss. Always multiply before dividing."
                                ),
                                recommendation=(
                                    "Reorder to multiply before dividing:\n"
                                    "  GOOD: result = (amount * multiplier) / divisor;\n"
                                    "  BAD:  result = (amount / divisor) * multiplier;"
                                ),
                                confidence=0.70,
                                detector_id=self.DETECTOR_ID,
                                detector_version=self.DETECTOR_VERSION,
                                metadata=FindingMetadata(extra={
                                    "pattern": "precision_loss",
                                    "variable": var,
                                    "div_line": div_line,
                                    "mul_line": line,
                                }),
                            ))
                            del div_vars[var]
                            break   # one finding per variable
        return findings

    # ------------------------------------------------------------------
    # Check 3 — Missing balance/input guard before transfer
    # ------------------------------------------------------------------

    def _check_missing_balance_guard(
        self,
        contract: ContractInfo,
        fn_info: FunctionInfo,
        cfg: CFGGraph,
    ) -> List[Finding]:
        # Only public/external functions matter
        if fn_info.visibility not in (Visibility.PUBLIC, Visibility.EXTERNAL):
            return []

        has_transfer = False
        has_guard = False
        transfer_line: Optional[int] = None

        for node in cfg.ordered_nodes():
            combined = " ".join(node.ir_stmts)

            # Check for a require/assert with a balance-like expression
            if _REQUIRE_RE.search(combined) and _BALANCE_EXPR_RE.search(combined):
                has_guard = True

            # Check for ETH/token transfer
            optypes = set(node.ir_op_types)
            if (optypes & _TRANSFER_OPTYPES) or _TRANSFER_STMT_RE.search(combined):
                if not has_transfer:
                    transfer_line = node.source_line
                has_transfer = True

        if not has_transfer or has_guard:
            return []

        return [Finding(
            vuln_type=VulnerabilityType.LOGIC_ERROR,
            severity=Severity.HIGH,
            contract_name=contract.name,
            function_name=fn_info.name,
            start_line=transfer_line or fn_info.start_line,
            title=f"Missing Balance Guard Before Transfer in `{fn_info.name}`",
            description=(
                f"`{fn_info.name}` in `{contract.name}` transfers ETH or tokens "
                f"without a `require(balance >= amount)` guard. This may allow "
                f"overdrafts, underflows, or insolvency."
            ),
            recommendation=(
                "Add an explicit balance check before the transfer:\n"
                "  require(balances[msg.sender] >= amount, \'Insufficient balance\');\n"
                "  balances[msg.sender] -= amount;   // Update state first\n"
                "  payable(msg.sender).transfer(amount);"
            ),
            confidence=0.60,
            detector_id=self.DETECTOR_ID,
            detector_version=self.DETECTOR_VERSION,
            metadata=FindingMetadata(extra={"pattern": "missing_balance_guard"}),
        )]

    # ------------------------------------------------------------------
    # BaseDetector abstract methods
    # ------------------------------------------------------------------

    def build_recommendation(self, context: dict) -> str:
        title = context.get("title", "")
        if "CEI" in title or "State Update" in title:
            return (
                "Apply Checks-Effects-Interactions: update state variables "
                "before making any external call or transfer."
            )
        if "Precision Loss" in title:
            return "Multiply before dividing: `result = (a * b) / c` not `(a / c) * b`."
        if "Balance Guard" in title:
            return (
                "Add `require(balances[msg.sender] >= amount, \'Insufficient\')` "
                "before any transfer."
            )
        return "Review function business logic for CEI pattern compliance."

    def calculate_cvss(self, context: dict) -> float:
        title = context.get("title", "")
        if "CEI" in title or "State Update" in title:
            return 7.5
        if "Precision Loss" in title:
            return 5.5
        if "Balance Guard" in title:
            return 7.0
        return 5.0
