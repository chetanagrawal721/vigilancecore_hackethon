"""
detectors/dos_detector.py

Denial-of-Service (DoS) vulnerability detector for VigilanceCore.

Detects three classic DoS patterns using VigilanceCore CFGNode API:
  1. LOOP OVER EXTERNAL CALLS   — .call / .transfer / .send inside a loop body
  2. UNBOUNDED LOOP OVER STATE  — loop bound derived from a state array .length
  3. UNGUARDED SEND / TRANSFER  — ETH transfer whose return is not checked

Change log:
  v1.0.0 — Initial implementation using Slither native API (broken — crashed
            on every function with NodeType / node.fathers AttributeErrors)
  v2.0.0 — Full port to VigilanceCore CFGNode / FunctionInfo API.
            No Slither objects accessed after construction.
            detect() signature matches BaseDetector exactly (5 params).
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
# IR optype sets — matched against CFGNode.ir_op_types (Slither IR class names)
# ---------------------------------------------------------------------------
_ALL_CALL_OPTYPES: frozenset[str] = frozenset({
    "Transfer", "Send", "LowLevelCall", "HighLevelCall",
})
_ETH_SEND_OPTYPES: frozenset[str] = frozenset({"Transfer", "Send"})

# ---------------------------------------------------------------------------
# Regex patterns — matched against CFGNode.ir_stmts joined strings
# ---------------------------------------------------------------------------
_CALL_STMT_RE = re.compile(
    r"\.(?:call|transfer|send)\s*[\({]"
    r"|\bLowLevelCall\b|\bHighLevelCall\b|\bTransfer\b|\bSend\b",
    re.IGNORECASE,
)
_SEND_STMT_RE = re.compile(
    r"\.(?:transfer|send)\s*\(|\bTransfer\b|\bSend\b",
    re.IGNORECASE,
)
_LENGTH_RE = re.compile(r"\.length\b", re.IGNORECASE)


class DosDetector(BaseDetector):
    """
    Detects Denial-of-Service patterns in Solidity contract functions.

    Runs per-function. Each call to detect() receives one function's
    FunctionInfo + CFGGraph — no Slither objects.
    """

    DETECTOR_ID:      ClassVar[str]               = "dos_v2"
    DETECTOR_VERSION: ClassVar[str]               = "2.0.0"
    VULN_TYPE:        ClassVar[VulnerabilityType]  = VulnerabilityType.DOS
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
        seen: Set[str] = set()

        loop_body: Set[int] = self._collect_loop_body(cfg)

        findings.extend(self._p1_loop_over_calls(contract, fn_info, cfg, loop_body, seen))
        findings.extend(self._p2_unbounded_loop(contract, fn_info, cfg, seen))
        findings.extend(self._p3_unguarded_send(contract, fn_info, cfg, loop_body, seen))

        return findings

    # ------------------------------------------------------------------
    # Pattern 1 — loop containing external call
    # ------------------------------------------------------------------

    def _p1_loop_over_calls(
        self,
        contract: ContractInfo,
        fn_info: FunctionInfo,
        cfg: CFGGraph,
        loop_body: Set[int],
        seen: Set[str],
    ) -> List[Finding]:
        findings: List[Finding] = []
        for nid in loop_body:
            node = cfg.nodes.get(nid)
            if node is None:
                continue

            # Primary: ir_op_types (extracted IR class names — never cleared)
            has_call = bool(set(node.ir_op_types) & _ALL_CALL_OPTYPES)
            # Fallback: ir_stmts text
            if not has_call:
                combined = " ".join(node.ir_stmts)
                has_call = bool(_CALL_STMT_RE.search(combined))
            if not has_call:
                continue

            key = f"p1_loop_call_{nid}"
            if key in seen:
                continue
            seen.add(key)

            call_label = self._describe_call(node)
            findings.append(Finding(
                vuln_type=VulnerabilityType.DOS,
                severity=Severity.HIGH,
                contract_name=contract.name,
                function_name=fn_info.name,
                start_line=node.source_line,
                title="DoS — Loop Over External Calls",
                description=(
                    f"`{fn_info.name}` in `{contract.name}` performs a "
                    f"{call_label} inside a loop. If any recipient reverts "
                    f"or runs out of gas the entire transaction fails, "
                    f"permanently locking the contract."
                ),
                recommendation=(
                    "Use the withdrawal pattern: store pending amounts in a "
                    "mapping and let recipients pull their own ETH, removing "
                    "the loop over external calls entirely."
                ),
                confidence=0.80,
                detector_id=self.DETECTOR_ID,
                detector_version=self.DETECTOR_VERSION,
                metadata=FindingMetadata(extra={"call_type": call_label, "cfg_node": nid}),
            ))
        return findings

    # ------------------------------------------------------------------
    # Pattern 2 — unbounded loop over state-array .length
    # ------------------------------------------------------------------

    def _p2_unbounded_loop(
        self,
        contract: ContractInfo,
        fn_info: FunctionInfo,
        cfg: CFGGraph,
        seen: Set[str],
    ) -> List[Finding]:
        findings: List[Finding] = []
        for node in cfg.nodes.values():
            lbl = node.label.upper()
            if "IFLOOP" not in lbl and "STARTLOOP" not in lbl:
                continue
            combined = " ".join(node.ir_stmts)
            if not _LENGTH_RE.search(combined):
                continue
            key = f"p2_unbounded_{node.node_id}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                vuln_type=VulnerabilityType.DOS,
                severity=Severity.MEDIUM,
                contract_name=contract.name,
                function_name=fn_info.name,
                start_line=node.source_line,
                title="DoS — Unbounded Loop Over State Array",
                description=(
                    f"`{fn_info.name}` in `{contract.name}` loops over a "
                    f"state-variable array using `.length` as the bound. "
                    f"An attacker can grow the array until the function "
                    f"exceeds the block gas limit and becomes permanently uncallable."
                ),
                recommendation=(
                    "Cap the iteration count with a max-per-call parameter, "
                    "use pagination with a stored cursor, or restructure to "
                    "avoid on-chain iteration over unbounded storage arrays."
                ),
                confidence=0.75,
                detector_id=self.DETECTOR_ID,
                detector_version=self.DETECTOR_VERSION,
            ))
        return findings

    # ------------------------------------------------------------------
    # Pattern 3 — unguarded send / transfer outside a loop
    # ------------------------------------------------------------------

    def _p3_unguarded_send(
        self,
        contract: ContractInfo,
        fn_info: FunctionInfo,
        cfg: CFGGraph,
        loop_body: Set[int],
        seen: Set[str],
    ) -> List[Finding]:
        """
        Primary path: fn_info.external_calls (structured ExternalCallInfo).
        Fallback: CFG IR optype / text scan for any node outside the loop body.
        """
        findings: List[Finding] = []

        # ---- Primary: structured ExternalCallInfo ----
        for ec in fn_info.external_calls:
            if ec.call_type not in (CallType.SEND, CallType.TRANSFER):
                continue
            if ec.is_return_checked:
                continue
            # Skip if the call line is inside a loop body (caught by Pattern 1)
            if self._line_in_loop(ec.start_line, cfg, loop_body):
                continue
            key = f"p3_struct_{ec.call_type.value}_{ec.start_line}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(self._make_send_finding(
                contract, fn_info,
                is_transfer=(ec.call_type == CallType.TRANSFER),
                line=ec.start_line,
                confidence=0.85,
            ))

        # ---- Fallback: CFG IR scan (catches calls not in ExternalCallInfo) ----
        if not findings:
            for node in cfg.nodes.values():
                if node.node_id in loop_body:
                    continue
                has_send = bool(set(node.ir_op_types) & _ETH_SEND_OPTYPES)
                if not has_send:
                    combined = " ".join(node.ir_stmts)
                    has_send = bool(_SEND_STMT_RE.search(combined))
                if not has_send:
                    continue
                key = f"p3_cfg_{node.node_id}"
                if key in seen:
                    continue
                seen.add(key)
                is_transfer = (
                    "Transfer" in node.ir_op_types
                    or ".transfer(" in " ".join(node.ir_stmts).lower()
                )
                findings.append(self._make_send_finding(
                    contract, fn_info,
                    is_transfer=is_transfer,
                    line=node.source_line,
                    confidence=0.60,
                ))
        return findings

    def _make_send_finding(
        self,
        contract: ContractInfo,
        fn_info: FunctionInfo,
        is_transfer: bool,
        line: Optional[int],
        confidence: float,
    ) -> Finding:
        if is_transfer:
            return Finding(
                vuln_type=VulnerabilityType.DOS,
                severity=Severity.MEDIUM,
                contract_name=contract.name,
                function_name=fn_info.name,
                start_line=line,
                title="DoS — Unexpected Revert via transfer()",
                description=(
                    f"`{fn_info.name}` uses `transfer()` which forwards only 2300 gas "
                    f"and reverts on failure. If the recipient is a contract that "
                    f"reverts in its fallback, this function is permanently locked."
                ),
                recommendation=(
                    "Replace `transfer()` with a low-level call and check the return:"
                    "  (bool ok,) = payable(addr).call{value: amt}(\'\');"
                    "  require(ok, \'Transfer failed\');"
                ),
                confidence=confidence,
                detector_id=self.DETECTOR_ID,
                detector_version=self.DETECTOR_VERSION,
            )
        return Finding(
            vuln_type=VulnerabilityType.DOS,
            severity=Severity.LOW,
            contract_name=contract.name,
            function_name=fn_info.name,
            start_line=line,
            title="DoS — Unchecked send() Return Value",
            description=(
                f"`{fn_info.name}` ignores the bool returned by `send()`. "
                f"Failed ETH transfers are silently swallowed, leaving "
                f"the contract in an inconsistent state."
            ),
            recommendation=(
                "Capture and assert the return value:"
                "  bool ok = payable(addr).send(amt);"
                "  require(ok, \'Send failed\');"
            ),
            confidence=confidence,
            detector_id=self.DETECTOR_ID,
            detector_version=self.DETECTOR_VERSION,
        )

    # ------------------------------------------------------------------
    # CFG helpers
    # ------------------------------------------------------------------

    def _collect_loop_body(self, cfg: CFGGraph) -> Set[int]:
        """
        BFS from every STARTLOOP node to collect all loop-body node IDs.
        Stops at ENDLOOP nodes — does not enter nested structure beyond the loop.
        """
        in_loop: Set[int] = set()
        for start_id, start_node in cfg.nodes.items():
            if "STARTLOOP" not in start_node.label.upper():
                continue
            visited: Set[int] = set()
            queue: List[int] = list(start_node.successors)
            while queue:
                nid = queue.pop()
                if nid in visited:
                    continue
                visited.add(nid)
                node = cfg.nodes.get(nid)
                if node is None:
                    continue
                if "ENDLOOP" in node.label.upper():
                    continue   # stop at loop end, don't recurse past it
                in_loop.add(nid)
                queue.extend(s for s in node.successors if s not in visited)
        return in_loop

    def _line_in_loop(
        self,
        line: Optional[int],
        cfg: CFGGraph,
        loop_body: Set[int],
    ) -> bool:
        if line is None:
            return False
        return any(
            cfg.nodes[nid].source_line == line
            for nid in loop_body
            if nid in cfg.nodes and cfg.nodes[nid].source_line is not None
        )

    def _describe_call(self, node) -> str:  # type: ignore[no-untyped-def]
        optypes = set(node.ir_op_types)
        if "LowLevelCall" in optypes:
            return "low-level .call()"
        if "Transfer" in optypes:
            return ".transfer()"
        if "Send" in optypes:
            return ".send()"
        if "HighLevelCall" in optypes:
            return "high-level external call"
        combined = " ".join(node.ir_stmts).lower()
        if ".transfer(" in combined:
            return ".transfer()"
        if ".send(" in combined:
            return ".send()"
        return "external call"

    # ------------------------------------------------------------------
    # BaseDetector abstract methods
    # ------------------------------------------------------------------

    def build_recommendation(self, context: dict) -> str:
        title = context.get("title", "")
        if "Loop Over External" in title:
            return (
                "Use the withdrawal pattern: store pending amounts in a mapping "
                "and let recipients pull their own ETH, removing the loop."
            )
        if "Unbounded Loop" in title:
            return (
                "Cap iterations per call or use off-chain computation with "
                "on-chain verification. Store a cursor for pagination."
            )
        if "transfer()" in title:
            return (
                "Replace `transfer()` with `call{value: amt}(\'\')` "
                "and check the bool return."
            )
        return "Handle send() return value: `bool ok = addr.send(amt); require(ok);`"

    def calculate_cvss(self, context: dict) -> float:
        title = context.get("title", "")
        if "Loop Over External" in title:
            return 7.5
        if "Unbounded Loop" in title:
            return 5.5
        if "transfer()" in title:
            return 5.0
        return 3.5
