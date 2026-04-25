"""
detectors/integer_overflow.py

Integer Overflow / Underflow detector for VigilanceCore.
v2.0.0 — Rewritten to conform to BaseDetector API.

Supplementary arithmetic detector focused on:
  - Explicit integer types (uint8 / int8 through uint256 / int256)
  - Solidity < 0.8.0 contracts (no built-in overflow protection)
  - Unchecked{} blocks in Solidity >= 0.8.0
  - Exponentiation (**)  which has the highest overflow risk

Complements arithmetic_detector.py (which uses CFG ir_op_types).
This detector uses raw-source pattern matching on fn_info + contract.raw_source.
"""
from __future__ import annotations

import logging
import re
from typing import List, Optional

from core.cfg_builder import CFGGraph, DFGGraph
from core.models import (
    ContractInfo,
    Finding,
    FindingMetadata,
    FunctionInfo,
    Severity,
    VulnerabilityType,
)
from core.taint_engine import TaintResult
from detectors.base_detector import BaseDetector

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

_PRE_08_PRAGMA_RE = re.compile(
    r"pragma\s+solidity\s+[^;]*?0\s*\.\s*[0-7]\b"
)
_UNCHECKED_BLOCK_RE  = re.compile(r"\bunchecked\s*\{", re.IGNORECASE)
_EXPONENT_RE         = re.compile(r"\*\*")
_OVERFLOW_OP_RE      = re.compile(r"(?<![=<>!])([+\-*])(?!=)")
_SMALL_INT_RE        = re.compile(
    r"\b(?:u?int(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128))\b"
)
_SAFEMATH_USING_RE   = re.compile(r"\busing\s+SafeMath\b", re.IGNORECASE)
_SAFEMATH_CALL_RE    = re.compile(
    r"\.(?:add|sub|mul|div|mod)\s*\(", re.IGNORECASE
)


# ---------------------------------------------------------------------------
# IntegerOverflowDetector
# ---------------------------------------------------------------------------

class IntegerOverflowDetector(BaseDetector):
    """
    Detects integer overflow/underflow using source-level pattern analysis.

    Emits findings only when:
      - Contract is pre-0.8.0 AND SafeMath is not used, OR
      - Code is inside an unchecked{} block, OR
      - Exponentiation (**) is used with small integer types.
    """

    DETECTOR_ID      = "integer_overflow_v1"
    DETECTOR_VERSION = "2.0.0"
    VULN_TYPE        = VulnerabilityType.ARITHMETIC
    DEFAULT_SEVERITY = Severity.HIGH
    NEEDS_STATELESS_ANALYSIS = True

    def detect(
        self,
        contract:     ContractInfo,
        fn_info:      FunctionInfo,
        cfg:          CFGGraph,
        dfg:          DFGGraph,
        taint_result: Optional[TaintResult],
    ) -> List[Finding]:
        is_pre_08   = self._is_pre_08(contract)
        fn_body     = self._fn_body(fn_info, contract)
        if not fn_body:
            return []

        has_safemath = bool(
            _SAFEMATH_USING_RE.search(contract.raw_source or "")
            and _SAFEMATH_CALL_RE.search(fn_body)
        )

        findings: List[Finding] = []
        findings.extend(self._check_pre08_ops(contract, fn_info, fn_body, is_pre_08, has_safemath))
        findings.extend(self._check_unchecked_ops(contract, fn_info, fn_body))
        findings.extend(self._check_small_int_exponent(contract, fn_info, fn_body, is_pre_08))
        return findings

    # ── pre-0.8.0 arithmetic ──────────────────────────────────────────────

    def _check_pre08_ops(
        self,
        contract:     ContractInfo,
        fn_info:      FunctionInfo,
        fn_body:      str,
        is_pre_08:    bool,
        has_safemath: bool,
    ) -> List[Finding]:
        if not is_pre_08 or has_safemath:
            return []

        body_nc = re.sub(r"//[^\n]*", "", fn_body)
        ops = _OVERFLOW_OP_RE.findall(body_nc)
        unique_ops = set(ops) - {"/", "%"}
        if not unique_ops:
            return []

        ctx = self._ctx(contract, fn_info, fn_info.start_line)
        ctx.update({"pattern": "pre08_arithmetic", "operators": sorted(unique_ops),
                    "is_pre_08": True})
        return [Finding(
            vuln_type        = VulnerabilityType.ARITHMETIC,
            severity         = Severity.HIGH,
            contract_name    = contract.name,
            function_name    = fn_info.name,
            source_file      = fn_info.source_file,
            start_line       = fn_info.start_line,
            title            = (
                f"Integer overflow risk in \'{fn_info.name}\' "
                f"(Solidity < 0.8.0, no SafeMath)"
            ),
            description      = (
                f"Function \'{fn_info.name}\' in \'{contract.name}\' uses "
                f"arithmetic operator(s) {sorted(unique_ops)} in a Solidity < 0.8.0 "
                f"contract without SafeMath protection. These operations can silently "
                f"wrap around, corrupting balances or counters."
            ),
            recommendation   = self.safe_recommendation(ctx),
            confidence       = 0.75,
            cvss_score       = self.safe_cvss(ctx),
            detector_id      = self.DETECTOR_ID,
            detector_version = self.DETECTOR_VERSION,
            metadata         = FindingMetadata(extra=ctx),
        )]

    # ── unchecked block arithmetic ────────────────────────────────────────

    def _check_unchecked_ops(
        self,
        contract: ContractInfo,
        fn_info:  FunctionInfo,
        fn_body:  str,
    ) -> List[Finding]:
        if not _UNCHECKED_BLOCK_RE.search(fn_body):
            return []

        body_nc = re.sub(r"//[^\n]*", "", fn_body)
        ops = _OVERFLOW_OP_RE.findall(body_nc)
        unique_ops = set(ops) - {"/", "%"}
        if not unique_ops:
            return []

        ctx = self._ctx(contract, fn_info, fn_info.start_line)
        ctx.update({"pattern": "unchecked_block", "operators": sorted(unique_ops)})
        return [Finding(
            vuln_type        = VulnerabilityType.ARITHMETIC,
            severity         = Severity.MEDIUM,
            contract_name    = contract.name,
            function_name    = fn_info.name,
            source_file      = fn_info.source_file,
            start_line       = fn_info.start_line,
            title            = (
                f"Arithmetic in unchecked block in \'{fn_info.name}\'"
            ),
            description      = (
                f"Function \'{fn_info.name}\' contains arithmetic inside an "
                f"unchecked{{}} block, which disables Solidity 0.8.0\' built-in "
                f"overflow/underflow protection. Operator(s): {sorted(unique_ops)}."
            ),
            recommendation   = self.safe_recommendation(ctx),
            confidence       = 0.70,
            cvss_score       = self.safe_cvss(ctx),
            detector_id      = self.DETECTOR_ID,
            detector_version = self.DETECTOR_VERSION,
            metadata         = FindingMetadata(extra=ctx),
        )]

    # ── small integer exponentiation ──────────────────────────────────────

    def _check_small_int_exponent(
        self,
        contract:  ContractInfo,
        fn_info:   FunctionInfo,
        fn_body:   str,
        is_pre_08: bool,
    ) -> List[Finding]:
        if not _EXPONENT_RE.search(fn_body):
            return []
        if not _SMALL_INT_RE.search(fn_body):
            return []

        ctx = self._ctx(contract, fn_info, fn_info.start_line)
        ctx.update({"pattern": "small_int_exponent", "is_pre_08": is_pre_08})
        return [Finding(
            vuln_type        = VulnerabilityType.ARITHMETIC,
            severity         = Severity.HIGH if is_pre_08 else Severity.MEDIUM,
            contract_name    = contract.name,
            function_name    = fn_info.name,
            source_file      = fn_info.source_file,
            start_line       = fn_info.start_line,
            title            = (
                f"Exponentiation (**) on small integer type in \'{fn_info.name}\'"
            ),
            description      = (
                f"Function \'{fn_info.name}\' uses the ** operator with a small "
                f"integer type (uint8-uint128). Exponentiation grows rapidly and "
                f"will overflow the integer bounds. Use uint256 for bases/exponents "
                f"and validate bounds before computing."
            ),
            recommendation   = self.safe_recommendation(ctx),
            confidence       = 0.72,
            cvss_score       = self.safe_cvss(ctx),
            detector_id      = self.DETECTOR_ID,
            detector_version = self.DETECTOR_VERSION,
            metadata         = FindingMetadata(extra=ctx),
        )]

    # ── BaseDetector required methods ─────────────────────────────────────

    def build_recommendation(self, context: dict) -> str:
        fn  = context.get("function_name", "unknown")
        pat = context.get("pattern", "")
        if pat == "pre08_arithmetic":
            return (
                f"In function \'{fn}\': upgrade to Solidity ^0.8.0 for built-in "
                f"overflow protection, or apply OpenZeppelin SafeMath: "
                f"`using SafeMath for uint256` and replace +/-/* with .add()/.sub()/.mul()."
            )
        if pat == "unchecked_block":
            return (
                f"In function \'{fn}\': remove the `unchecked{{}}` wrapper unless "
                f"overflow is intentional and values are mathematically bounded by "
                f"prior checks. If unchecked is needed for gas, add explicit bounds assertions."
            )
        if pat == "small_int_exponent":
            return (
                f"In function \'{fn}\': use uint256 for base and exponent in ** operations. "
                f"Add an upper-bound check before computing (e.g. require(exp <= 77) for uint256). "
                f"Consider using OpenZeppelin Math.pow() for safe exponentiation."
            )
        return (
            f"Review function \'{fn}\' for integer overflow/underflow risks. "
            f"Use Solidity ^0.8.0, SafeMath, or unchecked guards with explicit bounds."
        )

    def calculate_cvss(self, context: dict) -> float:
        pat      = context.get("pattern", "")
        is_pre08 = context.get("is_pre_08", False)
        base = 6.5
        if is_pre08:
            base += 1.5
        if pat == "small_int_exponent":
            base += 0.5
        vis = context.get("function_visibility", "")
        if vis in ("external", "public"):
            base += 0.3
        return round(min(10.0, max(0.0, base)), 1)

    @staticmethod
    def _is_pre_08(contract: ContractInfo) -> bool:
        ver = contract.solidity_version or ""
        if ver:
            nums = re.findall(r"0\.(\d+)", ver)
            if nums:
                return int(nums[0]) < 8
        raw = contract.raw_source or ""
        return bool(_PRE_08_PRAGMA_RE.search(raw))

    @staticmethod
    def _fn_body(fn_info: FunctionInfo, contract: ContractInfo) -> str:
        raw = contract.raw_source or ""
        if not raw:
            return ""
        start = fn_info.start_line
        end   = fn_info.end_line
        if not start or not end:
            return ""
        return chr(10).join(raw.splitlines()[max(0, start - 1) : min(len(raw.splitlines()), end)])

    @staticmethod
    def _ctx(contract: ContractInfo, fn_info: FunctionInfo, line: Optional[int]) -> dict:
        return {
            "contract_name":       contract.name,
            "function_name":       fn_info.name,
            "function_visibility": getattr(fn_info.visibility, "value", fn_info.visibility),
            "line_number":         line,
        }
