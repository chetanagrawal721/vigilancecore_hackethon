"""
detectors/tod_detector.py

Transaction Order Dependency (TOD / front-running) vulnerability detector.
v1.0.0

Detection pattern
-----------------
A contract is vulnerable to TOD when:
  1. A public/external function F_SETTER writes an address-type state
     variable with a value derived from msg.sender (the "race slot").
  2. A DIFFERENT public/external function F_SENDER sends ETH by reading
     that same state variable as the transfer recipient.

An attacker who monitors the mempool can front-run a legitimate call to
F_SETTER, substitute their own address as the winner, and steal the ETH
that F_SENDER later distributes.

This detector cross-references all functions in the contract to find
matching (setter, sender) pairs. One finding is emitted from the ETH-
sending function per discovered race slot.
"""

from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional, Set, Tuple

from core.cfg_builder import CFGGraph, DFGGraph
from core.models import (
    ContractInfo,
    Finding,
    FindingMetadata,
    FunctionInfo,
    Severity,
    VulnerabilityType,
)
from core.enums import Visibility, StateMutability
from core.taint_engine import TaintResult
from detectors.base_detector import BaseDetector

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Patterns for raw-source analysis
# ---------------------------------------------------------------------------

# Matches state-variable assignments from msg.sender:
#   winner = msg.sender;
#   owner_TOD7 = msg.sender;
_SENDER_ASSIGN_RE = re.compile(
    r"\b([a-zA-Z_]\w*)\s*=\s*(?:payable\s*\()?\s*msg\.sender",
    re.IGNORECASE,
)

# Matches ETH transfers to a variable:
#   winner.transfer(...)
#   owner_TOD7.transfer(msg.value)
#   winner_TOD7.call{value:...}
_TRANSFER_TARGET_RE = re.compile(
    r"\b([a-zA-Z_]\w*)\s*\.(?:transfer|send)\s*\(",
    re.IGNORECASE,
)

# Protection patterns — if present, not a clean TOD
_COMMIT_REVEAL_RE = re.compile(
    r"\b(?:commit|reveal|hash|nonce|secret|blind)\b",
    re.IGNORECASE,
)
_MUTEX_RE = re.compile(
    r"\b(?:locked|mutex|nonReentrant|lock|guard)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Contract-level analysis helpers
# ---------------------------------------------------------------------------

def _public_or_external(fn: FunctionInfo) -> bool:
    v = fn.visibility
    return v in (Visibility.PUBLIC, Visibility.EXTERNAL)


def _fn_body_lines(fn: FunctionInfo, raw_source: str) -> str:
    """Extract source lines for fn from the full contract source."""
    if not raw_source or not fn.start_line or not fn.end_line:
        return ""
    lines = raw_source.splitlines()
    start = max(0, fn.start_line - 1)
    end = min(len(lines), fn.end_line)
    return "\n".join(lines[start:end])


def _vars_set_from_sender(fn: FunctionInfo, raw_source: str) -> Set[str]:
    """
    Return state variable names that fn assigns from msg.sender.
    Uses both FunctionInfo.state_vars_written names (fast) and raw-source
    regex (ensures we catch payable-cast forms like `payable(msg.sender)`).
    """
    body = _fn_body_lines(fn, raw_source)
    candidates: Set[str] = set()
    for m in _SENDER_ASSIGN_RE.finditer(body):
        candidates.add(m.group(1))
    # Cross-reference with known written state vars for precision
    written_names = {v.name for v in fn.state_vars_written}
    if written_names:
        return candidates & written_names  # confirmed written vars
    return candidates  # fallback if state_vars_written is empty


def _eth_transfer_targets(fn: FunctionInfo, raw_source: str) -> Set[str]:
    """
    Return names of variables used as recipients in .transfer()/.send() calls.
    Also checks ExternalCallInfo for value_transfer=True as a primary source.
    """
    targets: Set[str] = set()

    # Primary: structured ExternalCallInfo
    for ec in fn.external_calls:
        if ec.value_transfer:
            # callee looks like "winner_TOD7.transfer" — extract prefix
            m = re.match(r"([a-zA-Z_]\w*)\.", ec.callee or "")
            if m:
                targets.add(m.group(1))

    # Fallback: raw-source scan
    body = _fn_body_lines(fn, raw_source)
    for m in _TRANSFER_TARGET_RE.finditer(body):
        targets.add(m.group(1))

    return targets


def _has_protection(fn: FunctionInfo, raw_source: str) -> bool:
    """True if commit-reveal or mutex patterns are present in the function."""
    body = _fn_body_lines(fn, raw_source)
    return bool(_COMMIT_REVEAL_RE.search(body) or _MUTEX_RE.search(body))


def _find_tod_pairs(
    contract: ContractInfo,
) -> List[Tuple[FunctionInfo, FunctionInfo, str]]:
    """
    Return (sender_fn, setter_fn, var_name) triples where:
      sender_fn  — public fn that sends ETH to an address state var
      setter_fn  — public fn that sets that state var = msg.sender
      var_name   — the race-condition state variable name
    """
    raw = contract.raw_source or ""
    pairs: List[Tuple[FunctionInfo, FunctionInfo, str]] = []

    public_fns = [f for f in contract.functions if _public_or_external(f)]
    if len(public_fns) < 2:
        return pairs

    # Build a map: var_name → list of setter fns
    setter_map: Dict[str, List[FunctionInfo]] = {}
    for fn in public_fns:
        for var_name in _vars_set_from_sender(fn, raw):
            setter_map.setdefault(var_name, []).append(fn)

    if not setter_map:
        return pairs

    # Find ETH-sending fns that read a race-condition variable
    seen: Set[Tuple[str, str, str]] = set()
    for fn in public_fns:
        transfer_targets = _eth_transfer_targets(fn, raw)
        if not transfer_targets:
            continue
        for var_name, setters in setter_map.items():
            if var_name not in transfer_targets:
                continue
            for setter in setters:
                if setter.name == fn.name:
                    continue  # same function — not TOD
                key = (fn.name, setter.name, var_name)
                if key in seen:
                    continue
                seen.add(key)
                pairs.append((fn, setter, var_name))

    return pairs


# ---------------------------------------------------------------------------
# Public Detector
# ---------------------------------------------------------------------------

class TODDetector(BaseDetector):
    """
    Detects Transaction Order Dependency (TOD / front-running) where a
    public function sends ETH to an address state variable that a DIFFERENT
    public function sets from msg.sender — a classic mempool race condition.
    """

    DETECTOR_ID = "tod_v1"
    DETECTOR_VERSION = "1.0.0"
    VULN_TYPE = VulnerabilityType.FRONT_RUNNING
    DEFAULT_SEVERITY = Severity.HIGH

    # Emit one finding per (sender_fn, var) pair, not per-function call.
    # Cache at the contract level using contract_hash.
    _emitted: Dict[str, Set[Tuple[str, str]]] = {}

    def detect(
        self,
        contract: ContractInfo,
        fn_info: FunctionInfo,
        cfg: CFGGraph,
        dfg: DFGGraph,
        taint_result: Optional[TaintResult],
    ) -> List[Finding]:

        # Only run from the ETH-sending function side
        has_eth_send = any(
            ec.value_transfer for ec in fn_info.external_calls
        )
        # Also check raw source for .transfer() pattern
        if not has_eth_send:
            raw = contract.raw_source or ""
            body = _fn_body_lines(fn_info, raw)
            has_eth_send = bool(_TRANSFER_TARGET_RE.search(body))

        if not has_eth_send:
            return []

        # Per-contract dedup key
        chash = contract.contract_hash or contract.name
        emitted = self._emitted.setdefault(chash, set())

        pairs = _find_tod_pairs(contract)
        if not pairs:
            return []

        findings: List[Finding] = []
        for sender_fn, setter_fn, var_name in pairs:
            if sender_fn.name != fn_info.name:
                continue  # this call is not for the sender function

            dedup_key = (sender_fn.name, var_name)
            if dedup_key in emitted:
                continue
            emitted.add(dedup_key)

            protected = _has_protection(sender_fn, contract.raw_source or "")
            cvss = self.safe_cvss({
                "var_name": var_name,
                "sender_fn": sender_fn.name,
                "setter_fn": setter_fn.name,
                "has_protection": protected,
                "function_visibility": fn_info.visibility.value,
            })

            findings.append(Finding(
                vuln_type=VulnerabilityType.FRONT_RUNNING,
                severity=Severity.MEDIUM if protected else Severity.HIGH,
                contract_name=contract.name,
                function_name=fn_info.name,
                source_file=fn_info.source_file,
                start_line=fn_info.start_line,
                title=(
                    f"TOD: ETH sent to race-condition address '{var_name}' "
                    f"set by '{setter_fn.name}'"
                ),
                description=(
                    f"Function '{sender_fn.name}' sends ETH to the address stored "
                    f"in state variable '{var_name}'. That variable is set to "
                    f"'msg.sender' in the public function '{setter_fn.name}'. "
                    f"An attacker watching the mempool can front-run a legitimate "
                    f"call to '{setter_fn.name}', substitute their own address as "
                    f"'{var_name}', and receive ETH intended for the honest caller."
                ),
                recommendation=self.safe_recommendation({
                    "var_name": var_name,
                    "setter_fn": setter_fn.name,
                    "sender_fn": sender_fn.name,
                }),
                confidence=0.75 if protected else 0.90,
                cvss_score=cvss,
                detector_id=self.DETECTOR_ID,
                detector_version=self.DETECTOR_VERSION,
                metadata=FindingMetadata(
                    extra={
                        "race_variable": var_name,
                        "setter_function": setter_fn.name,
                        "sender_function": sender_fn.name,
                        "has_protection": protected,
                    }
                ),
            ))

            logger.debug(
                "TOD: '%s' — '%s' sends ETH to '%s' set by '%s'. CVSS=%.1f",
                contract.name, sender_fn.name, var_name, setter_fn.name, cvss,
            )

        return findings

    def build_recommendation(self, context: dict) -> str:
        var = context.get("var_name", "the state variable")
        setter = context.get("setter_fn", "the setter function")
        sender = context.get("sender_fn", "the sending function")
        return (
            f"The address '{var}' set by '{setter}' can be manipulated via "
            f"front-running before '{sender}' distributes ETH. "
            f"Mitigations: (1) Use a commit-reveal scheme so the winner is "
            f"committed in one TX and revealed only after a delay; "
            f"(2) Use a pull-payment pattern — credit balances instead of "
            f"pushing ETH (OpenZeppelin PullPayment); "
            f"(3) Accept a salt/nonce parameter and compare against a "
            f"pre-committed hash to make front-running computationally infeasible."
        )

    def calculate_cvss(self, context: dict) -> float:
        score = 5.5
        if not context.get("has_protection"):
            score += 2.0   # fully unprotected
        if context.get("function_visibility") == "external":
            score += 0.5
        return round(min(10.0, score), 1)
