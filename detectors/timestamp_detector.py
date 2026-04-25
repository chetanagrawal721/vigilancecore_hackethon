"""
detectors/timestamp_detector_v2.py

Timestamp dependence vulnerability detector for VigilanceCore.
v2.0.0 — Adds Slither-native primary path; fixes import block, regex
patterns, and all unclosed parenthesis bugs from v1.

Detection pipeline (8 steps)
-----------------------------
Step 0 Slither-native  — query Slither StateVariable / IR nodes directly
Step 1 Fast-path       — skip if block.timestamp never appears in IR
Step 2 Usage scan      — find every node where timestamp is read
Step 3 Context scan    — classify each usage (condition / state write /
                         arithmetic / return / randomness seed)
Step 4 Risk filter     — drop low-risk usages (pure logging, events)
Step 5 Taint enrich    — confirm timestamp flows into critical sinks
Step 6 Dedup           — one finding per (node, usage_kind) pair
Step 7 Build           — Finding with safe_recommendation + safe_cvss
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, FrozenSet, List, Optional, Set, Tuple

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
# Slither-native imports — optional; graceful fallback
# ---------------------------------------------------------------------------
try:
    from slither.slithir.operations import Assignment  # type: ignore
    from slither.slithir.variables import TemporaryVariable  # type: ignore
    _SLITHER_AVAILABLE = True
except ImportError:
    _SLITHER_AVAILABLE = False

# ---------------------------------------------------------------------------
# Module-level compiled patterns
# ---------------------------------------------------------------------------

# Matches any miner-influenceable global in an IR statement
_TIMESTAMP_RE = re.compile(
    r"\b(?:block\.timestamp|block\.number|block\.difficulty"
    r"|block\.prevrandao|block\.basefee|now)\b",
    re.IGNORECASE,
)

# Deadline/expiry keyword — lower-severity patterns
_DEADLINE_RE = re.compile(
    r"\b(?:deadline|expir(?:y|es|ed|ation)|expires?|lockUntil"
    r"|lockTime|lockEnd|end(?:Time|At|Date)?|until)\b",
    re.IGNORECASE,
)

# Randomness seed patterns — keccak / sha / abi.encode + modulo
_RANDOM_RE = re.compile(
    r"\b(?:keccak256|sha256|sha3|ripemd160|abi\.encode(?:Packed)?)\b"
    r"|\b(?:rand(?:om)?|lottery|seed|dice|flip|roll)\b",
    re.IGNORECASE,
)

# Condition check patterns — comparison operators and if/require context
_CONDITION_RE = re.compile(
    r"(?:[><!]=?|==)\s*\w"
    r"|\b(?:require|assert|if)\b",
    re.IGNORECASE,
)

# Assignment operator (not comparison) — left := right style
_ASSIGN_RE = re.compile(r"(?<![=!<>])=(?![=>])")

# Arithmetic expression involving a timestamp value
_ARITH_WITH_TS_RE = re.compile(
    r"\b(?:block\.timestamp|block\.number|block\.difficulty"
    r"|block\.prevrandao|block\.basefee|now)\b"
    r".*?[+\-*/%]|[+\-*/%].*?"
    r"\b(?:block\.timestamp|block\.number|block\.difficulty"
    r"|block\.prevrandao|block\.basefee|now)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Safe TaintSourceKind lookups — some members may not exist in all versions
# ---------------------------------------------------------------------------
_TS_SOURCE_BLOCK_TIMESTAMP = getattr(TaintSourceKind, "BLOCK_TIMESTAMP", None)
_TS_SOURCE_BLOCK_NUMBER    = getattr(TaintSourceKind, "BLOCK_NUMBER", None)
_TS_SOURCE_BLOCK_DIFF      = getattr(TaintSourceKind, "BLOCK_DIFFICULTY", None)
_TS_SOURCE_PREVRANDAO      = getattr(TaintSourceKind, "BLOCK_PREVRANDAO", None)

_TS_SOURCES: FrozenSet = frozenset(filter(None, [
    _TS_SOURCE_BLOCK_TIMESTAMP,
    _TS_SOURCE_BLOCK_NUMBER,
    _TS_SOURCE_BLOCK_DIFF,
    _TS_SOURCE_PREVRANDAO,
]))

# ---------------------------------------------------------------------------
# Usage classification enum
# ---------------------------------------------------------------------------

class _UsageKind(Enum):
    CONDITION   = "condition"    # if / require using timestamp → deadline
    STATE_WRITE = "state_write"  # lastUpdate = block.timestamp
    ARITHMETIC  = "arithmetic"   # block.timestamp + 1 days
    RANDOMNESS  = "randomness"   # keccak256(block.timestamp) % 10
    RETURN      = "return"       # return block.timestamp
    GENERAL     = "general"      # any other read


@dataclass
class _TimestampUsage:
    """One location where a miner-influenceable value is used."""
    cfg_node_id: int
    ir_index: int
    source_name: str       # e.g. "block.timestamp"
    usage_kind: _UsageKind
    stmt: str
    source_line: Optional[int]
    is_deadline: bool


@dataclass
class _TimestampFinding:
    """Enriched finding candidate."""
    usage: _TimestampUsage
    taint_confirms: bool = False
    taint_source: Optional[TaintSourceKind] = None


# ---------------------------------------------------------------------------
# Step 0 — Slither-native detection
# ---------------------------------------------------------------------------

def _slither_fn_from_info(fn_info: FunctionInfo) -> Optional[Any]:
    for attr in ("_slither_fn", "slither_function", "_fn", "raw"):
        obj = getattr(fn_info, attr, None)
        if obj is not None:
            return obj
    return None


def _source_line_from_node(node: Any) -> Optional[int]:
    sm = getattr(node, "source_mapping", None)
    if sm is None:
        return None
    lines = getattr(sm, "lines", None)
    if lines:
        return lines[0]
    return None


# Names of Slither IR variables / expressions that correspond to block globals
_SLITHER_TS_NAMES = frozenset({
    "block.timestamp", "block.number", "block.difficulty",
    "block.prevrandao", "block.basefee", "now",
})


def _is_ts_value(v: Any) -> bool:
    """Return True if a Slither IR variable is a block-global timestamp."""
    if v is None:
        return False
    name = getattr(v, "name", "") or ""
    return name.lower() in _SLITHER_TS_NAMES


def _detect_slither_native(fn_info: FunctionInfo) -> List[_TimestampUsage]:
    """
    Scan Slither IR nodes directly for block.timestamp / block.number
    references and classify their usage kind.
    Returns a list of _TimestampUsage; empty when Slither is unavailable.
    """
    if not _SLITHER_AVAILABLE:
        return []

    slither_fn = _slither_fn_from_info(fn_info)
    if slither_fn is None:
        return []

    usages: List[_TimestampUsage] = []
    seen: Set[Tuple[int, str, str]] = set()

    nodes = getattr(slither_fn, "nodes", [])
    for node in nodes:
        # Build a combined string for context classification
        ir_list = (
            getattr(node, "irs_ssa", None)
            or getattr(node, "irs", None)
            or []
        )
        combined = " ".join(str(ir) for ir in ir_list)
        if not _TIMESTAMP_RE.search(combined):
            continue

        for ir_idx, ir in enumerate(ir_list):
            stmt_str = str(ir)
            if not _TIMESTAMP_RE.search(stmt_str):
                continue

            source_name = _extract_source_from_str(stmt_str)
            usage_kind = _UsageFinder._classify(
                stmt_str, combined, getattr(node, "type", ""), ir_idx
            )
            is_deadline = bool(_DEADLINE_RE.search(stmt_str))

            key = (id(node), source_name, usage_kind.value)
            if key in seen:
                continue
            seen.add(key)

            usages.append(_TimestampUsage(
                cfg_node_id=id(node),
                ir_index=ir_idx,
                source_name=source_name,
                usage_kind=usage_kind,
                stmt=stmt_str[:120],
                source_line=_source_line_from_node(node),
                is_deadline=is_deadline,
            ))

    return usages


def _extract_source_from_str(stmt: str) -> str:
    for src in (
        "block.prevrandao", "block.difficulty", "block.basefee",
        "block.timestamp", "block.number", "now",
    ):
        if re.search(rf"\b{re.escape(src)}\b", stmt, re.IGNORECASE):
            return src
    return "block.timestamp"


# ---------------------------------------------------------------------------
# Step 1 — Fast-path predicate
# ---------------------------------------------------------------------------

def _has_timestamp(cfg: CFGGraph) -> bool:
    for node in cfg.nodes.values():
        combined = " ".join(node.ir_stmts)
        if _TIMESTAMP_RE.search(combined):
            return True
    return False


# ---------------------------------------------------------------------------
# Step 2 + 3 — Usage finder and classifier
# ---------------------------------------------------------------------------

class _UsageFinder:
    def find(self, cfg: CFGGraph) -> List[_TimestampUsage]:
        usages: List[_TimestampUsage] = []
        seen: Set[Tuple[int, str, str]] = set()

        for node in cfg.ordered_nodes():
            combined = " ".join(node.ir_stmts)
            if not _TIMESTAMP_RE.search(combined):
                continue

            for ir_idx, stmt in enumerate(node.ir_stmts):
                if not _TIMESTAMP_RE.search(stmt):
                    continue

                source_name = _extract_source_from_str(stmt)
                usage_kind = self._classify(stmt, combined, node.label or "", ir_idx)
                is_deadline = bool(_DEADLINE_RE.search(stmt))

                key = (node.node_id, source_name, usage_kind.value)
                if key in seen:
                    continue
                seen.add(key)

                usages.append(_TimestampUsage(
                    cfg_node_id=node.node_id,
                    ir_index=ir_idx,
                    source_name=source_name,
                    usage_kind=usage_kind,
                    stmt=stmt[:120],
                    source_line=node.source_line,
                    is_deadline=is_deadline,
                ))

        return usages

    @staticmethod
    def _classify(
        stmt: str,
        combined: str,
        label: str,
        ir_idx: int = 0,
    ) -> _UsageKind:
        # Randomness seed — highest risk (two-statement pattern also covered)
        if _RANDOM_RE.search(stmt):
            return _UsageKind.RANDOMNESS
        if _RANDOM_RE.search(combined) and _TIMESTAMP_RE.search(combined):
            return _UsageKind.RANDOMNESS

        # Condition — if / require using timestamp
        label_upper = label.upper()
        node_is_cond = ir_idx == 0 and ("IF" in label_upper or "REQUIRE" in label_upper)
        if _CONDITION_RE.search(stmt) or node_is_cond:
            return _UsageKind.CONDITION

        # State write — timestamp saved to storage
        if _ASSIGN_RE.search(stmt) and _TIMESTAMP_RE.search(stmt):
            parts = re.split(r"(?<![=!<>])=(?!=)", stmt, maxsplit=1)
            if len(parts) == 2 and _TIMESTAMP_RE.search(parts[1]):
                return _UsageKind.STATE_WRITE

        # Arithmetic — timestamp used in expression
        if _ARITH_WITH_TS_RE.search(stmt):
            return _UsageKind.ARITHMETIC

        # Return value
        if re.search(r"\breturn\b", stmt, re.IGNORECASE):
            return _UsageKind.RETURN

        return _UsageKind.GENERAL


# ---------------------------------------------------------------------------
# Step 4 — Risk filter
# ---------------------------------------------------------------------------

_CRITICAL_USAGES: FrozenSet[_UsageKind] = frozenset({
    _UsageKind.RANDOMNESS,
    _UsageKind.CONDITION,
    _UsageKind.STATE_WRITE,
    _UsageKind.ARITHMETIC,
})


def _is_risky(usage: _TimestampUsage) -> bool:
    if usage.usage_kind in _CRITICAL_USAGES:
        return True
    return not usage.is_deadline


# ---------------------------------------------------------------------------
# Step 5 — Taint enricher
# ---------------------------------------------------------------------------

class _TaintEnricher:
    def enrich(
        self,
        candidates: List[_TimestampFinding],
        taint_result: Optional[TaintResult],
    ) -> None:
        if not taint_result or not taint_result.flows or not _TS_SOURCES:
            return
        for candidate in candidates:
            for flow in taint_result.flows:
                if flow.source_kind not in _TS_SOURCES:
                    continue
                source_node = getattr(
                    flow, "source_node_id",
                    getattr(flow, "cfg_node_id", None),
                )
                if source_node != candidate.usage.cfg_node_id:
                    continue
                candidate.taint_confirms = True
                candidate.taint_source = flow.source_kind
                break


# ---------------------------------------------------------------------------
# Step 7 — Finding builder
# ---------------------------------------------------------------------------

class _FindingBuilder:
    def build(
        self,
        candidate: _TimestampFinding,
        contract_name: str,
        fn_info: FunctionInfo,
        detector_id: str,
        detector_version: str,
        recommendation: str,
        cvss_score: float,
    ) -> Finding:
        u = candidate.usage
        return Finding(
            vuln_type=VulnerabilityType.TIME_MANIPULATION,
            severity=self._severity(candidate),
            contract_name=contract_name,
            function_name=fn_info.name,
            source_file=fn_info.source_file,
            start_line=u.source_line,
            title=self._title(candidate),
            description=self._description(candidate, fn_info),
            recommendation=recommendation,
            confidence=self._confidence(candidate),
            cvss_score=cvss_score,
            detector_id=detector_id,
            detector_version=detector_version,
            metadata=FindingMetadata(
                randomness_source=u.source_name,
                extra={
                    "usage_kind": u.usage_kind.value,
                    "source_name": u.source_name,
                    "is_deadline": u.is_deadline,
                    "stmt": u.stmt,
                    "cfg_node_id": u.cfg_node_id,
                    "ir_index": u.ir_index,
                    "taint_confirms": candidate.taint_confirms,
                    "taint_source": (
                        candidate.taint_source.value
                        if candidate.taint_source else None
                    ),
                },
            ),
        )

    @staticmethod
    def _severity(c: _TimestampFinding) -> Severity:
        kind = c.usage.usage_kind
        source_name = c.usage.source_name

        if kind == _UsageKind.RANDOMNESS:
            return Severity.CRITICAL
        if kind == _UsageKind.CONDITION:
            if source_name == "block.number":
                return Severity.MEDIUM
            return Severity.HIGH if not c.usage.is_deadline else Severity.MEDIUM
        if kind == _UsageKind.STATE_WRITE:
            return Severity.MEDIUM
        if kind == _UsageKind.ARITHMETIC:
            if source_name == "block.number":
                return Severity.LOW
            return Severity.MEDIUM
        return Severity.LOW

    @staticmethod
    def _confidence(c: _TimestampFinding) -> float:
        score = 0.65
        if c.taint_confirms:
            score += 0.20
        if c.usage.usage_kind == _UsageKind.RANDOMNESS:
            score += 0.15
        elif c.usage.usage_kind == _UsageKind.CONDITION:
            score += 0.10
        return round(min(1.0, score), 4)

    @staticmethod
    def _title(c: _TimestampFinding) -> str:
        src = c.usage.source_name
        kind = c.usage.usage_kind.value.replace("_", " ")
        return f"Timestamp Dependence: '{src}' used in {kind}"

    @staticmethod
    def _description(c: _TimestampFinding, fn_info: FunctionInfo) -> str:
        u = c.usage
        loc = f" at line {u.source_line}" if u.source_line else ""

        kind_msgs = {
            _UsageKind.RANDOMNESS: (
                f"'{u.source_name}' is used as a randomness seed{loc}. "
                f"Miners know the block timestamp before publishing the block "
                f"and can choose a value that makes them win lotteries, NFT mints, "
                f"or any game of chance in this function."
            ),
            _UsageKind.CONDITION: (
                f"'{u.source_name}' is used in a condition{loc}. "
                f"Miners can shift the timestamp by up to ~15 seconds, "
                f"allowing them to bypass time-based locks, hit deadlines early, "
                f"or delay expiry checks to their advantage."
            ),
            _UsageKind.STATE_WRITE: (
                f"'{u.source_name}' is written to contract state{loc}. "
                f"If downstream logic relies on this stored value for "
                f"access control or reward calculations, miner manipulation "
                f"of the timestamp propagates to all dependent decisions."
            ),
            _UsageKind.ARITHMETIC: (
                f"'{u.source_name}' is used in arithmetic{loc}. "
                f"Any calculation involving a miner-controlled value "
                f"produces a miner-controlled result, which can affect "
                f"reward amounts, vesting schedules, or lock durations."
            ),
        }

        base = kind_msgs.get(
            u.usage_kind,
            f"Function '{fn_info.name}' reads '{u.source_name}'{loc}, "
            f"which miners can influence within a ~15-second window.",
        )

        if c.taint_confirms:
            base += (
                f" Taint analysis confirms '{u.source_name}' flows "
                f"from a miner-controlled source into this function's logic."
            )

        return base


# ---------------------------------------------------------------------------
# Public detector
# ---------------------------------------------------------------------------

class TimestampDetector(BaseDetector):
    """
    Detects dangerous reliance on miner-influenceable block globals:
    block.timestamp, block.number, block.difficulty, block.prevrandao, now.
    v2: Primary Slither-native path + CFG/regex fallback.
    """

    DETECTOR_ID = "timestamp_v1"
    DETECTOR_VERSION = "2.0.0"
    VULN_TYPE = VulnerabilityType.TIME_MANIPULATION
    DEFAULT_SEVERITY = Severity.MEDIUM

    def __init__(self) -> None:
        self._usage_finder = _UsageFinder()
        self._taint_enricher = _TaintEnricher()
        self._finding_builder = _FindingBuilder()

    def detect(
        self,
        contract: ContractInfo,
        fn_info: FunctionInfo,
        cfg: CFGGraph,
        dfg: DFGGraph,
        taint_result: Optional[TaintResult],
    ) -> List[Finding]:

        # ── Step 0: Slither-native path (primary) ──────────────────────
        native_usages = _detect_slither_native(fn_info)

        if native_usages:
            usages = native_usages
        else:
            # ── Step 1: Fast-path ───────────────────────────────────────
            if not _has_timestamp(cfg):
                logger.debug(
                    "Timestamp: '%s.%s' — no timestamp usage, skipped.",
                    contract.name, fn_info.name,
                )
                return []

            # ── Steps 2 + 3: Find and classify usages ──────────────────
            usages = self._usage_finder.find(cfg)
            if not usages:
                return []

        # ── Step 4: Risk filter ───────────────────────────────────────
        risky = [u for u in usages if _is_risky(u)]
        if not risky:
            logger.debug(
                "Timestamp: '%s.%s' — all usages are low-risk (deadline getters).",
                contract.name, fn_info.name,
            )
            return []

        # ── Step 5: Taint enrichment ──────────────────────────────────
        candidates = [_TimestampFinding(usage=u) for u in risky]
        self._taint_enricher.enrich(candidates, taint_result)

        # ── Step 6: Deduplication ─────────────────────────────────────
        seen: Set[Tuple[int, str]] = set()
        deduplicated: List[_TimestampFinding] = []
        for c in candidates:
            key = (c.usage.cfg_node_id, c.usage.usage_kind.value)
            if key not in seen:
                seen.add(key)
                deduplicated.append(c)

        # ── Step 7: Build findings ────────────────────────────────────
        findings: List[Finding] = []
        for c in deduplicated:
            context = self._build_context(c, fn_info, contract)
            finding = self._finding_builder.build(
                candidate=c,
                contract_name=contract.name,
                fn_info=fn_info,
                detector_id=self.DETECTOR_ID,
                detector_version=self.DETECTOR_VERSION,
                recommendation=self.safe_recommendation(context),
                cvss_score=self.safe_cvss(context),
            )
            findings.append(finding)
            logger.debug(
                "Timestamp: '%s.%s' — %s severity, source='%s', "
                "kind=%s, taint=%s, cvss=%.1f.",
                contract.name, fn_info.name,
                finding.severity.value, c.usage.source_name,
                c.usage.usage_kind.value, c.taint_confirms,
                finding.cvss_score,
            )

        return findings

    def build_recommendation(self, context: dict) -> str:
        fn_name = context["function_name"]
        source = context.get("source_name", "block.timestamp")
        usage_kind = context.get("usage_kind", "general")
        is_payable = context.get("is_payable", False)
        line = context.get("line_number")
        loc = f" at line {line}" if line else ""

        recs = {
            "randomness": (
                f"In function '{fn_name}'{loc}: do NOT use '{source}' "
                f"as a randomness source. Miners control this value. "
                f"Use Chainlink VRF for provably fair randomness, or a "
                f"commit-reveal scheme where users commit a hash of their "
                f"secret before the reveal phase."
            ),
            "condition": (
                f"In function '{fn_name}'{loc}: '{source}' is used in a "
                f"condition that miners can influence by ~15 seconds. "
                f"For deadlines longer than 15 minutes this is usually acceptable."
                + (
                    " For shorter windows, use block.number instead "
                    "(miners cannot freely manipulate block numbers)."
                    if source != "block.number" else
                    " Since block.number itself is the source, consider "
                    "using a commit-reveal scheme or Chainlink VRF for "
                    "stronger manipulation resistance."
                )
            ),
            "state_write": (
                f"In function '{fn_name}'{loc}: '{source}' is stored in "
                f"contract state. Ensure downstream logic that reads this "
                f"stored value is not security-critical, or document the "
                f"accepted manipulation window explicitly."
            ),
            "arithmetic": (
                f"In function '{fn_name}'{loc}: '{source}' is used in "
                f"arithmetic. Verify the calculation result is not "
                f"exploitable within a ~15-second miner manipulation window. "
                f"For vesting/unlock schedules, prefer block.number for "
                f"shorter precision windows."
            ),
        }

        rec = recs.get(
            usage_kind,
            f"In function '{fn_name}'{loc}: avoid relying on '{source}' "
            f"for security-critical decisions — miners can influence it.",
        )

        if is_payable:
            rec += (
                f" '{fn_name}' is payable — a miner who also sends ETH "
                f"has compounded incentive to manipulate the timestamp."
            )

        return rec

    def calculate_cvss(self, context: dict) -> float:
        """
        Base: 5.5
        +3.0 randomness   +2.0 condition   +1.0 state_write
        +0.5 arithmetic   +0.5 taint       +0.5 payable   -1.0 deadline
        """
        score = 5.5
        deltas = {
            "randomness": 3.0,
            "condition":  2.0,
            "state_write": 1.0,
            "arithmetic":  0.5,
        }
        score += deltas.get(context.get("usage_kind", "general"), 0.0)
        if context.get("taint_confirms"):
            score += 0.5
        if context.get("is_payable"):
            score += 0.5
        if context.get("is_deadline"):
            score -= 1.0
        return round(max(0.0, min(10.0, score)), 1)

    @staticmethod
    def _build_context(
        c: _TimestampFinding,
        fn_info: FunctionInfo,
        contract: ContractInfo,
    ) -> dict:
        return {
            "contract_name": contract.name,
            "function_name": fn_info.name,
            "function_visibility": getattr(
                fn_info.visibility, "value", fn_info.visibility
            ),
            "is_payable": (
                getattr(fn_info.state_mutability, "value",
                        fn_info.state_mutability) == "payable"
            ),
            "line_number": c.usage.source_line,
            "cfg_node": c.usage.cfg_node_id,
            "source_name": c.usage.source_name,
            "usage_kind": c.usage.usage_kind.value,
            "is_deadline": c.usage.is_deadline,
            "stmt": c.usage.stmt,
            "taint_confirms": c.taint_confirms,
            "taint_source": (
                c.taint_source.value if c.taint_source else None
            ),
        }
