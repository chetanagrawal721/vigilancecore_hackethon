"""
detectors/randomness_detector.py

Bad / Insecure Randomness vulnerability detector for VigilanceCore.

What it detects
---------------
On-chain pseudo-random number generation that relies entirely on
block-level globals or other miner/validator-controlled values.
Any value derived from these sources is either predictable by an
ordinary user (who can read it before sending a transaction) or
manipulable by a miner/validator who mines the block.

Why this matters
----------------
Ethereum has no trusted on-chain entropy source. Every value that
is deterministically computable from the chain state — block.timestamp,
blockhash, block.difficulty / block.prevrandao, block.coinbase,
block.gaslimit, block.number — is visible to everyone BEFORE a
transaction lands. An attacker can simulate the exact same computation
off-chain, find the outcome, and only submit their transaction when the
outcome is in their favour.

Common real-world patterns this detector catches:
  ① uint r = uint(blockhash(block.number - 1)) % 100
  ② uint r = uint(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % N
  ③ uint r = uint(block.difficulty) % players.length
  ④ if (block.timestamp % 2 == 0) { winner = msg.sender; }

Difference from Timestamp Detector (Detector 4)
-------------------------------------------------
TimestampDetector focuses on TIME-based logic — deadlines, locks,
vesting schedules, and elapsed-time calculations. A timestamp used
in a condition like `require(block.timestamp >= endTime)` is squarely
in detector 4's territory.

THIS detector focuses on RANDOMNESS GENERATION — any pattern that
tries to produce a pseudorandom number using predictable on-chain data.
The two detectors complement each other with no overlap by design:
  - timestamp in condition / state write / arithmetic → detector 4
  - timestamp / blockhash / coinbase / gaslimit in hash or modulo
    for random selection                             → detector 5

Detection pipeline (7 steps)
-----------------------------
  Step 1  Fast-path    — skip if none of the weak entropy sources appear
  Step 2  Seed scan    — find all weak entropy reads in the function
  Step 3  RNG pattern  — detect the three dangerous PRNG patterns:
                         (a) direct modulo on block value
                         (b) hash-and-modulo (keccak/sha256 of block data)
                         (c) blockhash-based selection
  Step 4  Sink check   — confirm the random value flows into a decision
                         (winner selection, NFT id, prize amount …)
  Step 5  Taint enrich — use taint result to confirm source → sink flow
  Step 6  Dedup        — one finding per (node, pattern) pair
  Step 7  Build        — Finding with safe_recommendation + safe_cvss

Change log
----------
  v1.0.0  Initial release — covers blockhash, block.difficulty,
          block.prevrandao, block.coinbase, block.gaslimit,
          block.timestamp (hash-and-modulo only — direct timestamp
          use is left to TimestampDetector), and keccak/sha256
          hash-and-modulo patterns. CVSS scoring and taint enrichment.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from enum import Enum
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

# All weak on-chain entropy sources this detector targets
_WEAK_SOURCES: FrozenSet[str] = frozenset({
    "blockhash",
    "block.difficulty",
    "block.prevrandao",     # EIP-4399 — still miner/validator-influenced
    "block.coinbase",
    "block.gaslimit",
    "block.basefee",
    "block.timestamp",      # only flagged here when used in a hash-and-modulo
    "block.number",         # only flagged here when used in a hash-and-modulo
})
_BLOCKHASH_ENTROPY_RE = re.compile(
    r"blockhash\s*\("           # blockhash(block.number - 1)
    r"|block\s*\.\s*blockhash"  # block.blockhash(...)
    r"|block\s*\.\s*number\s*[%\-\+\*]"   # block.number arithmetic
    r"|block\s*\.\s*timestamp\s*[%]"       # timestamp modulo = randomness
    r"|keccak256\s*\([^)]*block\."         # keccak256(block.*)
    r"|uint\s*\(\s*block\s*\.\s*blockhash" # uint(block.blockhash)
    r"|sha3\s*\([^)]*block\.",             # sha3(block.*) — pre-0.5.0
    re.IGNORECASE
)
# Regex — any weak entropy source present in a statement
_WEAK_SOURCE_RE = re.compile(
    r"\b(?:blockhash|block\.difficulty|block\.prevrandao"
    r"|block\.coinbase|block\.gaslimit|block\.basefee"
    r"|block\.timestamp|block\.number)\b",
    re.IGNORECASE,
)

# Pattern A — direct modulo on a block value
# e.g.  block.difficulty % N  |  uint(block.timestamp) % players.length
_DIRECT_MOD_RE = re.compile(
    r"(?:blockhash|block\.difficulty|block\.prevrandao"
    r"|block\.coinbase|block\.gaslimit|block\.basefee"
    r"|block\.timestamp|block\.number)"
    r"[^;]{0,60}%\s*\w+",
    re.IGNORECASE,
)

# Pattern B — hash-and-modulo (keccak256 / sha256 of block data)
# e.g.  keccak256(abi.encodePacked(block.timestamp, msg.sender)) % N
_HASH_MOD_RE = re.compile(
    r"(?:keccak256|sha256|sha3)\s*\([^)]*"
    r"(?:blockhash|block\.difficulty|block\.prevrandao"
    r"|block\.coinbase|block\.gaslimit|block\.basefee"
    r"|block\.timestamp|block\.number)[^)]*\)"
    r"[^;]{0,80}%\s*\w+",
    re.IGNORECASE,
)

# Pattern C — blockhash used without modulo (still predictable)
# e.g.  uint(blockhash(block.number - 1))
_BLOCKHASH_RE = re.compile(
    r"\bblockhash\s*\(\s*(?:block\.number|block\.number\s*-\s*\d+)\s*\)",
    re.IGNORECASE,
)

# Pattern D — hash of block data without modulo (seed extraction)
# e.g.  keccak256(abi.encodePacked(block.timestamp))
_HASH_ONLY_RE = re.compile(
    r"(?:keccak256|sha256|sha3)\s*\([^)]*"
    r"(?:blockhash|block\.difficulty|block\.prevrandao"
    r"|block\.coinbase|block\.gaslimit|block\.basefee"
    r"|block\.timestamp|block\.number)[^)]*\)",
    re.IGNORECASE,
)

# Sink patterns — the random value is used for a consequential decision
_WINNER_RE = re.compile(
    r"\b(?:winner|selected|chosen|lucky|prize|reward|jackpot"
    r"|tokenId|nftId|mintId|recipient|beneficiary)\b",
    re.IGNORECASE,
)
_SELECTION_MOD_RE = re.compile(
    r"%\s*(?:\w+\.length|\d+)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Internal enums and data classes
# ---------------------------------------------------------------------------

class _RNGPattern(str, Enum):
    DIRECT_MOD   = "direct_modulo"       # block.X % N
    HASH_MOD     = "hash_and_modulo"     # keccak(block.X) % N
    BLOCKHASH    = "blockhash_cast"      # uint(blockhash(...))
    HASH_SEED    = "hash_seed"           # keccak(block.X) used as seed
    WEAK_READ    = "weak_entropy_read"   # bare read of block.X


@dataclass
class _WeakRNG:
    """One insecure RNG pattern found in a CFG node."""
    cfg_node_id: int
    ir_index:    int
    pattern:     _RNGPattern
    sources:     List[str]        # weak sources used (e.g. ["block.timestamp"])
    stmt:        str
    source_line: Optional[int]
    has_sink:    bool             # flows into winner/selection decision


@dataclass
class _RNGFinding:
    """Enriched finding candidate."""
    rng:            _WeakRNG
    taint_confirms: bool                      = False
    taint_source:   Optional[TaintSourceKind] = None


# ---------------------------------------------------------------------------
# Step 1 — Fast-path predicate
# ---------------------------------------------------------------------------

def _has_weak_source(cfg: CFGGraph) -> bool:
    """Quick check: any weak entropy source referenced anywhere?"""
    for node in cfg.nodes.values():
        combined = " ".join(node.ir_stmts)
        if _WEAK_SOURCE_RE.search(combined):
            return True
    return False


# ---------------------------------------------------------------------------
# Steps 2 + 3 — RNG finder
# ---------------------------------------------------------------------------

class _RNGFinder:
    """
    Scans every CFG node, detects weak entropy reads,
    and classifies each into a _RNGPattern.
    """

    def find(self, cfg: CFGGraph) -> List[_WeakRNG]:
        found: List[_WeakRNG]             = []
        seen:  Set[Tuple[int, str]]       = set()

        for node in cfg.ordered_nodes():
            combined = " ".join(node.ir_stmts)
            if not _WEAK_SOURCE_RE.search(combined):
                continue

            for ir_idx, stmt in enumerate(node.ir_stmts):
                if not _WEAK_SOURCE_RE.search(stmt):
                    continue

                pattern = self._classify(stmt, combined)
                sources = self._extract_sources(stmt)
                has_sink = bool(
                    _WINNER_RE.search(combined)
                    or _SELECTION_MOD_RE.search(stmt)
                )

                key = (node.node_id, pattern.value)
                if key in seen:
                    continue
                seen.add(key)

                found.append(_WeakRNG(
                    cfg_node_id = node.node_id,
                    ir_index    = ir_idx,
                    pattern     = pattern,
                    sources     = sources,
                    stmt        = stmt[:120],
                    source_line = node.source_line,
                    has_sink    = has_sink,
                ))

        return found

    @staticmethod
    def _classify(stmt: str, combined: str) -> _RNGPattern:
        """Classify from most to least dangerous pattern."""
        if _HASH_MOD_RE.search(stmt) or _HASH_MOD_RE.search(combined):
            return _RNGPattern.HASH_MOD
        if _DIRECT_MOD_RE.search(stmt):
            return _RNGPattern.DIRECT_MOD
        if _BLOCKHASH_RE.search(stmt):
            return _RNGPattern.BLOCKHASH
        if _HASH_ONLY_RE.search(stmt):
            return _RNGPattern.HASH_SEED
        return _RNGPattern.WEAK_READ

    @staticmethod
    def _extract_sources(stmt: str) -> List[str]:
        """Return all weak entropy sources found in a statement."""
        candidates = [
            "blockhash", "block.prevrandao", "block.difficulty",
            "block.coinbase", "block.gaslimit", "block.basefee",
            "block.timestamp", "block.number",
        ]
        return [
            s for s in candidates
            if re.search(rf"\b{re.escape(s)}\b", stmt, re.IGNORECASE)
        ]


# ---------------------------------------------------------------------------
# Step 4 — Risk filter
# ---------------------------------------------------------------------------

# Patterns that are always high-risk regardless of sink
_ALWAYS_REPORT: FrozenSet[_RNGPattern] = frozenset({
    _RNGPattern.HASH_MOD,
    _RNGPattern.DIRECT_MOD,
    _RNGPattern.BLOCKHASH,
})

def _is_risky(rng: _WeakRNG) -> bool:
    """
    Filter rule:
      - HASH_MOD, DIRECT_MOD, BLOCKHASH → always report (clearly RNG)
      - HASH_SEED → report only if a sink (winner/selection) is found
      - WEAK_READ → report only if a sink is found nearby
    """
    if rng.pattern in _ALWAYS_REPORT:
        return True
    return rng.has_sink


# ---------------------------------------------------------------------------
# Step 5 — Taint enricher
# ---------------------------------------------------------------------------

class _TaintEnricher:
    """
    Confirms taint engine independently tracked a weak entropy source
    flowing into this function's logic.
    """

    _WEAK_TAINT_SOURCES: FrozenSet[TaintSourceKind] = frozenset({
        TaintSourceKind.BLOCK_TIMESTAMP,
        TaintSourceKind.BLOCK_NUMBER,
    })

    def enrich(
        self,
        candidates:   List[_RNGFinding],
        taint_result: Optional[TaintResult],
    ) -> None:
        if not taint_result or not taint_result.flows:
            return
        for candidate in candidates:
            for flow in taint_result.flows:
                if flow.source_kind not in self._WEAK_TAINT_SOURCES:
                    continue
                if flow.cfg_node_id != candidate.rng.cfg_node_id:
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
        candidate:        _RNGFinding,
        contract_name:    str,
        fn_info:          FunctionInfo,
        detector_id:      str,
        detector_version: str,
        recommendation:   str,
        cvss_score:       float,
    ) -> Finding:
        rng = candidate.rng
        return Finding(
            vuln_type        = VulnerabilityType.BAD_RANDOMNESS,
            severity         = self._severity(candidate),
            contract_name    = contract_name,
            function_name    = fn_info.name,
            source_file      = fn_info.source_file,
            start_line       = rng.source_line,
            title            = self._title(candidate),
            description      = self._description(candidate, fn_info),
            recommendation   = recommendation,
            confidence       = self._confidence(candidate),
            cvss_score       = cvss_score,
            detector_id      = detector_id,
            detector_version = detector_version,
            metadata         = FindingMetadata(
                randomness_source = ", ".join(rng.sources) if rng.sources else None,
                extra             = {
                    "pattern":       rng.pattern.value,
                    "sources":       rng.sources,
                    "has_sink":      rng.has_sink,
                    "stmt":          rng.stmt,
                    "cfg_node_id":   rng.cfg_node_id,
                    "ir_index":      rng.ir_index,
                    "taint_confirms": candidate.taint_confirms,
                    "taint_source":  (
                        candidate.taint_source.value
                        if candidate.taint_source else None
                    ),
                },
            ),
        )

    @staticmethod
    def _severity(c: _RNGFinding) -> Severity:
        """
        Severity table:
          CRITICAL  — hash-and-modulo or direct-modulo with confirmed sink
          HIGH      — hash-and-modulo / direct-modulo / blockhash cast
          MEDIUM    — hash seed (no modulo, but still predictable)
          LOW       — bare weak entropy read with uncertain sink
        """
        pattern = c.rng.pattern
        if pattern in (
            _RNGPattern.HASH_MOD, _RNGPattern.DIRECT_MOD
        ) and c.rng.has_sink:
            return Severity.CRITICAL
        if pattern in (
            _RNGPattern.HASH_MOD, _RNGPattern.DIRECT_MOD, _RNGPattern.BLOCKHASH
        ):
            return Severity.HIGH
        if pattern == _RNGPattern.HASH_SEED:
            return Severity.MEDIUM
        return Severity.LOW

    @staticmethod
    def _confidence(c: _RNGFinding) -> float:
        score = 0.60
        if c.rng.pattern in (
            _RNGPattern.HASH_MOD, _RNGPattern.DIRECT_MOD
        ):
            score += 0.25
        elif c.rng.pattern == _RNGPattern.BLOCKHASH:
            score += 0.15
        if c.rng.has_sink:
            score += 0.10
        if c.taint_confirms:
            score += 0.05
        return round(min(1.0, score), 4)

    @staticmethod
    def _title(c: _RNGFinding) -> str:
        sources_str = " + ".join(c.rng.sources) if c.rng.sources else "block data"
        pattern_labels = {
            _RNGPattern.HASH_MOD:   "hash-and-modulo",
            _RNGPattern.DIRECT_MOD: "direct modulo",
            _RNGPattern.BLOCKHASH:  "blockhash cast",
            _RNGPattern.HASH_SEED:  "hash seed",
            _RNGPattern.WEAK_READ:  "weak entropy read",
        }
        label = pattern_labels.get(c.rng.pattern, c.rng.pattern.value)
        return f"Insecure Randomness: {label} using '{sources_str}'"

    @staticmethod
    def _description(c: _RNGFinding, fn_info: FunctionInfo) -> str:
        rng     = c.rng
        loc     = f" at line {rng.source_line}" if rng.source_line else ""
        src_str = " and ".join(rng.sources) if rng.sources else "block-level data"

        pattern_descs = {
            _RNGPattern.HASH_MOD: (
                f"Function '{fn_info.name}'{loc} generates a pseudorandom number "
                f"by hashing {src_str} and applying modulo. "
                f"This is a classic 'commit-reveal bypass' pattern: an attacker "
                f"can simulate the exact same keccak256 computation off-chain "
                f"using public blockchain data, predict the outcome, and only "
                f"submit their transaction when the result favours them."
            ),
            _RNGPattern.DIRECT_MOD: (
                f"Function '{fn_info.name}'{loc} computes a random index by "
                f"taking {src_str} modulo N directly. "
                f"Every value involved is public before the transaction mines — "
                f"any user (not just miners) can run the same computation and "
                f"know the result in advance."
            ),
            _RNGPattern.BLOCKHASH: (
                f"Function '{fn_info.name}'{loc} uses blockhash() as an entropy "
                f"source. blockhash(block.number - 1) is the hash of the PREVIOUS "
                f"block — a value that is publicly known before the current "
                f"transaction is included. Miners of the previous block also "
                f"had full control over this value."
            ),
            _RNGPattern.HASH_SEED: (
                f"Function '{fn_info.name}'{loc} creates a hash seed from "
                f"{src_str}. While no modulo is visible at this line, "
                f"the seed itself is deterministic and predictable from "
                f"public chain data. Any downstream use of this seed for "
                f"selection or allocation is exploitable."
            ),
        }

        base = pattern_descs.get(
            rng.pattern,
            f"Function '{fn_info.name}'{loc} reads {src_str} as an entropy "
            f"source. This value is miner-influenced or publicly predictable."
        )

        if rng.has_sink:
            base += (
                f" This random value appears to flow into a winner/selection "
                f"decision (detected nearby sink pattern), making this "
                f"directly exploitable for financial gain."
            )
        return base


# ---------------------------------------------------------------------------
# Public detector
# ---------------------------------------------------------------------------

class RandomnessDetector(BaseDetector):
    """
    Detects insecure on-chain pseudo-random number generation.

    Fires on:
      - keccak256(block.X) % N  (hash-and-modulo)
      - block.X % N             (direct modulo)
      - uint(blockhash(...))    (blockhash cast)
      - keccak256(block.X)      (hash seed, if used in a selection sink)

    Does NOT fire on:
      - block.timestamp in deadline conditions (→ TimestampDetector)
      - block.number in pure display/logging contexts
      - Chainlink VRF or commit-reveal patterns
    """

    DETECTOR_ID      = "randomness_v1"
    DETECTOR_VERSION = "1.0.0"
    VULN_TYPE        = VulnerabilityType.BAD_RANDOMNESS
    DEFAULT_SEVERITY = Severity.HIGH

    def __init__(self) -> None:
        self._rng_finder      = _RNGFinder()
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

        # ── Step 1: Fast-path ─────────────────────────────────────────
        if not _has_weak_source(cfg):
            logger.debug(
                "Randomness: '%s.%s' — no weak entropy source, skipped.",
                contract.name, fn_info.name,
            )
            return []

        # ── Steps 2 + 3: Find and classify RNG patterns ──────────────
        rngs = self._rng_finder.find(cfg)
        if not rngs:
            return []

        # ── Step 4: Risk filter ───────────────────────────────────────
        risky = [r for r in rngs if _is_risky(r)]
        if not risky:
            logger.debug(
                "Randomness: '%s.%s' — all patterns low-risk (no sink), skipped.",
                contract.name, fn_info.name,
            )
            return []

        # ── Step 5: Taint enrichment ──────────────────────────────────
        candidates = [_RNGFinding(rng=r) for r in risky]
        self._taint_enricher.enrich(candidates, taint_result)

        # ── Step 6: Deduplication ─────────────────────────────────────
        seen:         Set[Tuple[int, str]] = set()
        deduplicated: List[_RNGFinding]    = []
        for c in candidates:
            key = (c.rng.cfg_node_id, c.rng.pattern.value)
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
                "Randomness: '%s.%s' — %s severity, pattern='%s', "
                "sources=%s, sink=%s, taint=%s, cvss=%.1f.",
                contract.name, fn_info.name,
                finding.severity.value, c.rng.pattern.value,
                c.rng.sources, c.rng.has_sink,
                c.taint_confirms, finding.cvss_score,
            )

        return findings

    def build_recommendation(self, context: dict) -> str:
        fn_name    = context["function_name"]
        pattern    = context.get("pattern", "weak_entropy_read")
        sources    = context.get("sources") or ["block data"]
        is_payable = context.get("is_payable", False)
        line       = context.get("line_number")

        loc      = f" at line {line}" if line else ""
        src_str  = " and ".join(sources)

        base_recs = {
            "hash_and_modulo": (
                f"In function '{fn_name}'{loc}: replace the keccak256({src_str}) "
                f"% N pattern with Chainlink VRF (Verifiable Random Function). "
                f"Chainlink VRF provides cryptographically provable randomness "
                f"that cannot be predicted or manipulated by miners or users. "
                f"Alternatively, implement a commit-reveal scheme: users commit "
                f"a hash of their secret in one transaction, reveal it in the next, "
                f"and the random value is derived from both the contract's and "
                f"user's entropy combined."
            ),
            "direct_modulo": (
                f"In function '{fn_name}'{loc}: do NOT use {src_str} % N as "
                f"randomness — every component is public before your transaction "
                f"mines. Use Chainlink VRF for fair random selection. "
                f"If Chainlink is not feasible, a commit-reveal scheme gives "
                f"reasonable fairness for lower-stakes use cases."
            ),
            "blockhash_cast": (
                f"In function '{fn_name}'{loc}: blockhash() of a recent block "
                f"is publicly known — miners of that block had full control over "
                f"it, and all other users can look it up before sending. "
                f"Replace with Chainlink VRF. Note also that blockhash() returns "
                f"0x00 for blocks older than 256 — if that case is unhandled, "
                f"it is a separate bug."
            ),
            "hash_seed": (
                f"In function '{fn_name}'{loc}: the hash seed derived from "
                f"{src_str} is deterministic and publicly reproducible. "
                f"Any downstream selection using this seed is exploitable. "
                f"Replace with Chainlink VRF or ensure no financial decisions "
                f"depend on this value."
            ),
        }

        rec = base_recs.get(
            pattern,
            f"In function '{fn_name}'{loc}: replace predictable on-chain "
            f"entropy ({src_str}) with Chainlink VRF for any decision "
            f"involving money, NFT allocation, or game outcomes."
        )

        if is_payable:
            rec += (
                f" '{fn_name}' is payable — an attacker who can predict the "
                f"outcome can also front-run with the exact correct ETH amount "
                f"to maximise their payout."
            )

        return rec

    def calculate_cvss(self, context: dict) -> float:
        """
        Base: 6.0

        ┌──────────────────────────────────────────────┬───────┐
        │ Condition                                    │ Delta │
        ├──────────────────────────────────────────────┼───────┤
        │ hash_and_modulo pattern                      │ +2.5  │
        │ direct_modulo pattern                        │ +2.0  │
        │ blockhash_cast pattern                       │ +1.5  │
        │ hash_seed pattern                            │ +0.5  │
        │ has_sink (flows into winner/selection)       │ +1.0  │
        │ taint confirms entropy flow                  │ +0.5  │
        │ is_payable function                          │ +0.5  │
        │ external / public visibility                 │ +0.3  │
        └──────────────────────────────────────────────┴───────┘
        """
        score      = 6.0
        pattern    = context.get("pattern", "weak_entropy_read")
        is_payable = context.get("is_payable", False)

        pattern_deltas = {
            "hash_and_modulo": 2.5,
            "direct_modulo":   2.0,
            "blockhash_cast":  1.5,
            "hash_seed":       0.5,
        }
        score += pattern_deltas.get(pattern, 0.0)

        if context.get("has_sink"):
            score += 1.0
        if context.get("taint_confirms"):
            score += 0.5
        if is_payable:
            score += 0.5
        if context.get("function_visibility") in ("external", "public"):
            score += 0.3

        return round(max(0.0, min(10.0, score)), 1)

    # ------------------------------------------------------------------
    # Context builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_context(
        c:        _RNGFinding,
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
            "line_number":         c.rng.source_line,
            "cfg_node":            c.rng.cfg_node_id,
            "pattern":             c.rng.pattern.value,
            "sources":             c.rng.sources,
            "has_sink":            c.rng.has_sink,
            "stmt":                c.rng.stmt,
            "taint_confirms":      c.taint_confirms,
            "taint_source":        (
                c.taint_source.value if c.taint_source else None
            ),
        }