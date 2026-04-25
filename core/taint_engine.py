"""
core/taint_engine.py

Taint analysis engine for VigilanceCore.

This module is a QUERY LAYER only. It answers questions about taint
flow and provides propagation paths. It never decides vulnerability.

Architecture position:
    cfg_builder.py  →  CFGGraph, DFGGraph
                              ↓
                        TaintEngine
                              ↓
                    detectors/
                      reentrancy_detector
                      access_control_detector
                      arithmetic_detector
                      delegatecall_detector

Design rules:
  1.  TaintEngine never decides vulnerability — detectors do.
  2.  No Slither objects — operates only on CFGGraph, DFGGraph,
      FunctionInfo.
  3.  Models and graphs are never mutated.
  4.  Propagation is intra-procedural. Cross-function taint is the
      responsibility of the future call_graph_builder.py module.
  5.  Storage taint is tracked AND re-propagated: a tainted value
      written to a state variable taints that slot; subsequent reads
      of that slot propagate taint further through a fixed-point pass.
  6.  is_tainted(v, at_cfg_node) uses CFG dominance, not node_id
      ordering. node_id ordering is not guaranteed to reflect program
      execution order in the presence of branches and loops.
      Fallback when dominators are unavailable: set-membership check —
      avoids both false positives and false negatives.
  7.  Sanitizers (require/assert/revert) reduce flow confidence but
      do not eliminate flows. Detection is heuristic — may over-sanitize
      (see _SanitizerRegistry comment).
  8.  Source detection normalises versioned names (amount_1 → amount).
  9.  Unknown taint origins use TaintSourceKind.UNKNOWN (confidence 0.50)
      not FUNCTION_PARAM (1.0) — avoids inflating vulnerability reports.
  10. Helper instances created once in TaintEngine.__init__, not per run.
  11. Arithmetic sink detection uses ir_op_types (IR class names) as the
      primary signal and falls back to _ARITH_STMT_RE regex.
  12. Propagation chain stores List[Tuple[str, int]] — each step carries
      the variable name AND its cfg_node_id — giving every intermediate
      TaintNode an accurate CFG position.
  13. TaintEngineFactory carries proper generic type annotations.
  14. _StorageTaintTracker.track() always returns a Tuple — the missing
      return at the end of the tainted-storage path is present.
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from core.cfg_builder import CFGAnalysisResult, CFGGraph, DFGGraph
from core.enums import CallType
from core.models import FunctionInfo

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Module-level compiled patterns
# ---------------------------------------------------------------------------

# Arithmetic detection — symbolic operators AND Slither IR keyword forms
# including Signed/Unsigned/Safe variant prefixes.
# Used as FALLBACK when ir_op_types is unavailable.
_ARITH_STMT_RE = re.compile(
    r"(?:"
    r"[\+\-\*/%]"
    r"|\*\*"
    r"|\bADD\b|\bSUB\b|\bMUL\b|\bDIV\b|\bMOD\b"
    r"|\bBinaryOperation\b|\bAddition\b|\bSubt\b"
    r"|\b(?:Signed|Unsigned|Safe)?(?:Add|Sub|Mul|Div|Mod)\b"
    r")"
)

# IR op type name pattern — matches Slither IR class names directly.
# Used as PRIMARY arithmetic detection — no string ambiguity.
_ARITH_OP_TYPE_RE = re.compile(
    r"^(?:"
    r"(?:Signed|Unsigned|Safe)?(?:Add|Sub|Mul|Div|Mod)"
    r"|BinaryOperation"
    r"|LibraryCall"       # SafeMath and similar library arithmetic
    r")$"
)

# Identifier extractor for sanitizer variable scanning
_IDENT_RE = re.compile(r"\b[a-zA-Z_][a-zA-Z0-9_.]*\b")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TaintSourceKind(str, Enum):
    """
    Categories of taint sources, ordered roughly by attacker-control
    strength.

    UNKNOWN is used when origin cannot be determined — it carries a
    reduced confidence weight (0.50) rather than the full weight of
    FUNCTION_PARAM (1.0), preventing inflation of vulnerability reports.
    """
    MSG_SENDER      = "msg.sender"
    MSG_VALUE       = "msg.value"
    MSG_DATA        = "msg.data"
    TX_ORIGIN       = "tx.origin"
    BLOCK_TIMESTAMP = "block.timestamp"   # miner-influenced
    BLOCK_NUMBER    = "block.number"      # miner-influenced
    CALLDATA        = "calldata"
    FUNCTION_PARAM  = "function_parameter"
    STORAGE_READ    = "storage_read"      # tainted storage slot read
    RETURN_VALUE    = "return_value"      # return from external call
    UNKNOWN         = "unknown"           # origin not determinable


class TaintSinkKind(str, Enum):
    """Categories of dangerous taint sinks."""
    EXTERNAL_CALL_ARGUMENT = "external_call_argument"
    EXTERNAL_CALL_TARGET   = "external_call_target"
    EXTERNAL_CALL_VALUE    = "external_call_value"
    DELEGATECALL_TARGET    = "delegatecall_target"
    STORAGE_WRITE          = "storage_write"
    ARITHMETIC_OPERAND     = "arithmetic_operand"
    SELFDESTRUCT_TARGET    = "selfdestruct_target"
    REQUIRE_CONDITION      = "require_condition"
    EVENT_ARGUMENT         = "event_argument"


# ---------------------------------------------------------------------------
# Type alias
# ---------------------------------------------------------------------------

# Propagation chain entry: (variable_name, cfg_node_id_at_this_step)
# cfg_node_id is -1 for the source entry (position not tracked at init).
_ChainEntry   = Tuple[str, int]
_Chain        = List[_ChainEntry]
_ChainMap     = Dict[str, _Chain]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class TaintNode:
    """
    One step in a taint propagation path.

    cfg_node_id is now accurate for every hop including intermediate
    nodes, because the propagation chain stores (var, cfg_node_id) tuples.
    Source entries still use cfg_node_id=-1 (position unknown at source
    initialisation time).
    """
    variable:    str
    cfg_node_id: int
    is_source:   bool                      = False
    is_sink:     bool                      = False
    source_kind: Optional[TaintSourceKind] = None
    sink_kind:   Optional[TaintSinkKind]   = None
    source_line: Optional[int]             = None

    def __repr__(self) -> str:
        tag = "[SRC]" if self.is_source else ("[SNK]" if self.is_sink else "")
        return (
            f"TaintNode({self.variable!r} "
            f"@ node {self.cfg_node_id} {tag})"
        )


@dataclass
class TaintFlow:
    """
    A complete taint propagation path from one source to one sink.

    Attributes
    ----------
    source_variable : Variable name where taint originates.
    source_kind     : Category of the taint source.
    sink_variable   : Variable name at the sink.
    sink_kind       : Category of the sink.
    path            : Ordered steps (source → … → sink).
                      Each TaintNode carries its accurate cfg_node_id.
    cfg_node_id     : CFG node where the sink is located.
    source_line     : Source line of the sink (for reporting).
    confidence      : 0.0–1.0. Detectors should filter below their
                      own threshold (suggested minimum: 0.4).
    is_sanitized    : True if the flow passes through a sanitizer check.
                      Confidence is already reduced by
                      _SANITIZER_CONFIDENCE_FACTOR.
    call_type       : CallType if the sink is an external call, else None.
    """
    source_variable: str
    source_kind:     TaintSourceKind
    sink_variable:   str
    sink_kind:       TaintSinkKind
    path:            List[TaintNode]
    cfg_node_id:     int
    source_line:     Optional[int]      = None
    confidence:      float              = 1.0
    is_sanitized:    bool               = False
    call_type:       Optional[CallType] = None

    def path_str(self) -> str:
        """Human-readable propagation path for reports."""
        return " → ".join(n.variable for n in self.path)

    def hop_count(self) -> int:
        """Number of propagation steps (source to sink)."""
        return max(len(self.path) - 1, 0)

    def __repr__(self) -> str:
        return (
            f"TaintFlow({self.source_variable!r} → {self.sink_variable!r}, "
            f"sink={self.sink_kind.value}, conf={self.confidence:.2f})"
        )


@dataclass
class TaintResult:
    """Complete taint analysis result for one function."""
    function_sig:      str
    tainted_variables: Set[str]        = field(default_factory=set)
    flows:             List[TaintFlow] = field(default_factory=list)
    tainted_storage:   Set[str]        = field(default_factory=set)
    sanitized_vars:    Set[str]        = field(default_factory=set)
    source_count:      int             = 0
    analysis_error:    Optional[str]   = None

    def flows_to_sink(self, sink_kind: TaintSinkKind) -> List[TaintFlow]:
        """Return all flows to a specific sink category."""
        return [f for f in self.flows if f.sink_kind == sink_kind]

    def has_tainted_external_calls(self) -> bool:
        """True if any taint flows into an external call."""
        _call_sinks = {
            TaintSinkKind.EXTERNAL_CALL_ARGUMENT,
            TaintSinkKind.EXTERNAL_CALL_VALUE,
            TaintSinkKind.EXTERNAL_CALL_TARGET,
            TaintSinkKind.DELEGATECALL_TARGET,
        }
        return any(f.sink_kind in _call_sinks for f in self.flows)

    def high_confidence_flows(self, threshold: float = 0.6) -> List[TaintFlow]:
        """Return flows above a given confidence threshold."""
        return [f for f in self.flows if f.confidence >= threshold]


# ---------------------------------------------------------------------------
# Taint source registry and confidence weights
# ---------------------------------------------------------------------------

_KNOWN_GLOBAL_SOURCES: Dict[str, TaintSourceKind] = {
    "msg.sender":       TaintSourceKind.MSG_SENDER,
    "msg.value":        TaintSourceKind.MSG_VALUE,
    "msg.data":         TaintSourceKind.MSG_DATA,
    "msg.gas":          TaintSourceKind.MSG_DATA,
    "tx.origin":        TaintSourceKind.TX_ORIGIN,
    "block.timestamp":  TaintSourceKind.BLOCK_TIMESTAMP,
    "block.number":     TaintSourceKind.BLOCK_NUMBER,
    "block.difficulty": TaintSourceKind.BLOCK_TIMESTAMP,
    "block.prevrandao": TaintSourceKind.BLOCK_TIMESTAMP,
    "now":              TaintSourceKind.BLOCK_TIMESTAMP,
}

_SOURCE_CONFIDENCE: Dict[TaintSourceKind, float] = {
    TaintSourceKind.MSG_SENDER:      1.0,
    TaintSourceKind.MSG_VALUE:       1.0,
    TaintSourceKind.FUNCTION_PARAM:  1.0,
    TaintSourceKind.CALLDATA:        1.0,
    TaintSourceKind.TX_ORIGIN:       0.9,
    TaintSourceKind.MSG_DATA:        0.9,
    TaintSourceKind.STORAGE_READ:    0.85,
    TaintSourceKind.RETURN_VALUE:    0.80,
    TaintSourceKind.BLOCK_TIMESTAMP: 0.70,
    TaintSourceKind.BLOCK_NUMBER:    0.60,
    TaintSourceKind.UNKNOWN:         0.50,
}

# Safe fallback when taint origin cannot be determined.
# UNKNOWN (0.50) rather than FUNCTION_PARAM (1.0) avoids inflating risk.
_UNKNOWN_ORIGIN: TaintSourceKind = TaintSourceKind.UNKNOWN

_HOP_PENALTY:                 float = 0.04
_STORAGE_PENALTY:             float = 0.05
_SANITIZER_CONFIDENCE_FACTOR: float = 0.65
_MIN_CONFIDENCE:              float = 0.30


# ---------------------------------------------------------------------------
# _SourceInitialiser
# ---------------------------------------------------------------------------


class _SourceInitialiser:
    """
    Identifies taint sources visible in a function's DFG.

    Variable name normalisation:
        Slither IR versioning produces names like amount_1, amount_tmp.
        These are matched to parameter "amount" by splitting on "_" and
        comparing the base name.

        Exact match is tried first; base-name match is the fallback.
        Only fires when "_" is present — prevents false substring matches
        (e.g. "amountFee" does NOT match "amount").
    """

    def identify(
        self,
        dfg:     DFGGraph,
        fn_info: FunctionInfo,
    ) -> Dict[str, TaintSourceKind]:
        sources:     Dict[str, TaintSourceKind] = {}
        param_names: Set[str] = {
            p.name for p in fn_info.parameters if p.name
        }

        for var_name in dfg.def_use_chains.keys():
            # Check global sources — exact and dotted-prefix match
            matched = False
            for global_name, kind in _KNOWN_GLOBAL_SOURCES.items():
                if (
                    var_name == global_name
                    or var_name.startswith(global_name + ".")
                ):
                    sources[var_name] = kind
                    matched = True
                    break

            if not matched:
                # Exact parameter match
                if var_name in param_names:
                    sources[var_name] = TaintSourceKind.FUNCTION_PARAM
                    continue

                # Base-name normalisation: "amount_1" → "amount"
                if "_" in var_name:
                    base = var_name.split("_")[0]
                    if base and base in param_names:
                        sources[var_name] = TaintSourceKind.FUNCTION_PARAM

        return sources


# ---------------------------------------------------------------------------
# _TaintPropagator
# ---------------------------------------------------------------------------


class _TaintPropagator:
    """
    BFS worklist propagation through DFG def-use chains.

    Chain format:
        chain[v] = List[Tuple[str, int]]
        Each entry is (variable_name, cfg_node_id_at_this_step).
        Source entries use cfg_node_id=-1 (position not tracked at init).
        Propagation steps use the USE node's cfg_node_id for accuracy.

    KNOWN LIMITATION — statement-level granularity:
        Two independent IR operations sharing a CFG node are treated as
        one statement. If op A uses a tainted var, op B in the same node
        may be incorrectly tainted. This is a known over-approximation.
        IR-level granularity requires per-IR-op node IDs in DFGNode
        (ir_index is now stored — future improvement can use it here).
    """

    def propagate(
        self,
        dfg:     DFGGraph,
        sources: Dict[str, TaintSourceKind],
    ) -> Tuple[Set[str], Dict[str, TaintSourceKind], _ChainMap]:
        """
        Returns (tainted_vars, origin_kind, chain).

        chain[v] = [(var, cfg_node_id), ...] — source-to-v path.
        """
        tainted_vars: Set[str]                   = set(sources.keys())
        origin_kind:  Dict[str, TaintSourceKind] = dict(sources)
        chain:        _ChainMap                  = {
            v: [(v, -1)] for v in sources   # -1: source position unknown
        }

        # Pre-build cfg_node_id → set of DEF variable names once.
        # Avoids re-scanning DFG on every worklist iteration.
        defs_at: Dict[int, Set[str]] = defaultdict(set)
        for node in dfg.nodes.values():
            if node.is_definition:
                defs_at[node.cfg_node_id].add(node.variable)

        worklist: deque = deque(sources.keys())

        while worklist:
            var = worklist.popleft()
            for use_node in dfg.uses(var):
                for defined_var in defs_at.get(use_node.cfg_node_id, set()):
                    if defined_var in tainted_vars:
                        continue
                    tainted_vars.add(defined_var)
                    origin_kind[defined_var] = origin_kind.get(
                        var, _UNKNOWN_ORIGIN
                    )
                    chain[defined_var] = (
                        chain.get(var, [(var, -1)])
                        + [(defined_var, use_node.cfg_node_id)]
                    )
                    worklist.append(defined_var)

        return tainted_vars, origin_kind, chain


# ---------------------------------------------------------------------------
# _StorageTaintTracker
# ---------------------------------------------------------------------------


class _StorageTaintTracker:
    """
    Tracks taint through state variable storage writes and reads.

    Step 1 — tainted storage writes:
        If a tainted variable is USED at the same CFG node as a state
        variable DEFINITION → that storage slot is tainted.

    Step 2 — propagate from tainted storage reads:
        If a tainted storage slot is USED at a CFG node where another
        variable is DEFINED → the defined variable inherits taint.
        Multiple storage origins: picks the one with the richest
        existing chain (most provenance information).

    After track() returns, the engine re-runs _TaintPropagator on
    the newly discovered variables so that downstream uses (e.g.
    y = x + fee where x reads tainted storage) are also caught.

    IMPORTANT: this method always returns Tuple[Set[str], Set[str]].
    The early return for empty tainted_storage AND the final return
    both provide the full tuple — Python never falls off the end.
    """

    def track(
        self,
        dfg:          DFGGraph,
        fn_info:      FunctionInfo,
        tainted_vars: Set[str],
        origin_kind:  Dict[str, TaintSourceKind],
        chain:        _ChainMap,
    ) -> Tuple[Set[str], Set[str]]:
        """
        Returns (new_tainted, tainted_storage).

        new_tainted     : Local vars that read from tainted storage.
        tainted_storage : State variable names that are tainted.
        """
        sv_written: Set[str] = {
            sv.name for sv in fn_info.state_vars_written if sv.name
        }
        sv_read: Set[str] = {
            sv.name for sv in fn_info.state_vars_read if sv.name
        }

        used_at:    Dict[int, Set[str]] = defaultdict(set)
        defined_at: Dict[int, Set[str]] = defaultdict(set)

        for node in dfg.nodes.values():
            if node.is_use:
                used_at[node.cfg_node_id].add(node.variable)
            if node.is_definition:
                defined_at[node.cfg_node_id].add(node.variable)

        tainted_storage: Set[str] = set()

        # Step 1 — identify tainted state variable writes
        for cfg_nid, defs in defined_at.items():
            written_here = defs & sv_written
            if not written_here:
                continue
            if used_at.get(cfg_nid, set()) & tainted_vars:
                tainted_storage.update(written_here)

        if not tainted_storage:
            return set(), set()

        # Step 2 — propagate taint from reads of tainted storage
        new_tainted: Set[str] = set()

        for cfg_nid, uses in used_at.items():
            tainted_reads = uses & tainted_storage & sv_read
            if not tainted_reads:
                continue
            for defined_var in defined_at.get(cfg_nid, set()):
                if defined_var in tainted_vars:
                    continue
                new_tainted.add(defined_var)
                origin_kind[defined_var] = TaintSourceKind.STORAGE_READ
                # Pick the origin with the richest existing chain for
                # the best provenance information in the trace.
                best_origin = max(
                    tainted_reads,
                    key=lambda v: len(chain.get(v, [(v, -1)])),
                )
                chain[defined_var] = (
                    chain.get(best_origin, [(best_origin, -1)])
                    + [(defined_var, cfg_nid)]
                )

        return new_tainted, tainted_storage  # always reached


# ---------------------------------------------------------------------------
# _SanitizerRegistry
# ---------------------------------------------------------------------------


class _SanitizerRegistry:
    """
    Identifies variables that appear inside sanitizer conditions.

    A sanitizer is a defensive check — require(), assert(), revert() —
    that validates a variable before use. Flows involving sanitized
    variables have their confidence reduced by _SANITIZER_CONFIDENCE_FACTOR
    but are NOT eliminated because:
      1. The check might be incomplete (require(x > 0) still allows x=1).
      2. The check might appear AFTER the vulnerable use.

    HEURISTIC WARNING:
        This extracts all identifiers from sanitizer statement strings.
        It WILL over-sanitize in cases like:
            require(balance >= amount);
        where both `balance` AND `amount` are marked sanitized, even
        though `amount` may still be attacker-controlled downstream.
        IR-level boolean-comparison parsing would improve precision here.
        This is an acceptable trade-off: over-sanitization reduces
        confidence rather than eliminating flows.
    """

    _SANITIZER_KEYWORDS: FrozenSet[str] = frozenset({
        "require", "assert", "revert",
    })

    _SKIP_TOKENS: FrozenSet[str] = frozenset({
        "require", "assert", "revert", "if", "else",
        "msg", "sender", "value", "data", "gas",
        "tx", "origin", "block", "timestamp", "number",
        "true", "false", "this", "address",
    })

    def identify(self, cfg: CFGGraph) -> Set[str]:
        """
        Return variable names appearing in sanitizer check statements.
        """
        sanitized: Set[str] = set()

        for node in cfg.nodes.values():
            for stmt in node.ir_stmts:
                stmt_lower = stmt.lower()
                if not any(kw in stmt_lower for kw in self._SANITIZER_KEYWORDS):
                    continue
                # HEURISTIC WARNING: this extracts ALL identifiers from sanitizer
                # statements. It over-sanitizes in cases like:
                #     require(balance >= amount);
                # Both `balance` and `amount` are marked sanitized even though
                # `amount` may still be attacker-controlled downstream.
                #
                # Known limitation — not eliminated because:
                #   1. The check might be incomplete (require(x > 0) still allows x=1)
                #   2. The check might appear AFTER the vulnerable use site
                #
                # Confidence is reduced by _SANITIZER_CONFIDENCE_FACTOR (0.65) rather
                # than eliminating flows — detectors apply their own thresholds.
                #
                # Future improvement: parse comparison operators (>=, <=, ==, >, <)
                # and only sanitize the LEFT-HAND operand of the guard expression.
                # This would correctly mark `balance` but not `amount` sanitized.
                for token in _IDENT_RE.findall(stmt):
                    if token not in self._SKIP_TOKENS and len(token) > 2:
                        sanitized.add(token)

        return sanitized


# ---------------------------------------------------------------------------
# _SinkDetector
# ---------------------------------------------------------------------------


class _SinkDetector:
    """
    Identifies taint flows to dangerous sinks and builds TaintFlow objects.

    Three sink categories detected:
      1. External call sinks  — from FunctionInfo.external_calls
      2. Storage write sinks  — tainted value written to a state variable
      3. Arithmetic sinks     — tainted value used in arithmetic operation

    Sanitizer check:
      Any flow whose sink_variable appears in sanitized_vars gets its
      confidence reduced by _SANITIZER_CONFIDENCE_FACTOR.
    """

    def detect(
        self,
        dfg:             DFGGraph,
        cfg:             CFGGraph,
        fn_info:         FunctionInfo,
        tainted_vars:    Set[str],
        origin_kind:     Dict[str, TaintSourceKind],
        chain:           _ChainMap,
        tainted_storage: Set[str],
        sanitized_vars:  Set[str],
    ) -> List[TaintFlow]:
        if not tainted_vars:
            return []

        # cfg_node_id → set of tainted vars USED there
        tainted_used_at: Dict[int, Set[str]] = defaultdict(set)
        for node in dfg.nodes.values():
            if node.is_use and node.variable in tainted_vars:
                tainted_used_at[node.cfg_node_id].add(node.variable)

        # source_line → cfg_node_id (for call matching)
        line_to_cfg: Dict[int, int] = {}
        for node in cfg.nodes.values():
            if node.source_line is not None:
                line_to_cfg[node.source_line] = node.node_id

        flows: List[TaintFlow] = []
        flows.extend(self._detect_call_sinks(
            fn_info, tainted_used_at, line_to_cfg,
            origin_kind, chain, sanitized_vars,
        ))
        flows.extend(self._detect_storage_write_sinks(
            dfg, fn_info, tainted_used_at,
            origin_kind, chain, sanitized_vars,
        ))
        flows.extend(self._detect_arithmetic_sinks(
            cfg, tainted_used_at, origin_kind, chain, sanitized_vars,
        ))
        return flows

    # ------------------------------------------------------------------

    def _detect_call_sinks(
        self,
        fn_info:         FunctionInfo,
        tainted_used_at: Dict[int, Set[str]],
        line_to_cfg:     Dict[int, int],
        origin_kind:     Dict[str, TaintSourceKind],
        chain:           _ChainMap,
        sanitized_vars:  Set[str],
    ) -> List[TaintFlow]:
        flows: List[TaintFlow] = []

        for call in fn_info.external_calls:
            cfg_nid = self._resolve_cfg_node(call.start_line, line_to_cfg)
            if cfg_nid is None:
                continue

            tainted_here = tainted_used_at.get(cfg_nid, set())
            if not tainted_here:
                continue

            if call.call_type == CallType.DELEGATECALL:
                sink_kind = TaintSinkKind.DELEGATECALL_TARGET
            elif call.value_transfer:
                sink_kind = TaintSinkKind.EXTERNAL_CALL_VALUE
            else:
                sink_kind = TaintSinkKind.EXTERNAL_CALL_ARGUMENT

            for tainted_var in tainted_here:
                src_kind     = origin_kind.get(tainted_var, _UNKNOWN_ORIGIN)
                path         = self._build_path(
                    tainted_var, chain, cfg_nid,
                    call.start_line, sink_kind, src_kind,
                )
                is_sanitized = tainted_var in sanitized_vars
                confidence   = self._score(src_kind, path, False, is_sanitized)
                flows.append(TaintFlow(
                    source_variable = chain.get(tainted_var, [(tainted_var, -1)])[0][0],
                    source_kind     = src_kind,
                    sink_variable   = tainted_var,
                    sink_kind       = sink_kind,
                    path            = path,
                    cfg_node_id     = cfg_nid,
                    source_line     = call.start_line,
                    confidence      = confidence,
                    is_sanitized    = is_sanitized,
                    call_type       = call.call_type,
                ))

        return flows

    def _detect_storage_write_sinks(
        self,
        dfg:             DFGGraph,
        fn_info:         FunctionInfo,
        tainted_used_at: Dict[int, Set[str]],
        origin_kind:     Dict[str, TaintSourceKind],
        chain:           _ChainMap,
        sanitized_vars:  Set[str],
    ) -> List[TaintFlow]:
        flows: List[TaintFlow] = []

        sv_written: Set[str] = {
            sv.name for sv in fn_info.state_vars_written if sv.name
        }
        if not sv_written:
            return flows

        state_defs_at:    Dict[int, Set[str]]      = defaultdict(set)
        node_source_line: Dict[int, Optional[int]] = {}

        for dfg_node in dfg.nodes.values():
            if dfg_node.is_definition and dfg_node.variable in sv_written:
                state_defs_at[dfg_node.cfg_node_id].add(dfg_node.variable)
                node_source_line[dfg_node.cfg_node_id] = dfg_node.source_line

        for cfg_nid, state_vars in state_defs_at.items():
            tainted_here = tainted_used_at.get(cfg_nid, set())
            if not tainted_here:
                continue

            src_line = node_source_line.get(cfg_nid)

            for tainted_var in tainted_here:
                for state_var in state_vars:
                    src_kind     = origin_kind.get(tainted_var, _UNKNOWN_ORIGIN)
                    path         = self._build_path(
                        tainted_var, chain, cfg_nid,
                        src_line, TaintSinkKind.STORAGE_WRITE, src_kind,
                    )
                    is_sanitized = tainted_var in sanitized_vars
                    confidence   = self._score(
                        src_kind, path, True, is_sanitized
                    )
                    flows.append(TaintFlow(
                        source_variable = chain.get(tainted_var, [(tainted_var, -1)])[0][0],
                        source_kind     = src_kind,
                        sink_variable   = state_var,
                        sink_kind       = TaintSinkKind.STORAGE_WRITE,
                        path            = path,
                        cfg_node_id     = cfg_nid,
                        source_line     = src_line,
                        confidence      = confidence,
                        is_sanitized    = is_sanitized,
                    ))

        return flows

    def _detect_arithmetic_sinks(
        self,
        cfg:             CFGGraph,
        tainted_used_at: Dict[int, Set[str]],
        origin_kind:     Dict[str, TaintSourceKind],
        chain:           _ChainMap,
        sanitized_vars:  Set[str],
    ) -> List[TaintFlow]:
        """
        Detect tainted values flowing into arithmetic operations.

        Detection strategy:
          Primary:  match CFGNode.ir_op_types against _ARITH_OP_TYPE_RE
                    (IR class name — most accurate, no string ambiguity,
                     covers Signed/Unsigned/Safe variants)
          Fallback: match CFGNode.ir_stmts against _ARITH_STMT_RE
                    (used when ir_op_types is empty, e.g. when Slither
                     IR was unavailable during CFG build)
        """
        flows: List[TaintFlow] = []

        for cfg_node in cfg.nodes.values():
            tainted_here = tainted_used_at.get(cfg_node.node_id, set())
            if not tainted_here:
                continue

            # Primary: IR op type class names (no string ambiguity)
            is_arithmetic = any(
                _ARITH_OP_TYPE_RE.match(op_type)
                for op_type in getattr(cfg_node, "ir_op_types", [])   # ← safe
            )

            # Fallback: regex on ir_stmts when ir_op_types unavailable
            if not is_arithmetic and cfg_node.ir_stmts:
                is_arithmetic = any(
                    _ARITH_STMT_RE.search(stmt)
                    for stmt in cfg_node.ir_stmts
                )

            if not is_arithmetic:
                continue

            for tainted_var in tainted_here:
                src_kind     = origin_kind.get(tainted_var, _UNKNOWN_ORIGIN)
                path         = self._build_path(
                    tainted_var, chain, cfg_node.node_id,
                    cfg_node.source_line,
                    TaintSinkKind.ARITHMETIC_OPERAND,
                    src_kind,
                )
                is_sanitized = tainted_var in sanitized_vars
                confidence   = self._score(src_kind, path, False, is_sanitized)
                flows.append(TaintFlow(
                    source_variable = chain.get(tainted_var, [(tainted_var, -1)])[0][0],
                    source_kind     = src_kind,
                    sink_variable   = tainted_var,
                    sink_kind       = TaintSinkKind.ARITHMETIC_OPERAND,
                    path            = path,
                    cfg_node_id     = cfg_node.node_id,
                    source_line     = cfg_node.source_line,
                    confidence      = confidence,
                    is_sanitized    = is_sanitized,
                ))

        return flows

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_cfg_node(
        source_line: Optional[int],
        line_to_cfg: Dict[int, int],
    ) -> Optional[int]:
        """
        Map source line → CFG node ID.
        Tries exact match first, then ±5 line tolerance to handle
        multi-line statements and compiler line-number shifts.
        Solidity statements can shift 5-6 lines after compilation,
        so ±3 was insufficient for complex multi-line expressions.
        """
        if source_line is None:
            return None
        if source_line in line_to_cfg:
            return line_to_cfg[source_line]
        for delta in range(1, 6):           # ← ±5 lines
            for candidate in (source_line + delta, source_line - delta):
                if candidate in line_to_cfg:
                    return line_to_cfg[candidate]
        return None


    @staticmethod
    def _build_path(
        sink_var:    str,
        chain:       _ChainMap,
        cfg_nid:     int,
        source_line: Optional[int],
        sink_kind:   TaintSinkKind,
        source_kind: TaintSourceKind,
    ) -> List[TaintNode]:
        """
        Build TaintNode path for a flow.

        Intermediate nodes now carry accurate cfg_node_id values from
        the chain tuples. Source node uses -1 (position unknown at init).
        Sink node uses cfg_nid from the sink detection context.
        """
        var_chain: _Chain = chain.get(sink_var, [(sink_var, -1)])
        nodes: List[TaintNode] = []

        for i, (var, hop_cfg_nid) in enumerate(var_chain):
            is_src = (i == 0)
            is_snk = (i == len(var_chain) - 1)
            nodes.append(TaintNode(
                variable    = var,
                cfg_node_id = cfg_nid if is_snk else hop_cfg_nid,
                is_source   = is_src,
                is_sink     = is_snk,
                source_kind = source_kind if is_src else None,
                sink_kind   = sink_kind   if is_snk else None,
                source_line = source_line if is_snk else None,
            ))

        return nodes

    @staticmethod
    def _score(
        source_kind:  TaintSourceKind,
        path:         List[TaintNode],
        storage_hop:  bool,
        is_sanitized: bool,
    ) -> float:
        """
        Confidence score for a TaintFlow:
            base     = _SOURCE_CONFIDENCE[source_kind]
            penalty  = hop_count × _HOP_PENALTY
                     + _STORAGE_PENALTY  (if crosses storage)
            result   = max(base - penalty, _MIN_CONFIDENCE)
                     × _SANITIZER_CONFIDENCE_FACTOR  (if sanitized)
        """
        base    = _SOURCE_CONFIDENCE.get(source_kind, 0.8)
        hops    = max(len(path) - 1, 0)
        penalty = hops * _HOP_PENALTY
        if storage_hop:
            penalty += _STORAGE_PENALTY
        score = max(base - penalty, _MIN_CONFIDENCE)
        if is_sanitized:
            score = max(
                round(score * _SANITIZER_CONFIDENCE_FACTOR, 4),
                _MIN_CONFIDENCE,
            )
        return round(score, 4)


# ---------------------------------------------------------------------------
# TaintEngine — public entry point
# ---------------------------------------------------------------------------


class TaintEngine:
    """
    Intra-procedural taint analysis engine for one function.

    Helper instances are created once in __init__ and reused across
    calls — never reconstructed per run().

    Usage
    -----
        engine = TaintEngine(cfg, dfg, fn_info)
        result = engine.run()

        engine.is_tainted("amount")
        engine.is_tainted("amount", at_cfg_node=7)
        engine.tainted_sinks()
        engine.tainted_sinks_of_kind(TaintSinkKind.EXTERNAL_CALL_VALUE)
        engine.trace("amount")
        engine.tainted_variables()
        engine.tainted_storage_slots()
        engine.source_kind("amount")
        engine.is_sanitized("amount")

    run() is idempotent — subsequent calls return the cached result.
    """

    def __init__(
        self,
        cfg:     CFGGraph,
        dfg:     DFGGraph,
        fn_info: FunctionInfo,
    ) -> None:
        self._cfg     = cfg
        self._dfg     = dfg
        self._fn_info = fn_info
        self._ran     = False
        self._result: Optional[TaintResult] = None

        # Internal propagation state
        self._tainted_vars:    Set[str]                   = set()
        self._origin_kind:     Dict[str, TaintSourceKind] = {}
        self._chain:           _ChainMap                  = {}
        self._tainted_storage: Set[str]                   = set()
        self._sanitized_vars:  Set[str]                   = set()
        self._flows:           List[TaintFlow]             = []

        # Helpers created once
        self._source_init = _SourceInitialiser()
        self._propagator  = _TaintPropagator()
        self._storage_trk = _StorageTaintTracker()
        self._sanitizer   = _SanitizerRegistry()
        self._sink_det    = _SinkDetector()

    # ------------------------------------------------------------------
    # Public: run
    # ------------------------------------------------------------------

    def run(self) -> TaintResult:
        """
        Execute full taint analysis. Results are cached.
        Safe to call multiple times — subsequent calls return the cache.
        """
        if self._ran:
            return self._result  # type: ignore[return-value]
        self._ran = True

        try:
            self._run_internal()
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "TaintEngine failed for '%s': %s",
                self._fn_info.signature, exc,
            )
            self._result = TaintResult(
                function_sig   = self._fn_info.signature,
                analysis_error = str(exc),
            )
            return self._result

        self._result = TaintResult(
            function_sig      = self._fn_info.signature,
            tainted_variables = set(self._tainted_vars),
            flows             = list(self._flows),
            tainted_storage   = set(self._tainted_storage),
            sanitized_vars    = set(self._sanitized_vars),
            source_count      = sum(
                1 for v in self._origin_kind
                if self._origin_kind[v] != TaintSourceKind.STORAGE_READ
            ),
        )

        logger.debug(
            "TaintEngine '%s': %d tainted vars, %d storage, "
            "%d sanitized, %d flows.",
            self._fn_info.signature,
            len(self._tainted_vars),
            len(self._tainted_storage),
            len(self._sanitized_vars),
            len(self._flows),
        )

        return self._result

    # ------------------------------------------------------------------
    # Internal pipeline
    # ------------------------------------------------------------------

    def _run_internal(self) -> None:
        """
        Four-stage taint pipeline:
          Stage 1 — identify sources (_SourceInitialiser)
          Stage 2 — propagate through DFG (_TaintPropagator)
          Stage 3a — storage taint tracking (_StorageTaintTracker)
          Stage 3b — re-propagate from storage-tainted vars
          Stage 4 — sanitizer identification (_SanitizerRegistry)
          Stage 5 — detect sinks (_SinkDetector)
        """
        # Stage 1
        sources = self._source_init.identify(self._dfg, self._fn_info)
        if not sources:
            logger.debug(
                "TaintEngine '%s': no taint sources found.",
                self._fn_info.signature,
            )
            return

        # Stage 2
        self._tainted_vars, self._origin_kind, self._chain = (
            self._propagator.propagate(self._dfg, sources)
        )

        # Stage 3a
        new_tainted, self._tainted_storage = self._storage_trk.track(
            dfg          = self._dfg,
            fn_info      = self._fn_info,
            tainted_vars = self._tainted_vars,
            origin_kind  = self._origin_kind,
            chain        = self._chain,
        )
        self._tainted_vars.update(new_tainted)

        # Stage 3b — re-propagate so downstream uses of storage-read
        # vars (e.g. y = x + fee where x reads tainted storage) are caught
        if new_tainted:
            self._re_propagate_from_storage(new_tainted)

        # Stage 4
        self._sanitized_vars = self._sanitizer.identify(self._cfg)

        # Stage 5
        raw_flows = self._sink_det.detect(
            dfg             = self._dfg,
            cfg             = self._cfg,
            fn_info         = self._fn_info,
            tainted_vars    = self._tainted_vars,
            origin_kind     = self._origin_kind,
            chain           = self._chain,
            tainted_storage = self._tainted_storage,
            sanitized_vars  = self._sanitized_vars,
        )

        self._flows = [
            f for f in raw_flows if f.confidence >= _MIN_CONFIDENCE
        ]

    def _re_propagate_from_storage(self, new_tainted: Set[str]) -> None:
        """
        Re-run propagation starting from variables tainted via storage reads.

        Merges extra results into self._tainted_vars / _origin_kind / _chain.
        Builds extended chains:
            chain[y] = chain[x] + [(y, cfg_nid)]
        where x is the storage-read variable that feeds y.

        Does not overwrite richer chains already present.
        """
        storage_sources = {
            v: TaintSourceKind.STORAGE_READ for v in new_tainted
        }
        extra_tainted, extra_origins, extra_chains = (
            self._propagator.propagate(self._dfg, storage_sources)
        )

        for v, extra_path in extra_chains.items():
            if v in self._tainted_vars:
                continue

            self._tainted_vars.add(v)
            self._origin_kind.setdefault(
                v, extra_origins.get(v, TaintSourceKind.STORAGE_READ)
            )

            merged_path = extra_path
            if extra_path:
                start_var, _ = extra_path[0]   # unpack (var, cfg_nid)
                prefix = self._chain.get(start_var)
                if prefix:
                    # Avoid duplicating the start variable entry
                    merged_path = prefix + extra_path[1:]

            self._chain.setdefault(v, merged_path)

    # ------------------------------------------------------------------
    # Public: query methods
    # ------------------------------------------------------------------

    def is_tainted(
        self,
        variable:    str,
        at_cfg_node: Optional[int] = None,
    ) -> bool:
        """
        Return True if variable is tainted.

        If at_cfg_node is given, uses CFG dominance to check whether
        taint DEFINITELY reaches that node on every execution path:
            cfg.dominates(def_node, at_cfg_node)
            → definition dominates at_cfg_node
            → taint guaranteed to reach it

        Correct in the presence of branches and loops, unlike a raw
        node_id <= at_cfg_node comparison.

        Fallback when dominators not computed: set-membership check.
        This avoids false positives from `return True` while still
        catching clearly tainted variables.
        """
        if variable not in self._tainted_vars:
            return False
        if at_cfg_node is None:
            return True

        # Dominance not computed — safe set-membership fallback
        if not self._cfg.dominators:
            return variable in self._tainted_vars

        for dfg_node in self._dfg.def_use_chains.get(variable, []):
            if self._cfg.dominates(dfg_node.cfg_node_id, at_cfg_node):
                return True

        return False

    def tainted_sinks(self) -> List[TaintFlow]:
        """Return all taint flows to all sinks."""
        return list(self._flows)

    def tainted_sinks_of_kind(
        self, sink_kind: TaintSinkKind
    ) -> List[TaintFlow]:
        """Return all flows to a specific sink category."""
        return [f for f in self._flows if f.sink_kind == sink_kind]

    def trace(self, variable: str) -> List[TaintNode]:
        """
        Return the propagation path that caused this variable to be
        tainted.

        Each TaintNode carries its accurate cfg_node_id from the chain
        tuples. Source entry has cfg_node_id=-1.

        Returns [] if variable is not tainted.
        """
        if variable not in self._tainted_vars:
            return []
        var_chain = self._chain.get(variable, [(variable, -1)])
        src_kind  = self._origin_kind.get(variable, _UNKNOWN_ORIGIN)
        return [
            TaintNode(
                variable    = v,
                cfg_node_id = nid,
                is_source   = (i == 0),
                source_kind = src_kind if i == 0 else None,
            )
            for i, (v, nid) in enumerate(var_chain)
        ]

    def tainted_variables(self) -> Set[str]:
        """Return the full set of tainted variable names."""
        return set(self._tainted_vars)

    def tainted_storage_slots(self) -> Set[str]:
        """Return the set of state variable names that are tainted."""
        return set(self._tainted_storage)

    def source_kind(self, variable: str) -> Optional[TaintSourceKind]:
        """Return the originating taint source kind for a variable."""
        return self._origin_kind.get(variable)

    def is_sanitized(self, variable: str) -> bool:
        """True if variable appears in a sanitizer check."""
        return variable in self._sanitized_vars


# ---------------------------------------------------------------------------
# TaintEngineFactory
# ---------------------------------------------------------------------------


class TaintEngineFactory:
    """
    Builds TaintEngine instances for all functions in a contract.

    Detectors call build_for_contract() once and receive a pre-built
    Dict[function_sig → TaintEngine]. They then call engine.run() only
    on the functions they actually need to analyse.

    Usage
    -----
        factory = TaintEngineFactory()
        engines = factory.build_for_contract(
            contract_name = "Bank",
            fn_infos      = contract.functions,
            cfg_result    = cfg_results["Bank"],
        )
        engine = engines.get("withdraw(uint256)")
        if engine:
            result = engine.run()
    """

    def build_for_contract(
        self,
        contract_name: str,
        fn_infos:      Tuple[FunctionInfo, ...],
        cfg_result:    CFGAnalysisResult,
    ) -> Dict[str, TaintEngine]:
        """
        Build one TaintEngine per function.

        Functions whose CFG/DFG had build errors receive a no-op engine
        with empty graphs — they respond to all queries safely and
        return empty TaintResult objects.
        """
        engines: Dict[str, TaintEngine] = {}

        for fn_info in fn_infos:
            sig = fn_info.signature
            try:
                fg = cfg_result.get(sig)
                if fg is None or fg.build_error:
                    logger.debug(
                        "TaintEngineFactory: no valid graphs for '%s.%s'"
                        " — empty engine inserted.",
                        contract_name, fn_info.name,
                    )
                    engines[sig] = TaintEngine(
                        cfg     = CFGGraph(fn_info.name, sig),
                        dfg     = DFGGraph(fn_info.name, sig),
                        fn_info = fn_info,
                    )
                else:
                    engines[sig] = TaintEngine(
                        cfg     = fg.cfg,
                        dfg     = fg.dfg,
                        fn_info = fn_info,
                    )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "TaintEngineFactory: failed for '%s.%s': %s",
                    contract_name, fn_info.name, exc,
                )

        logger.debug(
            "TaintEngineFactory: %d engines built for '%s'.",
            len(engines), contract_name,
        )
        return engines
