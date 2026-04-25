"""
core/cfg_builder.py

Control Flow Graph (CFG) and Data Flow Graph (DFG) construction layer.

Design rules:
 1. Slither node objects (snode) are READ during CFG construction
    inside _CFGBuilder only. All data is extracted into plain Python
    types before the CFG node is stored. No Slither objects persist
    after CFG construction is complete.
 2. CFGNode stores ONLY normalised data — label (str), ir_stmts
    (List[str]), ir_ops (List[Any] of IR operations), ir_op_types
    (List[str] of IR class names). ir_ops are cleared after DFG build
    to free memory. ir_op_types are retained (plain strings, negligible
    memory cost, used by taint_engine for arithmetic detection).
 3. SequentialVersioner assigns linear version numbers. This is NOT
    full SSA. Full SSA requires dominance frontier + φ-node insertion
    + rename pass (~300 lines). Deferred to future ssa_builder.py.
 4. CFG sequential fallback fires ONLY when every node has both zero
    successors and zero predecessors (Slither gave no edge data).
 5. DFG variable extraction uses .name / .canonical_name only.
    Raw str(var) is never used — it produces garbage IR names.
 6. Duplicate DFG nodes prevented with per-IR seen_vars set.
 7. Edges stored as sets — no duplicate edges possible.
 8. ContractInfo / FunctionInfo models are never mutated.
 9. Every graph operation is wrapped defensively.
10. SequentialVersioner iterates in node_id order for deterministic
    reproducible output.
"""

from __future__ import annotations

import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from core.models import ContractInfo, FunctionInfo
from core.slither_wrapper import SlitherWrapper

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Slither IR types — imported ONCE at module level
# ---------------------------------------------------------------------------

try:
    from slither.slithir.operations import Assignment as _IR_Assignment  # type: ignore[import]
    from slither.slithir.operations import Index as _IR_Index            # type: ignore[import]
    from slither.slithir.operations import Member as _IR_Member          # type: ignore[import]
    _SLITHER_IR_AVAILABLE = True
    logger.debug("Slither IR types loaded for DFG builder.")
except Exception:  # noqa: BLE001
    _IR_Assignment = None  # type: ignore[assignment,misc]
    _IR_Index      = None  # type: ignore[assignment,misc]
    _IR_Member     = None  # type: ignore[assignment,misc]
    _SLITHER_IR_AVAILABLE = False
    logger.debug("Slither IR types unavailable — attribute fallback active.")


# ---------------------------------------------------------------------------
# CFGNode
# ---------------------------------------------------------------------------

class CFGNode:
    """
    A single node in the Control Flow Graph.

    No raw Slither objects persist here after CFG construction.
    ir_ops holds extracted IR operation objects used by _DFGBuilder
    and is cleared after DFG build to free memory.
    ir_op_types holds IR class name strings and is NEVER cleared —
    used by taint_engine for IR-type-based arithmetic sink detection.

    Attributes
    ----------
    node_id      : Unique integer ID within this function's CFG.
    label        : Human-readable node type ("EXPRESSION", "IF", …).
    ir_stmts     : String representations of SlithIR statements.
    ir_ops       : Extracted IR operation objects (cleared post-DFG).
    ir_op_types  : IR class name strings (e.g. "Assignment",
                   "BinaryOperation"). Never cleared.
    successors   : Set of node_ids this node flows into.
    predecessors : Set of node_ids that flow into this node.
    is_entry     : True for the function entry node.
    is_exit      : True for exit / return nodes.
    source_line  : Source line number (if available).
    """

    __slots__ = (
        "node_id",
        "label",
        "ir_stmts",
        "ir_ops",
        "ir_op_types",     # NEW: IR class name strings, never cleared
        "successors",
        "predecessors",
        "is_entry",
        "is_exit",
        "source_line",
    )

    def __init__(
        self,
        node_id:     int,
        label:       str,
        ir_stmts:    List[str],
        ir_ops:      List[Any],
        ir_op_types: Optional[List[str]] = None,  # NEW
        source_line: Optional[int]        = None,
        is_entry:    bool                 = False,
        is_exit:     bool                 = False,
    ) -> None:
        self.node_id     = node_id
        self.label       = label
        self.ir_stmts    = ir_stmts
        self.ir_ops      = ir_ops
        self.ir_op_types = ir_op_types or []       # NEW: always a list
        self.successors:   Set[int] = set()
        self.predecessors: Set[int] = set()
        self.is_entry    = is_entry
        self.is_exit     = is_exit
        self.source_line = source_line

    def __repr__(self) -> str:
        return (
            f"CFGNode(id={self.node_id}, label={self.label!r}, "
            f"succ={sorted(self.successors)}, line={self.source_line})"
        )


# ---------------------------------------------------------------------------
# DFGNode
# ---------------------------------------------------------------------------

class DFGNode:
    """
    A single node in the Data Flow Graph.

    Attributes
    ----------
    node_id       : Unique integer ID within this function's DFG.
    variable      : Variable name (qualified for state variables).
    is_definition : True if this is a write / assignment.
    is_use        : True if this is a read.
    cfg_node_id   : The CFG node this DFG node originates from.
    ir_index      : Index of the IR operation inside its CFG node.
                    -1 = unavailable. Used for intra-node ordering
                    in taint propagation.
    sequential_ver: Sequential version number (NOT full SSA).
                    -1 = not yet assigned.
    source_line   : Source line (if available).
    """

    __slots__ = (
        "node_id",
        "variable",
        "is_definition",
        "is_use",
        "cfg_node_id",
        "ir_index",        # index of IR op within CFG node
        "sequential_ver",
        "source_line",
    )

    def __init__(
        self,
        node_id:       int,
        variable:      str,
        is_definition: bool,
        is_use:        bool,
        cfg_node_id:   int,
        ir_index:      int           = -1,   # -1 = unavailable
        source_line:   Optional[int] = None,
    ) -> None:
        self.node_id        = node_id
        self.variable       = variable
        self.is_definition  = is_definition
        self.is_use         = is_use
        self.cfg_node_id    = cfg_node_id
        self.ir_index       = ir_index
        self.sequential_ver = -1
        self.source_line    = source_line

    def __repr__(self) -> str:
        kind = "DEF" if self.is_definition else "USE"
        return (
            f"DFGNode(id={self.node_id}, var={self.variable!r}, "
            f"kind={kind}, cfg={self.cfg_node_id}, "
            f"ir={self.ir_index}, ver={self.sequential_ver})"
        )


# ---------------------------------------------------------------------------
# CFGGraph
# ---------------------------------------------------------------------------

class CFGGraph:
    """
    Complete Control Flow Graph for one function.

    Edges are sets — no duplicate edges possible.
    """

    def __init__(self, function_name: str, function_sig: str) -> None:
        self.function_name = function_name
        self.function_sig  = function_sig
        self.nodes:      Dict[int, CFGNode]       = {}
        self.entry_id:   Optional[int]             = None
        self.exit_ids:   Set[int]                  = set()
        self.dominators: Dict[int, FrozenSet[int]] = {}
        self.idom:       Dict[int, Optional[int]]  = {}

    def add_node(self, node: CFGNode) -> None:
        self.nodes[node.node_id] = node
        if node.is_entry:
            self.entry_id = node.node_id
        if node.is_exit:
            self.exit_ids.add(node.node_id)

    def add_edge(self, from_id: int, to_id: int) -> None:
        if from_id not in self.nodes or to_id not in self.nodes:
            return
        self.nodes[from_id].successors.add(to_id)
        self.nodes[to_id].predecessors.add(from_id)

    def node_count(self) -> int:
        return len(self.nodes)

    def dominates(self, a: int, b: int) -> bool:
        """Return True if node a dominates node b."""
        return a in self.dominators.get(b, frozenset())

    def ordered_nodes(self) -> List[CFGNode]:
        """
        Return nodes in BFS order from entry.
        Unreachable nodes appended at the end in node_id order.
        """
        if self.entry_id is None or not self.nodes:
            return sorted(self.nodes.values(), key=lambda n: n.node_id)

        visited: List[int] = []
        queue = deque([self.entry_id])
        seen: Set[int] = set()

        while queue:
            nid = queue.popleft()
            if nid in seen:
                continue
            seen.add(nid)
            visited.append(nid)
            for succ in sorted(self.nodes[nid].successors):
                if succ not in seen:
                    queue.append(succ)

        for nid in sorted(self.nodes.keys()):
            if nid not in seen:
                visited.append(nid)

        return [self.nodes[nid] for nid in visited]

    def clear_ir_ops(self) -> None:
        """
        Clear ir_ops (Slither objects) from all nodes to free memory
        after DFG build. Call once DFGGraph has been constructed.

        ir_op_types (plain strings) are intentionally NOT cleared —
        they are used by taint_engine for arithmetic sink detection
        and carry negligible memory cost.
        """
        for node in self.nodes.values():
            node.ir_ops = []
        # ir_op_types deliberately retained

    def __repr__(self) -> str:
        return (
            f"CFGGraph(fn={self.function_name!r}, "
            f"nodes={self.node_count()}, entry={self.entry_id})"
        )


# ---------------------------------------------------------------------------
# DFGGraph
# ---------------------------------------------------------------------------

class DFGGraph:
    """
    Complete Data Flow Graph for one function.

    Attributes
    ----------
    function_name  : Name of the function.
    function_sig   : Full ABI signature.
    nodes          : Dict[node_id → DFGNode].
    def_use_chains : Dict[variable → List[DFGNode]].
    """

    def __init__(self, function_name: str, function_sig: str) -> None:
        self.function_name = function_name
        self.function_sig  = function_sig
        self.nodes:          Dict[int, DFGNode]         = {}
        self.def_use_chains: Dict[str, List[DFGNode]]   = defaultdict(list)
        self._next_id = 0

    def _new_id(self) -> int:
        nid = self._next_id
        self._next_id += 1
        return nid

    def add_node(self, node: DFGNode) -> None:
        self.nodes[node.node_id] = node
        self.def_use_chains[node.variable].append(node)

    def make_node(
        self,
        variable:      str,
        is_definition: bool,
        is_use:        bool,
        cfg_node_id:   int,
        ir_index:      int           = -1,   # NEW: IR position within CFG node
        source_line:   Optional[int] = None,
    ) -> DFGNode:
        node = DFGNode(
            node_id       = self._new_id(),
            variable      = variable,
            is_definition = is_definition,
            is_use        = is_use,
            cfg_node_id   = cfg_node_id,
            ir_index      = ir_index,         # NEW
            source_line   = source_line,
        )
        self.add_node(node)
        return node

    def node_count(self) -> int:
        return len(self.nodes)

    def definitions(self, variable: str) -> List[DFGNode]:
        return [n for n in self.def_use_chains.get(variable, []) if n.is_definition]

    def uses(self, variable: str) -> List[DFGNode]:
        return [n for n in self.def_use_chains.get(variable, []) if n.is_use]

    def __repr__(self) -> str:
        return (
            f"DFGGraph(fn={self.function_name!r}, "
            f"nodes={self.node_count()})"
        )


# ---------------------------------------------------------------------------
# Result containers
# ---------------------------------------------------------------------------

@dataclass
class FunctionGraphs:
    """All graph structures for a single function."""
    function_sig: str
    cfg:          CFGGraph
    dfg:          DFGGraph
    build_error:  Optional[str] = None


@dataclass
class CFGAnalysisResult:
    """All graph structures for a single contract."""
    contract_name:   str
    graphs:          Dict[str, FunctionGraphs] = field(default_factory=dict)
    total_cfg_nodes: int = 0
    total_dfg_nodes: int = 0

    def get(self, function_sig: str) -> Optional[FunctionGraphs]:
        return self.graphs.get(function_sig)


# ---------------------------------------------------------------------------
# Dominance computation
# ---------------------------------------------------------------------------

class DominanceComputer:
    """
    Computes dominator sets and immediate dominators for a CFGGraph.

    Algorithm: iterative dataflow (Cooper et al.)
        dom(entry) = {entry}
        dom(n)     = {n} ∪ (⋂ dom(p) for p ∈ predecessors(n))

    Complexity: O(N²) — acceptable for Solidity contract sizes.
    Results stored directly on the CFGGraph object.
    """

    def compute(self, cfg: CFGGraph) -> None:
        if cfg.entry_id is None or not cfg.nodes:
            return

        all_nodes = frozenset(cfg.nodes.keys())
        dom: Dict[int, FrozenSet[int]] = {
            nid: (frozenset([nid]) if nid == cfg.entry_id else all_nodes)
            for nid in cfg.nodes
        }

        ordered = cfg.ordered_nodes()
        changed = True

        while changed:
            changed = False
            for node in ordered:
                nid = node.node_id
                if nid == cfg.entry_id:
                    continue

                preds = node.predecessors
                if not preds:
                    new_dom = frozenset([nid])
                else:
                    pred_doms = [dom[p] for p in preds if p in dom]
                    if not pred_doms:
                        continue
                    intersection = pred_doms[0]
                    for pd in pred_doms[1:]:
                        intersection &= pd
                    new_dom = intersection | frozenset([nid])

                if new_dom != dom[nid]:
                    dom[nid] = new_dom
                    changed = True

        cfg.dominators = dom
        for nid in cfg.nodes:
            cfg.idom[nid] = self._find_idom(nid, dom)

        logger.debug(
            "Dominance computed: '%s' (%d nodes).",
            cfg.function_name, cfg.node_count(),
        )

    @staticmethod
    def _find_idom(
        nid: int,
        dom: Dict[int, FrozenSet[int]],
    ) -> Optional[int]:
        strict = dom[nid] - frozenset([nid])
        if not strict:
            return None
        for candidate in strict:
            if all(
                candidate in dom[other]
                for other in strict
                if other != candidate
            ):
                return candidate
        return None


# ---------------------------------------------------------------------------
# Sequential versioner — NOT full SSA
# ---------------------------------------------------------------------------

class SequentialVersioner:
    """
    Assigns sequential version numbers to DFGNode entries.

    !! THIS IS NOT FULL SSA !!

    Full SSA requires:
      1. Dominance frontier computation
      2. φ-node insertion at every join point
      3. Complete rename pass
    That is approximately 300 additional lines and is deferred to
    a future ssa_builder.py module.

    What this DOES provide:
      - Each variable definition gets an incrementing version number
      - Each use gets the version of the most recent prior definition
      - Iteration is in strict node_id order for deterministic output
      - Correct for straight-line code
      - Approximate (not path-aware) at branch join points

    Detectors that require branch-aware analysis should use
    CFGGraph.dominates() and CFGGraph.dominators directly.
    """

    def version(self, dfg: DFGGraph) -> None:
        """
        Assign sequential_ver to all DFGNodes.
        Iterates in node_id order for deterministic reproducible output.
        """
        counter: Dict[str, int] = defaultdict(int)

        for node in sorted(dfg.nodes.values(), key=lambda n: n.node_id):
            var = node.variable
            if node.is_definition:
                node.sequential_ver = counter[var]
                counter[var] += 1
            else:
                node.sequential_ver = max(counter[var] - 1, 0)

        logger.debug(
            "Sequential versioning complete: '%s' (%d nodes).",
            dfg.function_name, dfg.node_count(),
        )


# ---------------------------------------------------------------------------
# Internal: _CFGBuilder
# ---------------------------------------------------------------------------

class _CFGBuilder:
    """
    Builds a CFGGraph for one function from Slither IR node list.

    Slither node objects (snode) are read here during build and then
    discarded. All data is extracted into plain Python types before
    CFGNode is stored. After this builder returns, no Slither objects
    persist anywhere in the graph.

    Three-pass construction:
      Pass 1 — create CFGNodes (extract and discard Slither objects)
      Pass 2 — add directed edges from node.sons
      Pass 3 — sequential fallback ONLY when every node has zero
               successors AND zero predecessors
    """

    def build(
        self,
        fn_info:       FunctionInfo,
        slither_nodes: List[Any],
        wrapper:       SlitherWrapper,
    ) -> CFGGraph:
        cfg = CFGGraph(
            function_name = fn_info.name,
            function_sig  = fn_info.signature,
        )

        if not slither_nodes:
            return cfg

        sid_to_nid: Dict[int, int] = {}

        # ── Pass 1: create CFGNodes ──────────────────────────────────
        for idx, snode in enumerate(slither_nodes):
            label       = self._extract_label(snode)
            ir_stmts    = self._extract_ir_stmts(snode)
            ir_ops      = self._extract_ir_ops(snode)
            ir_op_types = self._extract_ir_op_types(snode)   # NEW
            _, start_line, _ = wrapper.get_source_mapping(snode)

            is_entry = (idx == 0)
            is_exit  = self._has_no_successors(snode)

            cfg_node = CFGNode(
                node_id     = idx,
                label       = label,
                ir_stmts    = ir_stmts,
                ir_ops      = ir_ops,
                ir_op_types = ir_op_types,   # NEW
                source_line = start_line,
                is_entry    = is_entry,
                is_exit     = is_exit,
            )
            cfg.add_node(cfg_node)
            sid_to_nid[id(snode)] = idx

        # ── Pass 2: add edges from Slither node.sons ─────────────────
        for idx, snode in enumerate(slither_nodes):
            try:
                for succ_snode in (getattr(snode, "sons", None) or []):
                    succ_nid = sid_to_nid.get(id(succ_snode))
                    if succ_nid is not None:
                        cfg.add_edge(idx, succ_nid)
            except Exception:  # noqa: BLE001
                pass

        # ── Pass 3: sequential fallback ──────────────────────────────
        # ONLY fires when Slither provided NO edge data at all.
        # Checks both successors == 0 AND predecessors == 0 on every
        # node to avoid corrupting partial CFGs.
        if self._all_nodes_isolated(cfg) and len(slither_nodes) > 1:
            for idx in range(len(slither_nodes) - 1):
                cfg.add_edge(idx, idx + 1)
            logger.debug(
                "CFG '%s': all nodes isolated — sequential fallback applied.",
                fn_info.name,
            )

        return cfg

    @staticmethod
    def _all_nodes_isolated(cfg: CFGGraph) -> bool:
        return all(
            len(n.successors) == 0 and len(n.predecessors) == 0
            for n in cfg.nodes.values()
        )

    @staticmethod
    def _extract_label(snode: Any) -> str:
        for attr in ("type", "node_type", "_node_type"):
            try:
                val = getattr(snode, attr, None)
                if val is not None:
                    return str(val).replace("NODE_TYPE_", "")
            except Exception:  # noqa: BLE001
                pass
        return "UNKNOWN"

    @staticmethod
    def _extract_ir_stmts(snode: Any) -> List[str]:
        stmts: List[str] = []
        try:
            for ir in (getattr(snode, "irs", None) or []):
                stmts.append(str(ir))
        except Exception:  # noqa: BLE001
            pass
        return stmts

    @staticmethod
    def _extract_ir_ops(snode: Any) -> List[Any]:
        """
        Extract raw IR operation objects. Stored temporarily in
        CFGNode.ir_ops for _DFGBuilder and cleared afterwards.
        """
        try:
            return list(getattr(snode, "irs", None) or [])
        except Exception:  # noqa: BLE001
            return []

    @staticmethod
    def _extract_ir_op_types(snode: Any) -> List[str]:
        """
        Extract IR operation class names for a Slither node.
        Plain strings only — no Slither objects escape this method.
        Used by taint_engine for IR-type-based arithmetic detection.
        NOT cleared by clear_ir_ops() — negligible memory cost.

        Examples: "Assignment", "HighLevelCall", "BinaryOperation",
                  "LowLevelCall", "LibraryCall", "Transfer", "Send"
        """
        try:
            return [
                type(ir).__name__
                for ir in (getattr(snode, "irs", None) or [])
            ]
        except Exception:  # noqa: BLE001
            return []

    @staticmethod
    def _has_no_successors(snode: Any) -> bool:
        """
        Primary exit detection — node is an exit if Slither reports
        zero successors. More reliable than label heuristics.
        """
        try:
            sons = getattr(snode, "sons", None)
            return sons is not None and len(sons) == 0
        except Exception:  # noqa: BLE001
            return False


# ---------------------------------------------------------------------------
# Internal: _DFGBuilder
# ---------------------------------------------------------------------------

class _DFGBuilder:
    """
    Derives a DFGGraph from a completed CFGGraph.

    Scans CFGNode.ir_ops (already extracted from Slither) and records
    variable definitions and uses. Each DFGNode now carries ir_index —
    the position of its IR operation within its CFG node — enabling
    intra-node ordering in taint propagation.

    Variable name rules:
      - Uses .name and .canonical_name only
      - Empty string names are rejected
      - Raw str(var) is never used

    Duplicate prevention:
      - seen_vars: Set[Tuple[str, str]] per IR operation
      - prevents same (variable, kind) pair from same IR
    """

    def build(self, cfg: CFGGraph, fn_info: FunctionInfo) -> DFGGraph:
        dfg = DFGGraph(
            function_name = fn_info.name,
            function_sig  = fn_info.signature,
        )

        for cfg_node in cfg.ordered_nodes():
            for ir_idx, ir in enumerate(cfg_node.ir_ops):   # NEW: enumerate
                try:
                    self._process_ir(
                        ir,
                        cfg_node.node_id,
                        ir_idx,                              # NEW: pass index
                        cfg_node.source_line,
                        dfg,
                    )
                except Exception:  # noqa: BLE001
                    pass

        return dfg

    def _process_ir(
        self,
        ir:          Any,
        cfg_node_id: int,
        ir_index:    int,            # NEW: IR position within CFG node
        source_line: Optional[int],
        dfg:         DFGGraph,
    ) -> None:
        seen_vars: Set[Tuple[str, str]] = set()

        def _register(var_name: str, is_def: bool) -> None:
            if not var_name:             # rejects None AND empty string
                return
            kind = "DEF" if is_def else "USE"
            key  = (var_name, kind)
            if key in seen_vars:
                return
            seen_vars.add(key)
            dfg.make_node(
                variable      = var_name,
                is_definition = is_def,
                is_use        = not is_def,
                cfg_node_id   = cfg_node_id,
                ir_index      = ir_index,    # NEW: propagated into DFGNode
                source_line   = source_line,
            )

        # Strategy 1 — isinstance on known IR types
        if _SLITHER_IR_AVAILABLE and _IR_Assignment:
            if isinstance(ir, _IR_Assignment):
                _register(self._var_name(getattr(ir, "lvalue", None)), True)
                _register(self._var_name(getattr(ir, "rvalue", None)), False)
                return

        # Strategy 2 — attribute inspection
        lval = getattr(ir, "lvalue", None)
        if lval is not None:
            _register(self._var_name(lval), True)

        for attr in ("rvalue", "read", "variable_left", "variable_right"):
            val = getattr(ir, attr, None)
            if val is None:
                continue
            items = val if isinstance(val, (list, tuple)) else [val]
            for item in items:
                _register(self._var_name(item), False)

    @staticmethod
    def _var_name(var: Any) -> str:
        """
        Extract a clean variable name from a Slither IR variable.

        Uses .name then .canonical_name.
        Rejects empty strings and None.
        Never uses raw str(var).
        """
        if var is None:
            return ""
        try:
            name = getattr(var, "name", None)
            if name:
                return str(name).strip()
            canon = getattr(var, "canonical_name", None)
            if canon:
                return str(canon).strip()
        except Exception:  # noqa: BLE001
            pass
        return ""


# ---------------------------------------------------------------------------
# CFGAnalyser — public entry point
# ---------------------------------------------------------------------------

class CFGAnalyser:
    """
    Orchestrates CFG + DFG construction for all functions in a contract.

    Usage
    -----
        analyser = CFGAnalyser(wrapper)
        results  = analyser.analyse(contracts)
        # results → Dict[contract_name → CFGAnalysisResult]

    Pipeline per function:
      1. Retrieve Slither IR nodes via wrapper
      2. Build CFGGraph        (_CFGBuilder)
      3. Compute dominance     (DominanceComputer)
      4. Build DFGGraph        (_DFGBuilder)
      5. Clear ir_ops          (memory; ir_op_types retained)
      6. Sequential versioning (SequentialVersioner)
    """

    def __init__(self, wrapper: SlitherWrapper) -> None:
        self._wrapper   = wrapper
        self._cfg_bld   = _CFGBuilder()
        self._dfg_bld   = _DFGBuilder()
        self._dom       = DominanceComputer()
        self._versioner = SequentialVersioner()

    def analyse(
        self,
        contracts: List[ContractInfo],
    ) -> Dict[str, CFGAnalysisResult]:
        results: Dict[str, CFGAnalysisResult] = {}

        for contract in contracts:
            result = self._analyse_contract(contract)
            results[contract.name] = result
            logger.debug(
                "CFG analysis done: '%s' — %d fns, "
                "%d CFG nodes, %d DFG nodes.",
                contract.name,
                len(result.graphs),
                result.total_cfg_nodes,
                result.total_dfg_nodes,
            )

        return results

    def _analyse_contract(self, contract: ContractInfo) -> CFGAnalysisResult:
        result = CFGAnalysisResult(contract_name=contract.name)

        slither_contract = self._wrapper.get_contract_by_name(contract.name)
        if slither_contract is None:
            logger.warning(
                "CFGAnalyser: Slither contract '%s' not found — skipping.",
                contract.name,
            )
            return result

        for fn_info in contract.functions:
            try:
                fg = self._analyse_function(fn_info, slither_contract)
                result.graphs[fn_info.signature] = fg
                result.total_cfg_nodes += fg.cfg.node_count()
                result.total_dfg_nodes += fg.dfg.node_count()
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "CFGAnalyser: failed for '%s.%s': %s",
                    contract.name, fn_info.name, exc,
                )
                result.graphs[fn_info.signature] = FunctionGraphs(
                    function_sig = fn_info.signature,
                    cfg          = CFGGraph(fn_info.name, fn_info.signature),
                    dfg          = DFGGraph(fn_info.name, fn_info.signature),
                    build_error  = str(exc),
                )

        return result

    def _analyse_function(
        self,
        fn_info:          FunctionInfo,
        slither_contract: Any,
    ) -> FunctionGraphs:
        slither_fn = self._wrapper.get_function_by_signature(
            slither_contract, fn_info.signature
        )
        slither_nodes = (
            self._wrapper.get_cfg_nodes(slither_fn)
            if slither_fn is not None
            else []
        )

        # Step 1 — CFG (Slither nodes read and discarded here)
        cfg = self._cfg_bld.build(
            fn_info       = fn_info,
            slither_nodes = slither_nodes,
            wrapper       = self._wrapper,
        )

        # Step 2 — Dominance
        self._dom.compute(cfg)

        # Step 3 — DFG
        dfg = self._dfg_bld.build(cfg=cfg, fn_info=fn_info)

        # Step 4 — Free ir_ops memory now that DFG is built
        #          ir_op_types are intentionally retained
        cfg.clear_ir_ops()

        # Step 5 — Sequential versioning
        self._versioner.version(dfg)

        logger.debug(
            "Function '%s': CFG=%d nodes, DFG=%d nodes.",
            fn_info.name, cfg.node_count(), dfg.node_count(),
        )

        return FunctionGraphs(
            function_sig = fn_info.signature,
            cfg          = cfg,
            dfg          = dfg,
        )
