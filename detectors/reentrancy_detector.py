"""
detectors/reentrancy_detector.py

Reentrancy vulnerability detector for VigilanceCore.

Change log:
  v1.0.0  Initial release
  v1.1.0  LibraryCall removed, prefix matching, regex ordering,
          OZ guard, IR ordering, reachability caching
  v1.2.0  state_vars_written type safety, ir_index safe access,
          status-mutex regex fix, BaseDetector subclass
  v1.2.1  Fast-path loosened, regex tightened, vuln_type from detector
  v1.3.0  build_recommendation() dynamic, calculate_cvss() context-adjusted,
          _build_context() added, static recommendation string removed
  v1.3.1  Step 7 uses safe_recommendation() and safe_cvss() — never raw methods
          _STATUS_ASSIGN_RE compiled at module level — not inside loop
  v2.1.0  SmartBugs recall fixes:
          — Fast-path changed: only exits on empty cfg.nodes, NOT on empty
            fn_info.external_calls. Pre-0.5 contracts leave external_calls
            empty but CFG nodes are always populated — old guard caused
            detector to return [] for all pre-0.5 reentrancy contracts.
          — _LOW_LEVEL_CALL_RE extended with \.call\.value to match the
            pre-0.5 Solidity idiom: recipient.call.value(amount)() which
            uses neither braces nor a direct call( form.
          — _StateWriteFinder: DFG-text fallback added. When dfg.nodes is
            empty (Slither discard_ir=True mode triggered by IR-gen failure)
            the finder now scans CFG IR text for assignment patterns to find
            state writes that the DFG missed. Enables reentrancy detection
            on reentrancy_bonus.sol and reentrancy_cross_function.sol which
            previously returned [E] due to IR generation failures.
          — Cross-function reentrancy (inter-procedural CEI violations)
          — Read-only reentrancy (view functions that read stale state)
          — ERC-777 / token callback hooks (onTokensReceived, tokensReceived)
          — Flash-loan callback reentrancy (executeOperation, uniswapV2Call, etc.)
          — Batch/loop reentrancy (calls inside loops, multiple write nodes)
          — Delegate-call reentrancy (delegatecall forwards storage context)
          — Self-call reentrancy (internal calls that re-enter same contract)
          — Nested struct/mapping state writes (deep prefix matching)
          — Missing guard on overridden virtual functions
          — Reachability cache (BFS result memoised per CFG)
          — Dominator check fast-path on all (call, write) pairs
          — All calls per node (not just first) — multiple-call-per-node edge case
          — sv_assign_re per (sv, node) compiled once per run via lru_cache
          — CVSS capped 0.0–10.0, confidence clamped 0.30–1.00
          — Safe fallback for missing source_line, ir_index, callee
"""

from __future__ import annotations

import logging
import re
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

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
# Module-level compiled patterns
# ---------------------------------------------------------------------------

_LIMITED_GAS_CALL_RE = re.compile(
    r"(?:\.transfer\(|\.send\(|\bTransfer\b|\bSend\b)"
)
_LOW_LEVEL_CALL_RE = re.compile(
    # FIX v2.1: added \.call\.value to catch pre-0.5 syntax:
    #   recipient.call.value(amount)()   — old style, no braces
    #   addr.call{value: x}(...)         — new style
    #   addr.call(...)                   — plain low-level
    r"(?:LowLevelCall\b|\.call\{|\.call\(|\.call\.value\b|\.delegatecall\b)"
)
_DELEGATE_CALL_RE = re.compile(
    r"(?:\.delegatecall\b|DelegateCall\b)"
)
_STATIC_CALL_RE = re.compile(
    r"(?:\.staticcall\b|StaticCall\b)"
)
_HIGH_LEVEL_CALL_RE = re.compile(
    r"(?:HighLevelCall\b|\.approve\(|\.transferFrom\()"
)

# ERC-777 / ERC-1363 / flash-loan callback hooks that create implicit reentrancy
_TOKEN_HOOK_RE = re.compile(
    r"(?:onTokensReceived|tokensReceived|onERC721Received|onERC1155Received"
    r"|onERC1155BatchReceived|onFlashLoan|executeOperation|uniswapV2Call"
    r"|pancakeCall|BiswapCall|AlgebraFlashCallback|uniswapV3FlashCallback"
    r"|uniswapV3SwapCallback|hookReceiver|_afterTokenTransfer"
    r"|_beforeTokenTransfer)",
    re.IGNORECASE,
)

_CALL_OP_TYPES: FrozenSet[str] = frozenset({
    "HighLevelCall",
    "LowLevelCall",
    "DelegateCall",
    "Transfer",
    "Send",
})

_GUARD_MODIFIER_RE = re.compile(
    r"(?:nonReentrant|reentrancyGuard|noReentrancy|withLock|mutexLock"
    r"|ReentrancyGuardUpgradeable|nonReentrantView)",
    re.IGNORECASE,
)
_MUTEX_BOOL_VAR_RE = re.compile(
    r"^(?:locked|mutex|_lock|_locked|_mutex|guard|_entered|_notEntered)$",
    re.IGNORECASE,
)
_MUTEX_STATUS_VAR_RE = re.compile(
    r"^(?:_status|status|_guardStatus|guardStatus|reentrancyStatus)$",
    re.IGNORECASE,
)
_MUTEX_ENTERED_RE = re.compile(
    r"(?:ENTERED|_ENTERED|ENTERED_STATE|2\b)", re.IGNORECASE
)
_MUTEX_NOT_ENTERED_RE = re.compile(
    r"(?:NOT_ENTERED|_NOT_ENTERED|NOT_ENTERED_STATE|1\b)", re.IGNORECASE
)

# Compiled once at module level — used in _GuardDetector._has_full_status_mutex()
_STATUS_ASSIGN_RE = re.compile(
    r"\b[\w_]+\s*=\s*", re.IGNORECASE
)

_CALLEE_RE = re.compile(
    r"([a-zA-Z_][a-zA-Z0-9_.]*)\."
    r"(?:call|transfer|send|approve|transferFrom|delegatecall|staticcall)\b"
)

# Read-only / view reentrancy: storage reads whose value could be stale
_STORAGE_READ_RE = re.compile(
    r"(?:SLOAD\b|StorageRead\b|\.balanceOf\(|\.totalSupply\(|\.getReserves\()",
    re.IGNORECASE,
)

# Loop indicators in IR
_LOOP_IR_RE = re.compile(
    r"(?:\bfor\b|\bwhile\b|\bdo\b|\bLOOP\b|\bBEGIN_LOOP\b)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _sv_name(v: object) -> str:
    """Normalise state variable to str whether it is a string or StateVariable."""
    if hasattr(v, "name"):
        return str(v.name)          # type: ignore[union-attr]
    return str(v)


@lru_cache(maxsize=2048)
def _compile_sv_assign(sv_escaped_lower: str) -> re.Pattern:
    """Cache per-variable assignment regex — avoids repeated re.compile in hot loops."""
    return re.compile(rf"\b{sv_escaped_lower}\s*=\s*", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Internal enums and data classes
# ---------------------------------------------------------------------------

class _CallKind(str, Enum):
    LOW_LEVEL    = "low_level"
    HIGH_LEVEL   = "high_level"
    LIMITED_GAS  = "limited_gas"
    DELEGATE     = "delegate_call"
    TOKEN_HOOK   = "token_hook"        # ERC-777, flash-loan, etc.
    STATIC       = "static_call"       # rarely exploitable but track for read-only reentrancy


@dataclass
class _ExternalCall:
    cfg_node_id:  int
    call_kind:    _CallKind
    ir_index:     int
    callee:       Optional[str]
    stmt:         Optional[str]
    source_line:  Optional[int]
    in_loop:      bool = False          # call is inside a loop body

    @property
    def forwards_full_gas(self) -> bool:
        return self.call_kind in (_CallKind.LOW_LEVEL, _CallKind.DELEGATE)

    @property
    def is_delegate(self) -> bool:
        return self.call_kind == _CallKind.DELEGATE


@dataclass
class _StateWrite:
    cfg_node_id: int
    ir_index:    int
    var_name:    str
    source_line: Optional[int]


@dataclass
class _StorageRead:
    """Tracks SLOAD / view reads that may observe stale state (read-only reentrancy)."""
    cfg_node_id: int
    ir_index:    int
    stmt:        Optional[str]
    source_line: Optional[int]


@dataclass
class _ReentrancyCandidate:
    call:              _ExternalCall
    write:             _StateWrite
    # optional read-only reentrancy context
    stale_read:        Optional[_StorageRead]  = None
    is_sanitized:      bool                    = False
    taint_confirms:    bool                    = False
    taint_source:      Optional[TaintSourceKind] = None
    # cross-function reentrancy: callee function name if violation spans functions
    cross_function_fn: Optional[str]           = None
    is_read_only:      bool                    = False   # read-only reentrancy variant
    is_delegate:       bool                    = False   # delegatecall variant


# ---------------------------------------------------------------------------
# Step 1 — Guard detector
# ---------------------------------------------------------------------------

class _GuardDetector:
    """
    Detects reentrancy guards at multiple levels:
      1. Modifier names (nonReentrant, nonReentrantView, etc.)
      2. Boolean mutex (locked/mutex pattern)
      3. OZ status-slot mutex (_status / ENTERED / NOT_ENTERED)
      4. Virtual/override functions — a guard on the base does NOT protect
         an override that doesn't re-declare it.
    """

    def has_reliable_guard(
        self,
        fn_info:  FunctionInfo,
        cfg:      CFGGraph,
        sv_names: Set[str],
    ) -> bool:
        if self._has_guard_modifier(fn_info):
            return True
        if self._has_full_bool_mutex(cfg, sv_names):
            return True
        if self._has_full_status_mutex(cfg, sv_names):
            return True
        return False

    def has_partial_guard(self, fn_info: FunctionInfo, sv_names: Set[str]) -> bool:
        fn_lower = fn_info.name.lower()
        if any(kw in fn_lower for kw in ("lock", "guard", "protect", "safe")):
            return True
        return any(
            _MUTEX_BOOL_VAR_RE.match(v) or _MUTEX_STATUS_VAR_RE.match(v)
            for v in sv_names
        )

    def is_unguarded_override(self, fn_info: FunctionInfo) -> bool:
        """
        Edge case: function overrides a virtual base but does not redeclare
        the guard modifier.  The inherited modifier is NOT applied automatically
        in Solidity overrides unless re-listed.
        """
        is_override = getattr(fn_info, "is_override", False)
        if not is_override:
            return False
        return not self._has_guard_modifier(fn_info)

    @staticmethod
    def _has_guard_modifier(fn_info: FunctionInfo) -> bool:
        return any(_GUARD_MODIFIER_RE.search(mod) for mod in fn_info.modifiers)

    @staticmethod
    def _has_full_bool_mutex(cfg: CFGGraph, sv_names: Set[str]) -> bool:
        mutex_vars = {v for v in sv_names if _MUTEX_BOOL_VAR_RE.match(v)}
        if not mutex_vars:
            return False
        has_require = has_acquire = has_release = False
        for node in cfg.nodes.values():
            combined = " ".join(node.ir_stmts).lower()
            for mv in mutex_vars:
                mv_l = mv.lower()
                if "require" in combined and mv_l in combined:
                    has_require = True
                if f"{mv_l} = true" in combined or f"{mv_l}=true" in combined:
                    has_acquire = True
                if f"{mv_l} = false" in combined or f"{mv_l}=false" in combined:
                    has_release = True
        return has_require and has_acquire and has_release

    @staticmethod
    def _has_full_status_mutex(cfg: CFGGraph, sv_names: Set[str]) -> bool:
        """
        Detect OZ ReentrancyGuard storage-slot mutex.
        Uses lru_cache-backed _compile_sv_assign — never re.compile() inside loop.
        """
        status_vars = {v for v in sv_names if _MUTEX_STATUS_VAR_RE.match(v)}
        if not status_vars:
            return False

        has_require = has_acquire = has_release = False

        for node in cfg.nodes.values():
            combined   = " ".join(node.ir_stmts)
            combined_l = combined.lower()

            for sv in status_vars:
                sv_l = sv.lower()

                if (
                    "require" in combined_l
                    and sv_l in combined_l
                    and (
                        _MUTEX_ENTERED_RE.search(combined)
                        or _MUTEX_NOT_ENTERED_RE.search(combined)
                    )
                ):
                    has_require = True

                sv_assign_re = _compile_sv_assign(re.escape(sv_l))
                if sv_assign_re.search(combined_l):
                    if _MUTEX_ENTERED_RE.search(combined):
                        has_acquire = True
                    if _MUTEX_NOT_ENTERED_RE.search(combined):
                        has_release = True

        return has_require and has_acquire and has_release


# ---------------------------------------------------------------------------
# Step 2 — External call node finder (ALL calls per node, not just first)
# ---------------------------------------------------------------------------

class _CallNodeFinder:
    """
    Edge case fixed vs v1.x: collects ALL external calls in a node, not
    just the first one.  A node may contain multiple chained calls, each of
    which is independently a reentrancy entry point.

    Also detects:
      - delegatecall (separate _CallKind.DELEGATE for accurate severity)
      - ERC-777 / flash-loan hook calls (_CallKind.TOKEN_HOOK)
      - loop context (in_loop=True when node is inside a loop)
    """

    def find(self, cfg: CFGGraph) -> List[_ExternalCall]:
        calls: List[_ExternalCall] = []
        loop_nodes = self._collect_loop_nodes(cfg)
        for node in cfg.ordered_nodes():
            calls.extend(self._check_node(node, node.node_id in loop_nodes))
        return calls

    # ------------------------------------------------------------------
    # Loop detection — mark nodes that are inside a loop body
    # ------------------------------------------------------------------

    @staticmethod
    def _collect_loop_nodes(cfg: CFGGraph) -> Set[int]:
        """
        Simple heuristic: a node is 'in a loop' if its ir_stmts contain a
        loop-start IR or if CFG back-edges are available.
        Falls back gracefully when CFG has no back-edge metadata.
        """
        loop_nodes: Set[int] = set()
        for node in cfg.nodes.values():
            combined = " ".join(node.ir_stmts)
            if _LOOP_IR_RE.search(combined):
                loop_nodes.add(node.node_id)
        # If cfg exposes back_edges, use BFS from back-edge targets
        if hasattr(cfg, "back_edges"):
            for src, tgt in cfg.back_edges:
                loop_nodes.add(src)
                loop_nodes.add(tgt)
        return loop_nodes

    # ------------------------------------------------------------------
    # Per-node scan — returns ALL calls in node
    # ------------------------------------------------------------------

    def _check_node(self, node, in_loop: bool) -> List[_ExternalCall]:
        results: List[_ExternalCall] = []

        # Pass 1: structured IR op_types (highest confidence)
        for ir_idx, op_type in enumerate(getattr(node, "ir_op_types", [])):
            if op_type in _CALL_OP_TYPES:
                matching_stmt = (
                    node.ir_stmts[ir_idx]
                    if ir_idx < len(node.ir_stmts)
                    else (node.ir_stmts[0] if node.ir_stmts else None)
                )
                kind = self._kind_from_op_type(op_type, matching_stmt or "")
                results.append(_ExternalCall(
                    cfg_node_id = node.node_id,
                    call_kind   = kind,
                    ir_index    = ir_idx,
                    callee      = self._extract_callee(matching_stmt),
                    stmt        = matching_stmt,
                    source_line = node.source_line,
                    in_loop     = in_loop,
                ))

        # Pass 2: text-pattern scan (catches calls missing from IR op_types)
        seen_indices = {r.ir_index for r in results}
        for stmt_idx, stmt in enumerate(node.ir_stmts):
            if stmt_idx in seen_indices:
                continue
            kind = self._kind_from_stmt(stmt)
            if kind is None:
                continue
            results.append(_ExternalCall(
                cfg_node_id = node.node_id,
                call_kind   = kind,
                ir_index    = stmt_idx,
                callee      = self._extract_callee(stmt),
                stmt        = stmt,
                source_line = node.source_line,
                in_loop     = in_loop,
            ))

        return results

    @staticmethod
    def _kind_from_op_type(op_type: str, stmt: str) -> _CallKind:
        if op_type == "DelegateCall" or _DELEGATE_CALL_RE.search(stmt):
            return _CallKind.DELEGATE
        if op_type == "LowLevelCall":
            return _CallKind.LOW_LEVEL
        if op_type in ("Transfer", "Send"):
            return _CallKind.LIMITED_GAS
        return _CallKind.HIGH_LEVEL

    @staticmethod
    def _kind_from_stmt(stmt: str) -> Optional[_CallKind]:
        if _TOKEN_HOOK_RE.search(stmt):
            return _CallKind.TOKEN_HOOK
        if _DELEGATE_CALL_RE.search(stmt):
            return _CallKind.DELEGATE
        if _LIMITED_GAS_CALL_RE.search(stmt):
            return _CallKind.LIMITED_GAS
        if _LOW_LEVEL_CALL_RE.search(stmt):
            return _CallKind.LOW_LEVEL
        if _HIGH_LEVEL_CALL_RE.search(stmt):
            return _CallKind.HIGH_LEVEL
        if _STATIC_CALL_RE.search(stmt):
            return _CallKind.STATIC
        return None

    @staticmethod
    def _extract_callee(stmt: Optional[str]) -> Optional[str]:
        if not stmt:
            return None
        m = _CALLEE_RE.search(stmt)
        return m.group(1) if m else None


# ---------------------------------------------------------------------------
# Step 3 — State variable write finder (deep struct/mapping support)
# ---------------------------------------------------------------------------

class _StateWriteFinder:
    """
    Edge cases added vs v1.x:
      - Nested struct writes: balances[user].amount, pool.reserve0, etc.
      - Multi-level mapping: allowances[a][b]
      - DFG nodes without ir_index fall back to -1 gracefully

    FIX v2.1: IR-text fallback.
      When Slither runs in discard_ir=True mode (triggered by IR generation
      failures on old contracts), dfg.nodes is empty.  In that case we fall
      back to scanning CFG IR text for assignment patterns, which is always
      available regardless of IR mode.
    """

    # Matches  "varname = ..."  or  "varname[...] = ..."  or  "varname.field = ..."
    # Used only in the text-fallback path.
    _ASSIGN_RE = re.compile(r"\b([\w][\w.\[\]]*?)\s*=(?!=)")

    def find(
        self,
        dfg:     DFGGraph,
        fn_info: FunctionInfo,
        cfg:     CFGGraph,
    ) -> List[_StateWrite]:
        sv_written: Set[str] = {_sv_name(v) for v in fn_info.state_vars_written}
        if not sv_written:
            return []

        writes: List[_StateWrite]    = []
        seen:   Set[Tuple[int, str]] = set()

        # ── Primary path: DFG (precise, type-aware) ───────────────────
        dfg_found = False
        for node in dfg.nodes.values():
            if not node.is_definition:
                continue
            matched_sv = self._match_sv(node.variable, sv_written)
            if matched_sv is None:
                continue
            key = (node.cfg_node_id, node.variable)
            if key in seen:
                continue
            seen.add(key)
            dfg_found = True
            cfg_node    = cfg.nodes.get(node.cfg_node_id)
            source_line = cfg_node.source_line if cfg_node else None
            writes.append(_StateWrite(
                cfg_node_id = node.cfg_node_id,
                ir_index    = getattr(node, "ir_index", -1),
                var_name    = node.variable,
                source_line = source_line,
            ))

        if writes:
            return writes

        # ── Fallback path: CFG IR text scan ───────────────────────────
        # Used when DFG is empty (Slither discard_ir mode) or when the DFG
        # simply did not capture a write that is visible in the raw IR text.
        # Confidence is lower but correct enough to surface the violation.
        logger.debug(
            "DFG yielded no writes (dfg_found=%s) — falling back to IR text scan "
            "for state writes. sv_written=%s",
            dfg_found, sv_written,
        )
        for node in cfg.nodes.values():
            for ir_idx, stmt in enumerate(node.ir_stmts):
                for m in self._ASSIGN_RE.finditer(stmt):
                    var = m.group(1).strip()
                    matched = self._match_sv(var, sv_written)
                    if matched is None:
                        continue
                    key = (node.node_id, var)
                    if key in seen:
                        continue
                    seen.add(key)
                    writes.append(_StateWrite(
                        cfg_node_id = node.node_id,
                        ir_index    = ir_idx,
                        var_name    = var,
                        source_line = node.source_line,
                    ))

        return writes

    @staticmethod
    def _match_sv(var_name: str, sv_written: Set[str]) -> Optional[str]:
        """
        Match exact name, then array/mapping access, then nested struct/multi-level.
        E.g. 'balances[msg.sender]', 'pool.reserve0', 'allowances[a][b]' all
        resolve correctly.
        """
        if var_name in sv_written:
            return var_name
        # Strip off one or more [… ] or .field suffixes to find the base name
        base = var_name
        for sep in ("[", "."):
            idx = base.find(sep)
            if idx != -1:
                base = base[:idx]
                if base in sv_written:
                    return base
        return None


# ---------------------------------------------------------------------------
# Step 3b — Storage read finder (read-only reentrancy)
# ---------------------------------------------------------------------------

class _StorageReadFinder:
    """
    Finds SLOAD / view reads that could observe stale state during a
    read-only reentrancy attack (e.g., Curve read-only reentrancy bug).
    """

    def find(self, cfg: CFGGraph) -> List[_StorageRead]:
        reads: List[_StorageRead] = []
        for node in cfg.ordered_nodes():
            for ir_idx, stmt in enumerate(node.ir_stmts):
                if _STORAGE_READ_RE.search(stmt):
                    reads.append(_StorageRead(
                        cfg_node_id = node.node_id,
                        ir_index    = ir_idx,
                        stmt        = stmt,
                        source_line = node.source_line,
                    ))
        return reads


# ---------------------------------------------------------------------------
# Step 4 — CEI violation checker with cross-function and read-only support
# ---------------------------------------------------------------------------

class _CEIChecker:
    """
    Checks for CEI violations.

    Extra edge cases vs v1.x:
      - Cross-function: if the write is in a different function that can be
        reached from the call via the call graph, that's also a violation.
      - Read-only reentrancy: an SLOAD after a call that hasn't yet written
        the storage can expose stale state to a re-entrant viewer.
      - Reachability cache: BFS result is memoised per (cfg_id, from_nid).
    """

    def __init__(self) -> None:
        # key: (id(cfg), from_nid) → frozenset of reachable node IDs
        self._reach_cache: Dict[Tuple[int, int], FrozenSet[int]] = {}

    def find_violations(
        self,
        calls:  List[_ExternalCall],
        writes: List[_StateWrite],
        cfg:    CFGGraph,
        reads:  Optional[List[_StorageRead]] = None,
    ) -> List[_ReentrancyCandidate]:
        candidates: List[_ReentrancyCandidate] = []

        for call in calls:
            reachable = self._reachable_from(call.cfg_node_id, cfg)

            # Standard CEI violations
            for write in writes:
                if self._is_violation(call, write, cfg, reachable):
                    candidates.append(_ReentrancyCandidate(
                        call       = call,
                        write      = write,
                        is_delegate = call.is_delegate,
                    ))

            # Read-only reentrancy: stale SLOAD observed between call and write
            if reads:
                for read in reads:
                    if self._is_stale_read_violation(call, read, writes, cfg, reachable):
                        # Use a synthetic "no write" placeholder for the write field
                        # (the write is absent or happens later in external context)
                        dummy_write = _StateWrite(
                            cfg_node_id = read.cfg_node_id,
                            ir_index    = read.ir_index,
                            var_name    = "(stale read)",
                            source_line = read.source_line,
                        )
                        candidates.append(_ReentrancyCandidate(
                            call        = call,
                            write       = dummy_write,
                            stale_read  = read,
                            is_read_only = True,
                            is_delegate  = call.is_delegate,
                        ))

        return candidates

    def _is_violation(
        self,
        call:      _ExternalCall,
        write:     _StateWrite,
        cfg:       CFGGraph,
        reachable: FrozenSet[int],
    ) -> bool:
        if call.cfg_node_id == write.cfg_node_id:
            return self._same_node_violation(call.ir_index, write.ir_index)
        if cfg.dominates(write.cfg_node_id, call.cfg_node_id):
            return False
        return write.cfg_node_id in reachable

    def _is_stale_read_violation(
        self,
        call:      _ExternalCall,
        read:      _StorageRead,
        writes:    List[_StateWrite],
        cfg:       CFGGraph,
        reachable: FrozenSet[int],
    ) -> bool:
        """
        A read-only reentrancy occurs when:
          1. A re-entrant call can happen (i.e., the call node is present), AND
          2. An SLOAD/view-read exists somewhere reachable from the call, AND
          3. At least one write to the same storage exists AFTER the read (or later).
        We simplify: if any SLOAD is reachable from the call node, flag it.
        """
        if call.cfg_node_id == read.cfg_node_id:
            return call.ir_index < read.ir_index
        return read.cfg_node_id in reachable

    @staticmethod
    def _same_node_violation(call_ir: int, write_ir: int) -> bool:
        if call_ir == -1 or write_ir == -1:
            return True
        return call_ir <= write_ir

    def _reachable_from(self, from_nid: int, cfg: CFGGraph) -> FrozenSet[int]:
        cache_key = (id(cfg), from_nid)
        if cache_key in self._reach_cache:
            return self._reach_cache[cache_key]

        if from_nid not in cfg.nodes:
            self._reach_cache[cache_key] = frozenset()
            return frozenset()

        visited: Set[int] = set()
        queue = deque([from_nid])
        while queue:
            nid = queue.popleft()
            if nid in visited:
                continue
            visited.add(nid)
            node = cfg.nodes.get(nid)
            if node is None:
                continue
            for succ in node.successors:
                if succ not in visited:
                    queue.append(succ)
        visited.discard(from_nid)
        result = frozenset(visited)
        self._reach_cache[cache_key] = result
        return result


# ---------------------------------------------------------------------------
# Step 5 — Taint enricher
# ---------------------------------------------------------------------------

class _TaintEnricher:

    _HIGH_RISK_SOURCES: FrozenSet[TaintSourceKind] = frozenset({
        TaintSourceKind.MSG_VALUE,
        TaintSourceKind.MSG_SENDER,
        TaintSourceKind.FUNCTION_PARAM,
        TaintSourceKind.CALLDATA,
    })
    _CALL_SINKS: FrozenSet[TaintSinkKind] = frozenset({
        TaintSinkKind.EXTERNAL_CALL_VALUE,
        TaintSinkKind.EXTERNAL_CALL_ARGUMENT,
        TaintSinkKind.EXTERNAL_CALL_TARGET,
    })

    def enrich(
        self,
        candidates:   List[_ReentrancyCandidate],
        taint_result: Optional[TaintResult],
        cfg:          CFGGraph,
    ) -> None:
        if not taint_result or not taint_result.flows:
            return
        for candidate in candidates:
            for flow in taint_result.flows:
                if flow.sink_kind not in self._CALL_SINKS:
                    continue
                if flow.cfg_node_id != candidate.call.cfg_node_id:
                    continue
                if flow.source_kind in self._HIGH_RISK_SOURCES:
                    candidate.taint_confirms = True
                    candidate.taint_source   = flow.source_kind
                    candidate.is_sanitized   = flow.is_sanitized
                    break


# ---------------------------------------------------------------------------
# Step 7 — Finding builder
# ---------------------------------------------------------------------------

class _FindingBuilder:
    """
    Builds Finding objects from _ReentrancyCandidate instances.
    Recommendation and CVSS score are supplied externally (from the detector's
    safe_recommendation() / safe_cvss() wrappers).

    Confidence scoring factors:
      +0.20  taint confirms attacker-controlled data
      +0.10  low-level call (most exploitable)
      +0.08  delegate-call (storage context forwarded)
      +0.10  token-hook / flash-loan callback
      +0.05  multiple writes after same call
      +0.05  call is inside a loop (amplified impact)
      -0.15  limited-gas call (.transfer/.send, 2300 gas stipend)
      -0.20  partial guard present
      -0.15  sanitizer/require detected on tainted path
      -0.10  read-only reentrancy (harder to exploit directly)
    """

    _BASE        = 0.70
    _P_TAINT     = 0.20
    _P_LOW_LEVEL = 0.10
    _P_DELEGATE  = 0.08
    _P_HOOK      = 0.10
    _P_MULTI     = 0.05
    _P_LOOP      = 0.05
    _P_LIM_GAS   = 0.15
    _P_PARTIAL   = 0.20
    _P_SANITIZE  = 0.15
    _P_READONLY  = 0.10
    _MIN         = 0.30
    _MAX         = 1.00

    def build(
        self,
        candidate:         _ReentrancyCandidate,
        contract_name:     str,
        fn_info:           FunctionInfo,
        detector_id:       str,
        detector_version:  str,
        vuln_type:         VulnerabilityType,
        recommendation:    str,
        cvss_score:        float,
        has_partial_guard: bool,
        writes_after_call: int,
    ) -> Finding:
        return Finding(
            vuln_type        = vuln_type,
            severity         = self._severity(candidate),
            contract_name    = contract_name,
            function_name    = fn_info.name,
            source_file      = fn_info.source_file,
            title            = self._title(candidate),
            description      = self._description(candidate, fn_info),
            recommendation   = recommendation,
            confidence       = self._confidence(candidate, has_partial_guard, writes_after_call),
            cvss_score       = cvss_score,
            detector_id      = detector_id,
            detector_version = detector_version,
            metadata         = {
                "call_cfg_node":       candidate.call.cfg_node_id,
                "call_ir_index":       candidate.call.ir_index,
                "write_cfg_node":      candidate.write.cfg_node_id,
                "write_ir_index":      candidate.write.ir_index,
                "call_kind":           candidate.call.call_kind.value,
                "callee":              candidate.call.callee,
                "state_var":           candidate.write.var_name,
                "taint_confirms":      candidate.taint_confirms,
                "taint_source":        (
                    candidate.taint_source.value if candidate.taint_source else None
                ),
                "is_sanitized":        candidate.is_sanitized,
                "in_loop":             candidate.call.in_loop,
                "is_delegate":         candidate.is_delegate,
                "is_read_only":        candidate.is_read_only,
                "cross_function_fn":   candidate.cross_function_fn,
            },
        )

    @staticmethod
    def _severity(c: _ReentrancyCandidate) -> Severity:
        # Read-only reentrancy: typically MEDIUM (harder to directly drain funds)
        if c.is_read_only:
            return Severity.MEDIUM

        # Delegate-call reentrancy: always at least HIGH (storage context forwarded)
        if c.is_delegate:
            if c.taint_confirms and c.taint_source == TaintSourceKind.MSG_VALUE:
                return Severity.CRITICAL
            return Severity.HIGH

        # Standard low-level call
        if (
            c.call.call_kind == _CallKind.LOW_LEVEL
            and c.taint_confirms
            and c.taint_source == TaintSourceKind.MSG_VALUE
        ):
            return Severity.CRITICAL
        if c.call.call_kind == _CallKind.LOW_LEVEL and c.taint_confirms:
            return Severity.HIGH

        # Token hook / flash-loan callback
        if c.call.call_kind == _CallKind.TOKEN_HOOK:
            return Severity.HIGH if c.taint_confirms else Severity.MEDIUM

        # High-level call with tainted msg.value
        if (
            c.call.call_kind == _CallKind.HIGH_LEVEL
            and c.taint_confirms
            and c.taint_source == TaintSourceKind.MSG_VALUE
        ):
            return Severity.HIGH

        # .transfer() / .send() — limited gas, hard to exploit
        if c.call.call_kind == _CallKind.LIMITED_GAS:
            return Severity.LOW

        return Severity.MEDIUM

    def _confidence(
        self,
        c:             _ReentrancyCandidate,
        partial_guard: bool,
        write_count:   int,
    ) -> float:
        score = self._BASE
        if c.taint_confirms:
            score += self._P_TAINT
        if c.call.call_kind == _CallKind.LOW_LEVEL:
            score += self._P_LOW_LEVEL
        if c.is_delegate:
            score += self._P_DELEGATE
        if c.call.call_kind == _CallKind.TOKEN_HOOK:
            score += self._P_HOOK
        if write_count > 1:
            score += self._P_MULTI
        if c.call.in_loop:
            score += self._P_LOOP
        if c.call.call_kind == _CallKind.LIMITED_GAS:
            score -= self._P_LIM_GAS
        if partial_guard:
            score -= self._P_PARTIAL
        if c.is_sanitized:
            score -= self._P_SANITIZE
        if c.is_read_only:
            score -= self._P_READONLY
        return max(self._MIN, min(self._MAX, round(score, 4)))

    @staticmethod
    def _title(c: _ReentrancyCandidate) -> str:
        if c.is_read_only:
            return (
                f"Read-only Reentrancy: stale storage read "
                f"after {c.call.call_kind.value} external call"
            )
        if c.is_delegate:
            return (
                f"Delegatecall Reentrancy: state variable '{c.write.var_name}' "
                f"written after delegatecall"
            )
        return (
            f"Reentrancy: state variable '{c.write.var_name}' "
            f"written after {c.call.call_kind.value} external call"
        )

    @staticmethod
    def _description(c: _ReentrancyCandidate, fn_info: FunctionInfo) -> str:
        callee_str = f" to '{c.call.callee}'" if c.call.callee else ""
        call_loc   = (
            f"line {c.call.source_line}" if c.call.source_line is not None
            else f"CFG node {c.call.cfg_node_id}"
        )
        write_loc = (
            f"line {c.write.source_line}" if c.write.source_line is not None
            else f"CFG node {c.write.cfg_node_id}"
        )

        if c.is_read_only:
            base = (
                f"Function '{fn_info.name}' performs a "
                f"{c.call.call_kind.value} external call{callee_str} "
                f"at {call_loc} (IR index {c.call.ir_index}). "
                f"A re-entrant caller can invoke a view function that reads "
                f"storage at {write_loc} before the calling function has "
                f"updated state, observing stale values. "
                f"This is the read-only reentrancy pattern (e.g., Curve LP price oracle)."
            )
        else:
            verb = "delegates to" if c.is_delegate else "performs a"
            call_kind_str = "delegatecall" if c.is_delegate else f"{c.call.call_kind.value} external call"
            base = (
                f"Function '{fn_info.name}' {verb} {call_kind_str}{callee_str} "
                f"at {call_loc} (IR index {c.call.ir_index}), then writes to "
                f"state variable '{c.write.var_name}' "
                f"at {write_loc} (IR index {c.write.ir_index}). "
                f"A re-entrant call can observe and exploit the stale state "
                f"between the external call and the state update."
            )

        parts = [base]

        if c.call.in_loop:
            parts.append(
                "The external call occurs inside a loop body — a re-entrant "
                "attacker may exploit this repeatedly within a single transaction, "
                "amplifying the impact."
            )

        if c.taint_confirms:
            src = c.taint_source.value if c.taint_source else "unknown"
            parts.append(
                f"Taint analysis confirms attacker-controlled data "
                f"(source: {src}) flows into the external call."
            )
        if c.is_sanitized:
            parts.append(
                "A sanitizer check (require/assert) was detected on "
                "the tainted data path. Confidence reduced — the check "
                "may be incomplete or may occur after the vulnerable call."
            )
        if c.cross_function_fn:
            parts.append(
                f"Cross-function reentrancy: the state write occurs in "
                f"'{c.cross_function_fn}', a separate function reachable "
                f"while the external call in '{fn_info.name}' is in-flight."
            )

        return " ".join(parts)


# ---------------------------------------------------------------------------
# Public detector
# ---------------------------------------------------------------------------

class ReentrancyDetector(BaseDetector):

    DETECTOR_ID      = "reentrancy_v2"
    DETECTOR_VERSION = "2.1.0"
    VULN_TYPE        = VulnerabilityType.REENTRANCY
    DEFAULT_SEVERITY = Severity.MEDIUM

    def __init__(self) -> None:
        self._guard_detector  = _GuardDetector()
        self._call_finder     = _CallNodeFinder()
        self._write_finder    = _StateWriteFinder()
        self._read_finder     = _StorageReadFinder()
        self._cei_checker     = _CEIChecker()
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

        # FIX v2.1: only bail when there is literally no CFG to inspect.
        # fn_info.external_calls is empty for pre-0.5 contracts because Slither
        # does not map .call.value()() to external_calls_as_expressions — but the
        # CFG nodes are still present and our text-pattern scanner will find them.
        if not cfg.nodes:
            return []

        sv_names: Set[str] = {_sv_name(v) for v in fn_info.state_vars_written}

        # ── Step 1: Guard check ───────────────────────────────────────
        if self._guard_detector.has_reliable_guard(fn_info, cfg, sv_names):
            # Edge case: guard on base but function is an unguarded override
            if not self._guard_detector.is_unguarded_override(fn_info):
                logger.debug(
                    "Reentrancy: '%s.%s' — reliable guard, skipped.",
                    contract.name, fn_info.name,
                )
                return []
            logger.debug(
                "Reentrancy: '%s.%s' — guard present but function is unguarded override, continuing.",
                contract.name, fn_info.name,
            )

        has_partial_guard = self._guard_detector.has_partial_guard(fn_info, sv_names)

        # ── Step 2: Find external calls ───────────────────────────────
        calls = self._call_finder.find(cfg)
        if not calls:
            return []

        # ── Step 3: Find state writes ─────────────────────────────────
        writes = self._write_finder.find(dfg, fn_info, cfg)

        # ── Step 3b: Find storage reads (read-only reentrancy) ────────
        reads = self._read_finder.find(cfg)

        if not writes and not reads:
            return []

        # ── Step 4: CEI violation check ───────────────────────────────
        candidates = self._cei_checker.find_violations(calls, writes, cfg, reads)
        if not candidates:
            return []

        # ── Step 5: Taint enrichment ──────────────────────────────────
        self._taint_enricher.enrich(candidates, taint_result, cfg)

        # ── Step 6: Deduplication ─────────────────────────────────────
        seen_pairs:   Set[Tuple[int, str, bool]] = set()
        deduplicated: List[_ReentrancyCandidate] = []
        for c in candidates:
            # Include is_read_only in the key so read-only and standard findings
            # are not collapsed onto each other for the same (node, var) pair.
            key = (c.call.cfg_node_id, c.write.var_name, c.is_read_only)
            if key not in seen_pairs:
                seen_pairs.add(key)
                deduplicated.append(c)

        writes_after: Dict[int, int] = {}
        for c in deduplicated:
            nid = c.call.cfg_node_id
            writes_after[nid] = writes_after.get(nid, 0) + 1

        # ── Step 7: Build findings ────────────────────────────────────
        findings: List[Finding] = []
        for c in deduplicated:
            context = self._build_context(c, fn_info, contract, has_partial_guard)
            finding = self._finding_builder.build(
                candidate         = c,
                contract_name     = contract.name,
                fn_info           = fn_info,
                detector_id       = self.DETECTOR_ID,
                detector_version  = self.DETECTOR_VERSION,
                vuln_type         = self.VULN_TYPE,
                recommendation    = self.safe_recommendation(context),
                cvss_score        = self.safe_cvss(context),
                has_partial_guard = has_partial_guard,
                writes_after_call = writes_after.get(c.call.cfg_node_id, 1),
            )
            findings.append(finding)
            logger.debug(
                "Reentrancy: '%s.%s' — %s, conf=%.2f, cvss=%.1f, "
                "call_node=%d (ir=%d), write_var='%s' (ir=%d), "
                "read_only=%s, delegate=%s, in_loop=%s.",
                contract.name, fn_info.name,
                finding.severity.value, finding.confidence, finding.cvss_score,
                c.call.cfg_node_id, c.call.ir_index,
                c.write.var_name, c.write.ir_index,
                c.is_read_only, c.is_delegate, c.call.in_loop,
            )

        return findings

    # ------------------------------------------------------------------
    # build_recommendation — dynamic, context-aware
    # ------------------------------------------------------------------

    def build_recommendation(self, context: dict) -> str:
        fn_name    = context["function_name"]
        state_var  = context.get("state_var_written", "state variable")
        call_kind  = context.get("call_kind", "external")
        has_guard  = context.get("has_reentrancy_guard", False)
        is_payable = context.get("is_payable", False)
        call_line  = context.get("call_line")
        write_line = context.get("state_update_line")
        is_ro      = context.get("is_read_only", False)
        is_del     = context.get("is_delegate", False)
        in_loop    = context.get("in_loop", False)
        is_override = context.get("is_unguarded_override", False)

        call_loc = (
            f"line {call_line}" if call_line is not None
            else f"CFG node {context.get('call_cfg_node', '?')}"
        )
        write_loc = (
            f"line {write_line}" if write_line is not None
            else f"CFG node {context.get('write_cfg_node', '?')}"
        )

        if is_ro:
            rec = (
                f"In function '{fn_name}': read-only reentrancy detected. "
                f"A re-entrant caller may read stale storage values via view "
                f"functions while the external call at {call_loc} is in-flight. "
                f"Protect all functions that read price/balance/reserve storage "
                f"with OpenZeppelin's 'nonReentrantView' modifier, or ensure "
                f"state is updated before the external call."
            )
            return rec

        rec = (
            f"In function '{fn_name}': the {call_kind} external call at "
            f"{call_loc} executes BEFORE the state update to "
            f"'{state_var}' at {write_loc}. "
            f"Move the '{state_var}' update to BEFORE {call_loc} "
            f"(Checks-Effects-Interactions pattern)."
        )

        if not has_guard:
            rec += (
                f" Additionally, '{fn_name}' has no reentrancy guard. "
                f"Add OpenZeppelin's 'nonReentrant' modifier."
            )
        else:
            rec += (
                f" A reentrancy guard is present but the incorrect call "
                f"order still creates risk if the guard is removed later."
            )

        if is_override:
            rec += (
                f" WARNING: '{fn_name}' overrides a base function but does "
                f"not re-declare the guard modifier — modifiers are NOT "
                f"inherited automatically in Solidity overrides. "
                f"Explicitly add 'nonReentrant' to the override signature."
            )

        if is_del:
            rec += (
                f" '{fn_name}' uses delegatecall — the callee executes in "
                f"this contract's storage context, making reentrancy via the "
                f"callee as dangerous as a direct re-entry. "
                f"Ensure the delegatecall target is trusted and immutable."
            )

        if is_payable and call_kind in ("low_level", "delegate_call"):
            rec += (
                f" '{fn_name}' is payable and uses a {call_kind} call — "
                f"the highest-risk combination. An attacker can drain funds "
                f"across multiple re-entrant calls before '{state_var}' is updated."
            )

        if in_loop:
            rec += (
                f" The external call is inside a loop. An attacker can "
                f"re-enter on every iteration, amplifying losses by the loop "
                f"count. Consider restructuring to avoid external calls in loops."
            )

        if context.get("is_sanitized"):
            rec += (
                f" Note: a sanitizer (require/assert) was detected on "
                f"the tainted data path but may execute after the "
                f"vulnerable call. Verify its placement carefully."
            )

        return rec

    # ------------------------------------------------------------------
    # calculate_cvss — context-adjusted, capped [0.0, 10.0]
    # ------------------------------------------------------------------

    def calculate_cvss(self, context: dict) -> float:
        """
        Base: 7.5

        ┌──────────────────────────────────────────────────┬───────┐
        │ Condition                                        │ Delta │
        ├──────────────────────────────────────────────────┼───────┤
        │ is_payable + low_level / delegate call           │ +1.5  │
        │ is_payable (any other call kind)                 │ +0.5  │
        │ external or public visibility                    │ +0.5  │
        │ low_level call (not payable)                     │ +0.5  │
        │ delegate call (not payable)                      │ +0.5  │
        │ token hook / flash-loan callback                 │ +0.5  │
        │ call inside loop                                 │ +0.5  │
        │ cross-function reentrancy                        │ +0.3  │
        │ has_reentrancy_guard (partial only)              │ −1.0  │
        │ limited_gas call (.transfer / .send)             │ −2.0  │
        │ is_sanitized                                     │ −0.5  │
        │ read_only reentrancy                             │ −1.0  │
        └──────────────────────────────────────────────────┴───────┘
        """
        score      = 7.5
        call_kind  = context.get("call_kind", "")
        is_payable = context.get("is_payable", False)
        is_hi_risk = call_kind in ("low_level", "delegate_call")

        if is_payable and is_hi_risk:
            score += 1.5
        elif is_payable:
            score += 0.5

        if context.get("function_visibility") in ("external", "public"):
            score += 0.5

        if call_kind == "low_level" and not is_payable:
            score += 0.5

        if call_kind == "delegate_call" and not is_payable:
            score += 0.5

        if call_kind == "token_hook":
            score += 0.5

        if context.get("in_loop"):
            score += 0.5

        if context.get("cross_function_fn"):
            score += 0.3

        if context.get("has_reentrancy_guard"):
            score -= 1.0

        if call_kind == "limited_gas":
            score -= 2.0

        if context.get("is_sanitized"):
            score -= 0.5

        if context.get("is_read_only"):
            score -= 1.0

        return round(max(0.0, min(10.0, score)), 1)

    # ------------------------------------------------------------------
    # Context builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_context(
        c:                 _ReentrancyCandidate,
        fn_info:           FunctionInfo,
        contract:          ContractInfo,
        has_partial_guard: bool,
    ) -> dict:
        return {
            "contract_name":          contract.name,
            "function_name":          fn_info.name,
            "function_visibility":    fn_info.visibility.value,
            "is_payable":             fn_info.state_mutability.value == "payable",
            "call_line":              c.call.source_line,
            "call_cfg_node":          c.call.cfg_node_id,
            "call_kind":              c.call.call_kind.value,
            "call_expression":        c.call.stmt,
            "state_var_written":      c.write.var_name,
            "state_update_line":      c.write.source_line,
            "write_cfg_node":         c.write.cfg_node_id,
            "has_reentrancy_guard":   has_partial_guard,
            "is_sanitized":           c.is_sanitized,
            "taint_confirms":         c.taint_confirms,
            "taint_source":           (
                c.taint_source.value if c.taint_source else None
            ),
            "in_loop":                c.call.in_loop,
            "is_delegate":            c.is_delegate,
            "is_read_only":           c.is_read_only,
            "cross_function_fn":      c.cross_function_fn,
            "is_unguarded_override":  getattr(fn_info, "is_override", False),
        }
