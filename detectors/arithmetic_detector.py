"""
detectors/arithmetic_detector.py

Arithmetic overflow / underflow vulnerability detector for VigilanceCore.
v2.1.0 — Adds Step 0b: raw-source fallback for pre-0.8.0 contracts.

Root cause fixed
----------------
FunctionInfo is a frozen, slot-based dataclass (contract_parser.py design
rule #2: "No Slither types stored beyond this file"). Therefore
_slither_fn_from_info() ALWAYS returns None — the Slither-native path
(Step 0) never fires. The CFG fallback (Steps 1-2) also silently produces
zero results for many pre-0.8.0 contracts because cfg_builder does not
populate ir_op_types / ir_stmts for arithmetic nodes under those pragmas.

Fix: Step 0b extracts the function body directly from contract.raw_source
using fn_info.start_line / end_line, then regex-scans for arithmetic
operators not wrapped in SafeMath calls. Fires only when is_pre_08 is True
AND both upstream paths produced zero vulnerable findings.

Detection pipeline (9 steps)
-----------------------------
Step 0   Slither-native  — Binary IR via slither_fn (usually None)
Step 0b  Raw-source      — pre-0.8.0 fallback: scan fn body from raw_source
Step 1   Fast-path       — skip if no arithmetic in CFG at all
Step 2   IR scan         — find ops via ir_op_types / regex
Step 3   Version check   — is this a pre-0.8.0 contract?
Step 4   Filter          — keep only vulnerable ops
Step 5   Taint enrich    — does attacker-controlled data flow in?
Step 6   Dedup           — one finding per (node_id, operator)
Step 7   Build           — create Finding with recommendation + CVSS
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
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
# Slither-native imports — optional; graceful fallback if unavailable
# ---------------------------------------------------------------------------
try:
    from slither.slithir.operations import Binary, BinaryType  # type: ignore
    _SLITHER_AVAILABLE = True
except ImportError:
    Binary = None       # type: ignore[assignment,misc]
    BinaryType = None   # type: ignore[assignment,misc]
    _SLITHER_AVAILABLE = False

# ---------------------------------------------------------------------------
# Module-level compiled patterns — never re-compiled in hot path
# ---------------------------------------------------------------------------

_ARITH_OP_TYPES: FrozenSet[str] = frozenset({
    "BinaryOperation", "Addition", "Subtraction",
    "Multiplication",  "Division",  "Modulo",  "Power",
})

# Matches infix arithmetic in Slither IR text: 'a + b', 'x[i] * 2', etc.
# Negative look-ahead avoids matching comparison/assignment operators.
_ARITH_STMT_RE = re.compile(
    r"\b(\w[\w\[\].]*)\s*"
    r"([+\-*/%]|\*\*)\s*"
    r"(\w[\w\[\].]*)"
    r"(?!\s*[=>])"
)

# SafeMath detection — matches library calls and method-style calls.
_SAFEMATH_RE = re.compile(
    r"\b(?:SafeMath|safeAdd|safeSub|safeMul|safeDiv|safeMod)\b"
    r"|\.(?:add|sub|mul|div|mod)\s*\(",
    re.IGNORECASE,
)

# Matches pragma versions below 0.8.0 in raw Solidity source.
_PRE_08_RE = re.compile(
    r"pragma\s+solidity\s+[^;]*?0\s*\.\s*[0-7]\b"
)

# Matches the opening of an unchecked block in IR text / labels.
_UNCHECKED_RE = re.compile(r"\bunchecked\b", re.IGNORECASE)

# Extracts a single arithmetic operator from an IR statement string.
_OP_EXTRACT_RE = re.compile(r"\s(\*\*|[+\-*/%])\s")

# Human-readable operator names used in titles / descriptions.
_OP_NAMES: dict = {
    "+":   "addition",        "+=":  "addition",      "ADD":  "addition",
    "-":   "subtraction",     "-=":  "subtraction",   "SUB":  "subtraction",
    "*":   "multiplication",  "*=":  "multiplication", "MUL":  "multiplication",
    "/":   "division",        "/=":  "division",      "DIV":  "division",
    "%":   "modulo",          "%=":  "modulo",        "MOD":  "modulo",
    "**":  "exponentiation",  "**=": "exponentiation","EXP":  "exponentiation",
    "POW": "exponentiation",  "POWER": "exponentiation",
}

# ---------------------------------------------------------------------------
# Raw-source fallback patterns (Step 0b — new in v2.1.0)
# ---------------------------------------------------------------------------

# Matches infix arithmetic in raw Solidity source (not IR).
# Excludes: >=, <=, ==, => comparisons; comments.
_RAW_INFIX_RE = re.compile(
    r"(?<![=<>!+\-*/%])"
    r"\b([\w][\w.\[\]]*)\s*"
    r"([+\-*])\s*"
    r"([\w][\w.\[\]]*)\b"
    r"(?!\s*[=>])",
    re.MULTILINE,
)

# Matches compound assignment operators: +=, -=, *=
_RAW_COMPOUND_RE = re.compile(
    r"\b([\w][\w.\[\]]*)\s*"
    r"([+\-*])="
    r"(?!=)",
    re.MULTILINE,
)

# Detects SafeMath *call sites* in raw source.
# 'using SafeMath for uint256' alone does NOT mean every op is protected.
_RAW_SAFEMATH_CALL_RE = re.compile(
    r"\.(?:add|sub|mul|div|mod)\s*\("
    r"|\bSafeMath\s*\.\s*(?:add|sub|mul|div|mod)\s*\(",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Taint sink — may not exist in all TaintSinkKind versions
# ---------------------------------------------------------------------------
try:
    _ARITH_SINK: Optional[TaintSinkKind] = TaintSinkKind.ARITHMETIC_OPERAND
except AttributeError:
    _ARITH_SINK = None

# ---------------------------------------------------------------------------
# Slither BinaryType -> operator symbol map (built once on first use)
# ---------------------------------------------------------------------------

def _build_bintype_map() -> dict:
    if not _SLITHER_AVAILABLE:
        return {}
    candidates = {
        "ADDITION":       "+",
        "SUBTRACTION":    "-",
        "MULTIPLICATION": "*",
        "DIVISION":       "/",
        "MODULO":         "%",
        "POWER":          "**",
    }
    result = {}
    for name, sym in candidates.items():
        bt = getattr(BinaryType, name, None)
        if bt is not None:
            result[bt] = sym
    return result


_BINTYPE_SYM: dict = {}  # populated lazily on first call


def _overflow_binary_types() -> set:
    """Return BinaryType members that represent potentially-overflowing ops."""
    if not _SLITHER_AVAILABLE:
        return set()
    global _BINTYPE_SYM
    if not _BINTYPE_SYM:
        _BINTYPE_SYM = _build_bintype_map()
    return set(_BINTYPE_SYM.keys())

# ---------------------------------------------------------------------------
# Internal data classes
# ---------------------------------------------------------------------------

@dataclass
class _ArithOp:
    cfg_node_id:  int
    ir_index:     int
    operator:     str
    operands:     List[str]
    stmt:         str
    source_line:  Optional[int]
    in_unchecked: bool
    has_safemath: bool


@dataclass
class _ArithFinding:
    op:             _ArithOp
    taint_confirms: bool = False
    taint_source:   Optional[TaintSourceKind] = None
    is_pre_08:      bool = False

# ---------------------------------------------------------------------------
# Step 0 — Slither-native detection
# ---------------------------------------------------------------------------

def _slither_fn_from_info(fn_info: FunctionInfo) -> Optional[Any]:
    """
    Try every attribute name under which the Slither Function object
    might be stored. In practice contract_parser.py strips all Slither
    objects (design rule), so this always returns None. Retained for
    forward-compatibility if a future parser version attaches the object.
    """
    for attr in (
        "_slither_fn", "slither_function", "slither_fn",
        "_fn", "_function", "fn", "raw",
    ):
        obj = getattr(fn_info, attr, None)
        if obj is not None:
            return obj
    return None


def _source_line_from_node(node: Any) -> Optional[int]:
    sm = getattr(node, 'source_mapping', None)
    if sm is None:
        return None
    lines_list = getattr(sm, 'lines', None)
    if lines_list:
        return lines_list[0]
    return getattr(sm, 'start', None)


def _is_node_unchecked(node: Any) -> bool:
    return bool(
        getattr(node, 'is_unchecked', False)
        or getattr(node, 'unchecked', False)
    )


def _detect_slither_native(
    fn_info:  FunctionInfo,
    contract: ContractInfo,
    is_pre_08: bool,
) -> List[_ArithOp]:
    """
    Query Slither Binary IR objects directly.
    Returns [] when the Slither function object is not accessible.
    """
    if not _SLITHER_AVAILABLE:
        return []
    slither_fn = _slither_fn_from_info(fn_info)
    if slither_fn is None:
        return []

    overflow_types = _overflow_binary_types()
    global _BINTYPE_SYM
    if not _BINTYPE_SYM:
        _BINTYPE_SYM = _build_bintype_map()

    ops:  List[_ArithOp] = []
    seen: Set[Tuple[int, str]] = set()

    for node in getattr(slither_fn, 'nodes', []):
        in_unchecked = _is_node_unchecked(node)
        ir_list = (
            getattr(node, 'irs_ssa', None)
            or getattr(node, 'irs', None)
            or []
        )
        for ir_idx, ir in enumerate(ir_list):
            if Binary is None or not isinstance(ir, Binary):
                continue
            bt = getattr(ir, 'type', None)
            if bt not in overflow_types:
                continue
            operator = _BINTYPE_SYM.get(bt, str(bt))
            stmt_str = str(ir)
            if _SAFEMATH_RE.search(stmt_str):
                continue
            key = (id(node), operator)
            if key in seen:
                continue
            seen.add(key)
            operands: List[str] = []
            for attr in ('variable_left', 'variable_right'):
                v = getattr(ir, attr, None)
                if v is not None:
                    operands.append(str(v))
            ops.append(_ArithOp(
                cfg_node_id  = id(node),
                ir_index     = ir_idx,
                operator     = operator,
                operands     = operands,
                stmt         = stmt_str[:120],
                source_line  = _source_line_from_node(node),
                in_unchecked = in_unchecked,
                has_safemath = False,
            ))
    return ops

# ---------------------------------------------------------------------------
# Step 0b — Raw-source fallback (NEW in v2.1.0)
# ---------------------------------------------------------------------------

def _extract_fn_body(fn_info: FunctionInfo, contract: ContractInfo) -> str:
    """
    Return the raw Solidity source lines for fn_info using its line range.
    Returns "" when line info or raw_source is unavailable.
    """
    raw = getattr(contract, 'raw_source', None) or ''
    if not raw:
        return ''
    start = fn_info.start_line
    end   = fn_info.end_line
    if not start or not end:
        return ''
    src_lines = raw.splitlines()
    return chr(10).join(src_lines[max(0, start - 1) : min(len(src_lines), end)])


def _raw_source_overflow_scan(
    fn_body:  str,
    fn_info:  FunctionInfo,
    is_pre_08: bool,
) -> List[_ArithFinding]:
    """
    Last-resort raw-source scan for unprotected arithmetic in pre-0.8.0
    functions.

    Algorithm
    ---------
    1. Strip single-line comments so // ... does not confuse the regex.
    2. Count SafeMath call sites in the body.
    3. Collect all infix (+,-,*) and compound (+=,-=,*=) matches.
    4. Skip any match whose line already contains a SafeMath call.
    5. Deduplicate by operator symbol — at most one finding per type.
    6. Suppress entirely when safemath_calls >= raw_ops_found.
    """
    if not is_pre_08 or not fn_body:
        return []

    # Strip single-line comments
    body_nc = re.sub(r'//[^\n]*', '', fn_body)

    safemath_calls = len(_RAW_SAFEMATH_CALL_RE.findall(body_nc))
    body_lines_list = body_nc.splitlines()

    seen_ops: Set[str]          = set()
    findings: List[_ArithFinding] = []

    def _process(m: re.Match, is_compound: bool) -> None:
        op = m.group(2)
        if op in seen_ops:
            return
        # Division and modulo cannot overflow/underflow — skip
        if op in ('/', '%'):
            return
        # Locate the source line for this match
        match_start = m.start()
        line_no = body_nc.count(chr(10), 0, match_start)
        src_line = (
            body_lines_list[line_no].strip()
            if line_no < len(body_lines_list) else ''
        )
        # Skip if this line itself calls SafeMath
        if _RAW_SAFEMATH_CALL_RE.search(src_line):
            return
        seen_ops.add(op)
        left_op  = m.group(1)
        right_op = m.group(len(m.groups())) if not is_compound else ''
        operands = [x for x in (left_op, right_op) if x]
        arith_op = _ArithOp(
            cfg_node_id  = -1,
            ir_index     = -1,
            operator     = (op + '=') if is_compound else op,
            operands     = operands,
            stmt         = m.group(0)[:80],
            source_line  = (fn_info.start_line or 0) + line_no,
            in_unchecked = False,
            has_safemath = False,
        )
        findings.append(_ArithFinding(op=arith_op, is_pre_08=True))

    for m in _RAW_INFIX_RE.finditer(body_nc):
        _process(m, is_compound=False)
    for m in _RAW_COMPOUND_RE.finditer(body_nc):
        _process(m, is_compound=True)

    # Suppress when all ops appear to be SafeMath-wrapped
    if safemath_calls > 0 and len(findings) <= safemath_calls:
        logger.debug(
            "Arithmetic[raw-fallback]: '%s' — all ops appear SafeMath-wrapped "
            "(%d calls, %d raw ops). Suppressing.",
            fn_info.name, safemath_calls, len(findings),
        )
        return []
    return findings

# ---------------------------------------------------------------------------
# Step 1 — Fast-path: skip functions with no arithmetic at all
# ---------------------------------------------------------------------------

def _has_arithmetic(cfg: CFGGraph) -> bool:
    for node in cfg.nodes.values():
        if any(t in _ARITH_OP_TYPES for t in node.ir_op_types):
            return True
        for stmt in node.ir_stmts:
            if _ARITH_STMT_RE.search(stmt):
                return True
    return False

# ---------------------------------------------------------------------------
# Step 2 — CFG / regex-based arithmetic operation finder
# ---------------------------------------------------------------------------

class _ArithOpFinder:
    def find(self, cfg: CFGGraph) -> List[_ArithOp]:
        ops:  List[_ArithOp] = []
        seen: Set[Tuple[int, str]] = set()
        in_unchecked: bool = False

        for node in cfg.ordered_nodes():
            label_upper = (node.label or '').upper()
            if 'BEGIN_UNCHECKED' in label_upper or (
                'UNCHECKED' in label_upper and 'END_UNCHECKED' not in label_upper
            ):
                in_unchecked = True
            if 'END_UNCHECKED' in label_upper:
                in_unchecked = False

            combined       = ' '.join(node.ir_stmts)
            node_unchecked = in_unchecked or bool(_UNCHECKED_RE.search(combined))
            node_safemath  = bool(_SAFEMATH_RE.search(combined))

            if node.ir_op_types:
                for ir_idx, op_type in enumerate(node.ir_op_types):
                    if op_type not in _ARITH_OP_TYPES:
                        continue
                    stmt = (
                        node.ir_stmts[ir_idx]
                        if ir_idx < len(node.ir_stmts)
                        else combined
                    )
                    operator = self._extract_operator(stmt, op_type)
                    operands = self._extract_operands(stmt)
                    key = (node.node_id, operator)
                    if key in seen:
                        continue
                    seen.add(key)
                    ops.append(_ArithOp(
                        cfg_node_id  = node.node_id,
                        ir_index     = ir_idx,
                        operator     = operator,
                        operands     = operands,
                        stmt         = stmt[:120],
                        source_line  = node.source_line,
                        in_unchecked = node_unchecked,
                        has_safemath = node_safemath,
                    ))
            else:
                for ir_idx, stmt in enumerate(node.ir_stmts):
                    if not _ARITH_STMT_RE.search(stmt):
                        continue
                    operator = self._extract_operator(stmt, '')
                    if not operator:
                        continue
                    operands = self._extract_operands(stmt)
                    key = (node.node_id, operator)
                    if key in seen:
                        continue
                    seen.add(key)
                    ops.append(_ArithOp(
                        cfg_node_id  = node.node_id,
                        ir_index     = ir_idx,
                        operator     = operator,
                        operands     = operands,
                        stmt         = stmt[:120],
                        source_line  = node.source_line,
                        in_unchecked = node_unchecked,
                        has_safemath = node_safemath,
                    ))
        return ops

    @staticmethod
    def _extract_operator(stmt: str, op_type: str) -> str:
        m = _OP_EXTRACT_RE.search(stmt)
        if m:
            return m.group(1)
        type_map = {
            "Addition":       "+",
            "Subtraction":    "-",
            "Multiplication": "*",
            "Division":       "/",
            "Modulo":         "%",
            "Power":          "**",
            "BinaryOperation":"+",
        }
        return type_map.get(op_type, op_type or '?')

    @staticmethod
    def _extract_operands(stmt: str) -> List[str]:
        cleaned = re.sub(
            r"\b(?:ADD|SUB|MUL|DIV|MOD|EXP|require|assert|return)\b",
            ' ', stmt, flags=re.IGNORECASE,
        )
        tokens = re.findall(r"\b[a-zA-Z_]\w*\b", cleaned)
        noise = {
            "uint", "int", "bool", "address", "bytes", "string",
            "memory", "storage", "calldata", "this", "true", "false",
        }
        return [t for t in tokens if t.lower() not in noise][:2]

# ---------------------------------------------------------------------------
# Step 3 — Solidity version checker
# ---------------------------------------------------------------------------

def _is_pre_08(contract: ContractInfo) -> bool:
    """
    Return True if the contract uses Solidity < 0.8.0.
    Checks both solidity_version field AND raw source pragma so that
    non-standard version strings (e.g. >=0.5.0 <0.8.0) are handled.
    """
    ver = contract.solidity_version or ''
    if ver:
        nums = re.findall(r"0\.(\d+)", ver)
        if nums:
            return int(nums[0]) < 8
    # Fallback — always check raw source even when solidity_version is set
    if contract.raw_source:
        return bool(_PRE_08_RE.search(contract.raw_source))
    return False

# ---------------------------------------------------------------------------
# Step 4 — Vulnerability filter
# ---------------------------------------------------------------------------

def _is_vulnerable(op: _ArithOp, is_pre_08: bool) -> bool:
    """
    Vulnerable when NOT SafeMath-protected AND either:
      - pre-0.8.0 contract (no built-in overflow check), OR
      - inside an explicit unchecked{} block.
    """
    if op.has_safemath:
        return False
    if is_pre_08:
        return True
    return op.in_unchecked

# ---------------------------------------------------------------------------
# Step 5 — Taint enricher
# ---------------------------------------------------------------------------

class _TaintEnricher:
    _HIGH_RISK_SOURCES: FrozenSet[TaintSourceKind] = frozenset(filter(None, [
        getattr(TaintSourceKind, 'MSG_VALUE',      None),
        getattr(TaintSourceKind, 'MSG_SENDER',     None),
        getattr(TaintSourceKind, 'FUNCTION_PARAM', None),
        getattr(TaintSourceKind, 'CALLDATA',       None),
    ]))

    def enrich(
        self,
        candidates:   List[_ArithFinding],
        taint_result: Optional[TaintResult],
    ) -> None:
        if not taint_result or not taint_result.flows:
            return
        for candidate in candidates:
            for flow in taint_result.flows:
                if _ARITH_SINK is not None:
                    if flow.sink_kind != _ARITH_SINK:
                        continue
                if flow.cfg_node_id != candidate.op.cfg_node_id:
                    continue
                if flow.source_kind in self._HIGH_RISK_SOURCES:
                    candidate.taint_confirms = True
                    candidate.taint_source   = flow.source_kind
                    break

# ---------------------------------------------------------------------------
# Step 7 — Finding builder
# ---------------------------------------------------------------------------

class _FindingBuilder:
    def build(
        self,
        candidate:        _ArithFinding,
        contract_name:    str,
        fn_info:          FunctionInfo,
        detector_id:      str,
        detector_version: str,
        recommendation:   str,
        cvss_score:       float,
    ) -> Finding:
        op = candidate.op
        return Finding(
            vuln_type        = VulnerabilityType.ARITHMETIC,
            severity         = self._severity(candidate),
            contract_name    = contract_name,
            function_name    = fn_info.name,
            source_file      = fn_info.source_file,
            start_line       = op.source_line,
            title            = self._title(candidate),
            description      = self._description(candidate, fn_info),
            recommendation   = recommendation,
            confidence       = self._confidence(candidate),
            cvss_score       = cvss_score,
            detector_id      = detector_id,
            detector_version = detector_version,
            metadata         = FindingMetadata(
                overflow_operand = ', '.join(op.operands) if op.operands else None,
                extra = {
                    'operator':       op.operator,
                    'operands':       op.operands,
                    'in_unchecked':   op.in_unchecked,
                    'has_safemath':   op.has_safemath,
                    'is_pre_08':      candidate.is_pre_08,
                    'taint_confirms': candidate.taint_confirms,
                    'taint_source': (
                        candidate.taint_source.value
                        if candidate.taint_source else None
                    ),
                    'cfg_node_id':    op.cfg_node_id,
                    'ir_index':       op.ir_index,
                    'stmt':           op.stmt,
                    'via_raw_source': op.cfg_node_id == -1,
                },
            ),
        )

    @staticmethod
    def _severity(c: _ArithFinding) -> Severity:
        if c.is_pre_08 and c.taint_confirms:
            return Severity.CRITICAL
        if c.is_pre_08 or (c.op.in_unchecked and c.taint_confirms):
            return Severity.HIGH
        if c.op.in_unchecked:
            return Severity.MEDIUM
        return Severity.LOW

    @staticmethod
    def _confidence(c: _ArithFinding) -> float:
        score = 0.60
        if c.taint_confirms:
            score += 0.25
        if c.is_pre_08:
            score += 0.10
        if c.op.in_unchecked:
            score += 0.10
        # Raw-source findings are slightly less certain (no IR confirmation)
        if c.op.cfg_node_id == -1:
            score -= 0.05
        return round(min(1.0, max(0.4, score)), 4)

    @staticmethod
    def _title(c: _ArithFinding) -> str:
        op_name = _OP_NAMES.get(c.op.operator.upper(),
                  _OP_NAMES.get(c.op.operator, c.op.operator))
        if c.op.operator in ('-', '-=', 'SUB'):
            kind = 'underflow'
        elif c.op.operator in ('/', '/=', 'DIV', '%', '%=', 'MOD'):
            kind = 'division issue'
        else:
            kind = 'overflow'
        context = 'pre-0.8.0' if c.is_pre_08 else 'unchecked block'
        return (
            f'Arithmetic {kind}: unprotected {op_name} '
            f'operation in {context}'
        )

    @staticmethod
    def _description(c: _ArithFinding, fn_info: FunctionInfo) -> str:
        op = c.op
        op_name = _OP_NAMES.get(op.operator.upper(),
                  _OP_NAMES.get(op.operator, op.operator))
        loc = f' at line {op.source_line}' if op.source_line else ''
        # Use a temp variable to avoid nested-quote issues in f-strings
        if op.operands:
            ops_joined = "' and '".join(op.operands)
            operand_str = f" on operands '{ops_joined}'"
        else:
            operand_str = ''

        if c.is_pre_08:
            base = (
                f"Function '{fn_info.name}' performs an unchecked {op_name}{loc}"
                f"{operand_str}. This contract uses Solidity < 0.8.0 which has "
                f"no built-in overflow/underflow protection. The operation can "
                f"silently wrap around, corrupting balances or counters."
            )
        else:
            base = (
                f"Function '{fn_info.name}' performs a {op_name}{loc}"
                f"{operand_str} inside an 'unchecked{{}}' block. "
                f"The 'unchecked' keyword deliberately disables Solidity 0.8.0+'s "
                f"built-in overflow protection, making this operation unsafe."
            )

        if op.cfg_node_id == -1:
            base += (
                ' (Detected via raw-source analysis — '
                'IR confirmation unavailable for this compiler version.)'
            )

        if c.taint_confirms:
            src = c.taint_source.value if c.taint_source else 'external input'
            base += (
                f' Taint analysis confirms attacker-controlled data '
                f'(source: {src}) flows into this operation — '
                f'an attacker can trigger the overflow/underflow deliberately.'
            )
        return base

# ---------------------------------------------------------------------------
# Public detector
# ---------------------------------------------------------------------------

class ArithmeticDetector(BaseDetector):
    """
    Detects arithmetic overflow and underflow vulnerabilities.

    v2.1.0 — Three-path detection:
      Path A  Slither-native Binary IR   (fires if slither_fn accessible)
      Path B  CFG node ir_op_types/stmts (fires when IR is populated)
      Path C  Raw-source regex fallback  (fires for pre-0.8.0 when A+B fail)

    Path C is the fix for SolidiFI Overflow-Underflow Recall = 0%.
    """

    DETECTOR_ID      = 'arithmetic_v1'
    DETECTOR_VERSION = '2.1.0'
    VULN_TYPE        = VulnerabilityType.ARITHMETIC
    DEFAULT_SEVERITY = Severity.MEDIUM

    def __init__(self) -> None:
        self._op_finder       = _ArithOpFinder()
        self._taint_enricher  = _TaintEnricher()
        self._finding_builder = _FindingBuilder()

    def detect(
        self,
        contract:     ContractInfo,
        fn_info:      FunctionInfo,
        cfg:          CFGGraph,
        dfg:          DFGGraph,
        taint_result: Optional[TaintResult],
    ) -> List[Finding]:

        is_pre_08 = _is_pre_08(contract)

        # ── Path A: Slither-native (almost always returns []) ──────────
        native_ops = _detect_slither_native(fn_info, contract, is_pre_08)
        if native_ops:
            vulnerable: List[_ArithFinding] = [
                _ArithFinding(op=op, is_pre_08=is_pre_08)
                for op in native_ops
                if _is_vulnerable(op, is_pre_08)
            ]
            logger.debug(
                "Arithmetic[native]: '%s.%s' — %d op(s) found.",
                contract.name, fn_info.name, len(native_ops),
            )
        else:
            # ── Path B: CFG / regex ─────────────────────────────────
            if not _has_arithmetic(cfg):
                vulnerable = []
            else:
                ops = self._op_finder.find(cfg)
                vulnerable = [
                    _ArithFinding(op=op, is_pre_08=is_pre_08)
                    for op in ops
                    if _is_vulnerable(op, is_pre_08)
                ]

        # ── Path C: Raw-source fallback for pre-0.8.0 ───────────────
        # Fires only when is_pre_08 AND both A+B found nothing.
        # This is the fix for SolidiFI Overflow-Underflow Recall = 0%.
        if is_pre_08 and not vulnerable:
            fn_body      = _extract_fn_body(fn_info, contract)
            raw_findings = _raw_source_overflow_scan(fn_body, fn_info, is_pre_08)
            if raw_findings:
                logger.debug(
                    "Arithmetic[raw-fallback]: '%s.%s' — %d op(s) via raw source.",
                    contract.name, fn_info.name, len(raw_findings),
                )
            vulnerable.extend(raw_findings)

        if not vulnerable:
            return []

        # ── Step 5: Taint enrichment ─────────────────────────────────
        self._taint_enricher.enrich(vulnerable, taint_result)

        # ── Step 6: Deduplication ────────────────────────────────────
        seen_keys:    Set[Tuple[int, str]] = set()
        deduplicated: List[_ArithFinding]  = []
        for c in vulnerable:
            key = (c.op.cfg_node_id, c.op.operator)
            if key not in seen_keys:
                seen_keys.add(key)
                deduplicated.append(c)

        # ── Step 7: Build findings ───────────────────────────────────
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
                "Arithmetic: '%s.%s' — %s severity, op='%s', "
                "pre_08=%s, unchecked=%s, taint=%s, raw=%s, cvss=%.1f.",
                contract.name, fn_info.name,
                finding.severity.value, c.op.operator,
                c.is_pre_08, c.op.in_unchecked,
                c.taint_confirms, c.op.cfg_node_id == -1,
                finding.cvss_score,
            )
        return findings

    def build_recommendation(self, context: dict) -> str:
        fn_name    = context['function_name']
        operator   = context.get('operator', '?')
        operands   = context.get('operands') or []
        is_pre_08  = context.get('is_pre_08', False)
        unchecked  = context.get('in_unchecked', False)
        is_payable = context.get('is_payable', False)
        line       = context.get('line_number')
        op_name    = _OP_NAMES.get(operator.upper(), _OP_NAMES.get(operator, operator))

        loc = f' at line {line}' if line else ''
        # Use temp variable to avoid nested-quote f-string issues
        if operands:
            ops_joined = "' and '".join(operands)
            op_str = f"'{ops_joined}'"
        else:
            op_str = 'the operands'

        if is_pre_08:
            rec = (
                f"In function '{fn_name}'{loc}: the {op_name} on {op_str} "
                f"is unprotected because this contract uses Solidity < 0.8.0. "
                f"Either upgrade to Solidity ^0.8.0 (overflow reverts built-in) "
                f"or wrap the operation with OpenZeppelin SafeMath: "
                f"'using SafeMath for uint256' and replace '{operator}' with "
                f"the corresponding SafeMath method."
            )
        elif unchecked:
            rec = (
                f"In function '{fn_name}'{loc}: the {op_name} on {op_str} "
                f"is inside an 'unchecked{{}}' block which disables Solidity "
                f"0.8.0's built-in overflow protection. "
                f"Remove the 'unchecked' wrapper unless overflow is intentional "
                f"and the values are mathematically bounded by prior checks."
            )
        else:
            rec = (
                f"In function '{fn_name}'{loc}: review the {op_name} on "
                f"{op_str} for potential overflow or underflow."
            )

        if is_payable:
            rec += (
                f" '{fn_name}' is payable — an attacker can supply crafted "
                f"msg.value to trigger the overflow deliberately."
            )
        if context.get('taint_confirms'):
            src = context.get('taint_source', 'external input')
            rec += (
                f' Taint analysis confirms attacker-controlled data ({src}) '
                f'reaches this operation — treat this as high priority.'
            )
        return rec

    def calculate_cvss(self, context: dict) -> float:
        score = 6.5
        if context.get('is_pre_08'):
            score += 1.5
        if context.get('in_unchecked'):
            score += 1.0
        if context.get('taint_confirms'):
            score += 1.0
        if context.get('is_payable'):
            score += 0.5
        if context.get('function_visibility') in ('external', 'public'):
            score += 0.3
        if context.get('has_safemath'):
            score -= 2.0
        return round(max(0.0, min(10.0, score)), 1)

    @staticmethod
    def _build_context(
        c:        _ArithFinding,
        fn_info:  FunctionInfo,
        contract: ContractInfo,
    ) -> dict:
        return {
            'contract_name':       contract.name,
            'function_name':       fn_info.name,
            'function_visibility': getattr(
                fn_info.visibility, 'value', fn_info.visibility
            ),
            'is_payable': (
                getattr(fn_info.state_mutability, 'value',
                        fn_info.state_mutability) == 'payable'
            ),
            'line_number':    c.op.source_line,
            'cfg_node':       c.op.cfg_node_id,
            'operator':       c.op.operator,
            'operands':       c.op.operands,
            'in_unchecked':   c.op.in_unchecked,
            'has_safemath':   c.op.has_safemath,
            'is_pre_08':      c.is_pre_08,
            'solidity_version': contract.solidity_version,
            'taint_confirms': c.taint_confirms,
            'taint_source': (
                c.taint_source.value if c.taint_source else None
            ),
            'via_raw_source': c.op.cfg_node_id == -1,
        }