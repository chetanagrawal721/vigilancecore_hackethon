"""
core/contract_parser.py

Conversion layer between raw Slither objects and VigilanceCore's clean
model layer.

Design rules:
  1.  This file is the ONLY consumer of SlitherWrapper accessors.
  2.  No Slither types are stored, returned, or passed beyond this file.
  3.  Every Slither field access is wrapped defensively.
  4.  Output is always a valid List[ContractInfo] even if parts fail.
  5.  All enum mappings live in private helpers — never inline.
  6.  selector and signature are computed once here, not in detectors.
  7.  var_map (qualified_name → StateVariable) gives O(1) resolution.
  8.  Source file is read exactly once per contract and passed through.
  9.  Inherited state variables carry declaring contract name.
  10. Selector returns None when keccak is unavailable — never wrong data.
  11. Slither IR types imported once at module level — not in hot path.
  12. contract_hash uses normalised source — cosmetic edits don't change it.
  13. Source normalisation is string-literal-safe — comment tokens inside
      quoted strings are never removed.
  14. Selector results are cached — identical signatures hashed once only.
  15. _check_return_used() inspects IR rvalue identity, not any lvalue.
  16. value_transfer checks both .value and .call_value across Slither
      versions.
"""

from __future__ import annotations

import hashlib
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from core.enums import (
    CallType,
    ContractKind,
    StateMutability,
    Visibility,
)
from core.models import (
    ContractInfo,
    ExternalCallInfo,
    FunctionInfo,
    FunctionParameter,
    StateVariable,
)
from core.slither_wrapper import SlitherWrapper, parse_pragma_version

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Slither IR types — imported ONCE at module level
# ---------------------------------------------------------------------------

try:
    from slither.slithir.operations import HighLevelCall as _SLITHER_HIGH_LEVEL_CALL   # type: ignore[import]
    from slither.slithir.operations import LowLevelCall  as _SLITHER_LOW_LEVEL_CALL    # type: ignore[import]
    from slither.slithir.operations import LibraryCall   as _SLITHER_LIBRARY_CALL      # type: ignore[import]
    from slither.slithir.operations import Transfer      as _SLITHER_TRANSFER          # type: ignore[import]
    from slither.slithir.operations import Send          as _SLITHER_SEND              # type: ignore[import]
    from slither.slithir.operations import Assignment    as _SLITHER_ASSIGNMENT        # type: ignore[import]
    logger.debug("Slither IR types imported successfully.")
except Exception:  # noqa: BLE001
    _SLITHER_HIGH_LEVEL_CALL = None   # type: ignore[assignment,misc]
    _SLITHER_LOW_LEVEL_CALL  = None   # type: ignore[assignment,misc]
    _SLITHER_LIBRARY_CALL    = None   # type: ignore[assignment,misc]
    _SLITHER_TRANSFER        = None   # type: ignore[assignment,misc]
    _SLITHER_SEND            = None   # type: ignore[assignment,misc]
    _SLITHER_ASSIGNMENT      = None   # type: ignore[assignment,misc]
    logger.debug("Slither IR types unavailable — heuristic fallbacks active.")


# ---------------------------------------------------------------------------
# Compiled regexes — module level so they are never recompiled per call
# ---------------------------------------------------------------------------

_RE_MULTI_COMMENT  = re.compile(r"/\*.*?\*/",  re.DOTALL)
_RE_SINGLE_COMMENT = re.compile(r"//[^\n]*")
_RE_WHITESPACE     = re.compile(r"\s+")          # precompiled — runs many times


# ---------------------------------------------------------------------------
# Selector cache — identical signatures keccak-hashed only once
# ---------------------------------------------------------------------------

_selector_cache: Dict[str, Optional[str]] = {}


# ---------------------------------------------------------------------------
# Source normalisation
# ---------------------------------------------------------------------------


def _normalise_source(source: str) -> str:
    """
    Strip Solidity comments and collapse whitespace for stable hashing.

    Comment removal is STRING-LITERAL SAFE: tokens that appear inside
    single-quoted or double-quoted strings are never removed.

    Algorithm:
      Pass 1 — character-by-character scan building a comment-free copy.
               Tracks whether we are inside a string literal so that
               '//' or '/*' inside a string is preserved verbatim.
      Pass 2 — collapse all whitespace runs to a single space.

    This means:
        string url = "https://example.com";  // website
    becomes:
        string url = "https://example.com";
    not:
        string url = "https:
    """
    result:     list  = []
    i:          int   = 0
    n:          int   = len(source)
    in_string:  str   = ""    # "" means not in a string; otherwise the quote char

    while i < n:
        ch = source[i]

        # ── Handle string literal boundaries ────────────────────────
        if in_string:
            result.append(ch)
            if ch == "\\" and i + 1 < n:
                # Escaped character — append next char verbatim
                i += 1
                result.append(source[i])
            elif ch == in_string:
                in_string = ""
            i += 1
            continue

        if ch in ('"', "'"):
            in_string = ch
            result.append(ch)
            i += 1
            continue

        # ── Multi-line comment  /* ... */ ───────────────────────────
        if ch == "/" and i + 1 < n and source[i + 1] == "*":
            # Skip until closing */
            end = source.find("*/", i + 2)
            if end == -1:
                break                 # Unclosed comment — skip rest
            i = end + 2
            result.append(" ")       # Replace with single space
            continue

        # ── Single-line comment  // ... ─────────────────────────────
        if ch == "/" and i + 1 < n and source[i + 1] == "/":
            # Skip until end of line
            end = source.find("\n", i + 2)
            if end == -1:
                break                 # Comment runs to EOF
            i = end                   # Keep the newline itself
            continue

        result.append(ch)
        i += 1

    normalised = "".join(result)
    normalised = _RE_WHITESPACE.sub(" ", normalised)
    return normalised.strip()


# ---------------------------------------------------------------------------
# Enum resolution helpers
# ---------------------------------------------------------------------------


def _resolve_visibility(raw: str) -> Visibility:
    """
    Map a Slither visibility string to our Visibility enum.

    Fallback is INTERNAL — Solidity's actual default visibility for
    state variables and functions that lack an explicit specifier.
    """
    _MAP = {
        "public":   Visibility.PUBLIC,
        "external": Visibility.EXTERNAL,
        "internal": Visibility.INTERNAL,
        "private":  Visibility.PRIVATE,
    }
    return _MAP.get(str(raw).lower().strip(), Visibility.INTERNAL)


def _resolve_mutability(sf: Any) -> StateMutability:
    """
    Extract state mutability from a Slither function object.

    Tries both attribute names Slither uses across versions:
        stateMutability  (older Slither)
        state_mutability (newer Slither)
    """
    _MAP = {
        "pure":       StateMutability.PURE,
        "view":       StateMutability.VIEW,
        "nonpayable": StateMutability.NONPAYABLE,
        "payable":    StateMutability.PAYABLE,
    }
    raw = (
        getattr(sf, "stateMutability",  None)
        or getattr(sf, "state_mutability", None)
        or "nonpayable"
    )
    return _MAP.get(str(raw).lower().strip(), StateMutability.UNKNOWN)


def _resolve_contract_kind(sc: Any) -> ContractKind:
    """Determine whether the Slither contract is a contract, interface, or library."""
    try:
        if getattr(sc, "is_interface", False):
            return ContractKind.INTERFACE
        if getattr(sc, "is_library", False):
            return ContractKind.LIBRARY
    except Exception:  # noqa: BLE001
        pass
    return ContractKind.CONTRACT


def _resolve_call_type(call_expr: Any) -> CallType:
    """
    Classify a Slither call expression into our CallType enum.

    Strategy order (most to least reliable):
      1. isinstance() on module-level Slither IR types
      2. .type_call attribute string  (LowLevelCall specific)
      3. Class name substring         (version-tolerant fallback)
      4. Callee string heuristics     (last resort)
    """
    # Strategy 1 — isinstance (zero import overhead, most reliable)
    if _SLITHER_LOW_LEVEL_CALL and isinstance(call_expr, _SLITHER_LOW_LEVEL_CALL):
        type_str = str(getattr(call_expr, "type_call", "") or "").lower()
        if "delegatecall" in type_str:
            return CallType.DELEGATECALL
        if "staticcall" in type_str:
            return CallType.STATICCALL
        return CallType.CALL

    if _SLITHER_TRANSFER and isinstance(call_expr, _SLITHER_TRANSFER):
        return CallType.TRANSFER

    if _SLITHER_SEND and isinstance(call_expr, _SLITHER_SEND):
        return CallType.SEND

    if _SLITHER_LIBRARY_CALL and isinstance(call_expr, _SLITHER_LIBRARY_CALL):
        return CallType.HIGH_LEVEL

    if _SLITHER_HIGH_LEVEL_CALL and isinstance(call_expr, _SLITHER_HIGH_LEVEL_CALL):
        return CallType.HIGH_LEVEL

    # Strategy 2 — .type_call attribute
    try:
        type_str = str(getattr(call_expr, "type_call", "") or "").lower()
        if "delegatecall" in type_str:
            return CallType.DELEGATECALL
        if "staticcall" in type_str:
            return CallType.STATICCALL
        if "call" in type_str:
            return CallType.CALL
    except Exception:  # noqa: BLE001
        pass

    # Strategy 3 — class name
    try:
        class_name = type(call_expr).__name__.lower()
        if "highlevel" in class_name or "library" in class_name:
            return CallType.HIGH_LEVEL
        if "transfer" in class_name:
            return CallType.TRANSFER
        if "send" in class_name:
            return CallType.SEND
        if "lowlevel" in class_name:
            return CallType.CALL
    except Exception:  # noqa: BLE001
        pass

    # Strategy 4 — callee string (last resort)
    try:
        callee_str = str(
            getattr(call_expr, "called",     "")
            or getattr(call_expr, "expression", "")
            or ""
        ).lower()
        if "delegatecall" in callee_str:
            return CallType.DELEGATECALL
        if "staticcall" in callee_str:
            return CallType.STATICCALL
        if ".transfer" in callee_str:
            return CallType.TRANSFER
        if ".send(" in callee_str:
            return CallType.SEND
        if ".call" in callee_str:
            return CallType.CALL
    except Exception:  # noqa: BLE001
        pass

    return CallType.UNKNOWN


# ---------------------------------------------------------------------------
# Signature and selector
# ---------------------------------------------------------------------------


def _compute_signature(
    fn_name: str,
    params: Tuple[FunctionParameter, ...],
) -> str:
    """
    Build the ABI-canonical function signature string.

    Example:
        "transfer", [FunctionParameter("to","address"), ...]
        → "transfer(address,uint256)"
    """
    param_types = ",".join(p.type for p in params)
    return f"{fn_name}({param_types})"


def _compute_selector(signature: str) -> Optional[str]:
    """
    Compute the 4-byte keccak256 selector for a function signature.

    Results are cached in _selector_cache so identical signatures
    (e.g. ERC-20 transfer across hundreds of contracts) are hashed
    exactly once per process lifetime.

    Returns None if no keccak library is available — NEVER returns
    incorrect data from the wrong hash function.

    Example:
        "transfer(address,uint256)" → "0xa9059cbb"
    """
    # Cache hit
    if signature in _selector_cache:
        return _selector_cache[signature]

    result: Optional[str] = None

    # Attempt 1 — eth_hash (standard in Slither environments)
    try:
        from eth_hash.auto import keccak  # type: ignore[import]
        digest = keccak(signature.encode("utf-8"))
        result = "0x" + digest[:4].hex()
    except Exception:  # noqa: BLE001
        pass

    # Attempt 2 — eth_utils
    if result is None:
        try:
            from eth_utils import keccak as eth_keccak  # type: ignore[import]
            digest = eth_keccak(text=signature)
            result = "0x" + digest[:4].hex()
        except Exception:  # noqa: BLE001
            pass

    if result is None:
        logger.debug(
            "keccak unavailable — selector not computed for '%s'. "
            "Install eth-hash or eth-utils.",
            signature,
        )

    _selector_cache[signature] = result
    return result


# ---------------------------------------------------------------------------
# Reentrancy guard detection
# ---------------------------------------------------------------------------

_REENTRANCY_GUARD_MODIFIERS: frozenset = frozenset({
    "nonreentrant",
    "noreentrancy",
    "reentrancyguard",
    "mutex",
    "protected",
    "lock",
    "islocked",
})


def _detect_reentrancy_guard(modifiers: Tuple[str, ...]) -> bool:
    """Return True if any modifier is a known reentrancy guard."""
    return any(m.lower() in _REENTRANCY_GUARD_MODIFIERS for m in modifiers)


# ---------------------------------------------------------------------------
# var_map builder
# ---------------------------------------------------------------------------


def _build_var_map(
    state_vars: Tuple[StateVariable, ...]
) -> Dict[str, StateVariable]:
    """Build qualified_name → StateVariable for O(1) resolution."""
    return {v.qualified_name: v for v in state_vars}


# ---------------------------------------------------------------------------
# ContractParser
# ---------------------------------------------------------------------------


class ContractParser:
    """
    Converts raw Slither objects into VigilanceCore's clean model layer.

    Usage
    -----
        wrapper   = SlitherWrapper(input_path="contracts/Bank.sol")
        result    = wrapper.run()

        if result.success:
            parser    = ContractParser(wrapper)
            contracts = parser.parse()
            # contracts → List[ContractInfo]
            # Slither never referenced again past this point.

    One ContractParser instance per analysis run.
    """

    def __init__(self, wrapper: SlitherWrapper) -> None:
        self._wrapper = wrapper

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def parse(self) -> List[ContractInfo]:
        """
        Parse all contracts in the compilation unit.

        Returns List[ContractInfo]. Returns [] if wrapper has no
        Slither instance. Individual contract failures are skipped.
        """
        slither_contracts = self._wrapper.get_contracts()
        if not slither_contracts:
            logger.warning("No contracts found in Slither output.")
            return []

        results: List[ContractInfo] = []
        for sc in slither_contracts:
            name = self._safe_str(getattr(sc, "name", "<unknown>"))
            try:
                contract_info = self._parse_contract(sc)
                results.append(contract_info)
                logger.debug(
                    "Parsed contract '%s' (%s) — %d functions, %d state vars.",
                    contract_info.name,
                    contract_info.kind.value,
                    len(contract_info.functions),
                    len(contract_info.state_variables),
                )
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Failed to parse contract '%s': %s — skipping.",
                    name, exc,
                )

        return results

    # ------------------------------------------------------------------
    # Contract conversion
    # ------------------------------------------------------------------

    def _parse_contract(self, sc: Any) -> ContractInfo:
        """Convert a single Slither contract object into ContractInfo."""

        name        = self._safe_str(getattr(sc, "name", "UnknownContract"))
        kind        = _resolve_contract_kind(sc)
        source_file = self._extract_source_file(sc)

        # Read source ONCE — reused for version detection and hashing
        raw_source = self._read_source_file(source_file)

        solidity_version = self._extract_solidity_version(sc, raw_source)

        # Hash normalised source — cosmetic edits don't change the hash
        contract_hash: Optional[str] = None
        if raw_source:
            normalised    = _normalise_source(raw_source)
            contract_hash = hashlib.sha256(
                normalised.encode("utf-8")
            ).hexdigest()

        base_contracts = self._extract_base_contracts(sc, name)

        # ── State variables ──────────────────────────────────────────
        slither_vars    = self._wrapper.get_state_variables(sc)
        state_variables = tuple(
            sv for sv in (
                self._safe_parse_state_variable(v, name)
                for v in slither_vars
            )
            if sv is not None
        )

        var_map = _build_var_map(state_variables)

        # ── Functions ────────────────────────────────────────────────
        slither_fns = self._wrapper.get_functions(sc)
        functions   = tuple(
            fn for fn in (
                self._safe_parse_function(f, name, var_map)
                for f in slither_fns
            )
            if fn is not None
        )

        return ContractInfo(
            name=name,
            kind=kind,
            solidity_version=solidity_version,
            source_file=source_file,
            contract_address=None,
            contract_hash=contract_hash,
            state_variables=state_variables,
            functions=functions,
            base_contracts=base_contracts,
            derived_contracts=tuple(),
            raw_source=raw_source,
        )

    # ------------------------------------------------------------------
    # State variable conversion
    # ------------------------------------------------------------------

    def _safe_parse_state_variable(
        self, sv: Any, contract_name: str
    ) -> Optional[StateVariable]:
        try:
            return self._parse_state_variable(sv, contract_name)
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "Skipping state variable in '%s': %s", contract_name, exc
            )
            return None

    def _parse_state_variable(
        self, sv: Any, contract_name: str
    ) -> StateVariable:
        """
        Convert a Slither state variable into StateVariable.

        qualified_name uses the DECLARING contract name so inherited
        variables keep their true identity across the chain.
        """
        name = self._safe_str(getattr(sv, "name", "unknown"))

        decl_contract  = getattr(sv, "contract", None)
        decl_name      = self._safe_str(
            getattr(decl_contract, "name", None) or contract_name
        )
        qualified_name = f"{decl_name}.{name}"

        type_str       = self._extract_type_str(sv)
        visibility     = _resolve_visibility(
            getattr(sv, "visibility", "internal") or "internal"
        )
        is_constant    = bool(getattr(sv, "is_constant",  False))
        is_immutable   = bool(getattr(sv, "is_immutable", False))
        is_publicly_writable = (
            visibility == Visibility.PUBLIC
            and not is_constant
            and not is_immutable
        )

        source_file, start_line, end_line = self._wrapper.get_source_mapping(sv)

        return StateVariable(
            name=name,
            qualified_name=qualified_name,
            type=type_str,
            visibility=visibility,
            is_constant=is_constant,
            is_immutable=is_immutable,
            is_publicly_writable=is_publicly_writable,
            start_line=start_line,
            end_line=end_line,
            source_file=source_file,
        )

    # ------------------------------------------------------------------
    # Function conversion
    # ------------------------------------------------------------------

    def _safe_parse_function(
        self,
        sf: Any,
        contract_name: str,
        var_map: Dict[str, StateVariable],
    ) -> Optional[FunctionInfo]:
        try:
            return self._parse_function(sf, contract_name, var_map)
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "Skipping function '%s' in '%s': %s",
                getattr(sf, "name", "<unknown>"), contract_name, exc,
            )
            return None

    def _parse_function(
        self,
        sf: Any,
        contract_name: str,
        var_map: Dict[str, StateVariable],
    ) -> FunctionInfo:
        """Convert a Slither function object into FunctionInfo."""

        name             = self._safe_str(getattr(sf, "name", "unknown"))
        visibility       = _resolve_visibility(
            getattr(sf, "visibility", "internal") or "internal"
        )
        state_mutability = _resolve_mutability(sf)

        is_constructor = bool(getattr(sf, "is_constructor", False))
        is_fallback    = bool(getattr(sf, "is_fallback",    False))
        is_receive     = bool(getattr(sf, "is_receive",     False))
        is_virtual     = bool(getattr(sf, "is_virtual",     False))
        is_override    = bool(getattr(sf, "is_overridden",  False))

        parameters = tuple(
            p for p in (
                self._safe_parse_parameter(param)
                for param in (getattr(sf, "parameters",  None) or [])
            )
            if p is not None
        )
        returns = tuple(
            p for p in (
                self._safe_parse_parameter(ret)
                for ret in (getattr(sf, "return_type", None) or [])
            )
            if p is not None
        )

        modifiers  = self._extract_modifier_names(sf)
        signature  = _compute_signature(name, parameters)
        selector   = _compute_selector(signature)

        state_vars_read = self._resolve_state_vars(
            getattr(sf, "state_variables_read",    None) or [],
            contract_name, var_map,
        )
        state_vars_written = self._resolve_state_vars(
            getattr(sf, "state_variables_written", None) or [],
            contract_name, var_map,
        )

        raw_calls      = self._wrapper.get_external_calls(sf)
        external_calls = tuple(
            ec for ec in (
                self._safe_parse_external_call(node, call_expr)
                for node, call_expr in raw_calls
            )
            if ec is not None
        )

        events_emitted       = tuple(self._wrapper.get_events_emitted(sf))
        has_reentrancy_guard = _detect_reentrancy_guard(modifiers)
        cfg_node_count       = self._count_cfg_nodes(sf)

        source_file, start_line, end_line = self._wrapper.get_source_mapping(sf)
        natspec = self._extract_natspec(sf)

        return FunctionInfo(
            name=name,
            visibility=visibility,
            state_mutability=state_mutability,
            signature=signature,
            selector=selector,
            is_constructor=is_constructor,
            is_fallback=is_fallback,
            is_receive=is_receive,
            is_virtual=is_virtual,
            is_override=is_override,
            parameters=parameters,
            returns=returns,
            modifiers=modifiers,
            state_vars_read=state_vars_read,
            state_vars_written=state_vars_written,
            external_calls=external_calls,
            events_emitted=events_emitted,
            has_reentrancy_guard=has_reentrancy_guard,
            cfg_node_count=cfg_node_count,
            dfg_node_count=0,
            start_line=start_line,
            end_line=end_line,
            source_file=source_file,
            natspec=natspec,
        )

    # ------------------------------------------------------------------
    # Parameter conversion
    # ------------------------------------------------------------------

    def _safe_parse_parameter(self, param: Any) -> Optional[FunctionParameter]:
        try:
            return self._parse_parameter(param)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Skipping parameter: %s", exc)
            return None

    def _parse_parameter(self, param: Any) -> FunctionParameter:
        name     = self._safe_str(getattr(param, "name", "") or "")
        type_str = self._extract_type_str(param)

        location: Optional[str] = None
        try:
            loc_raw = str(
                getattr(param, "location", None) or ""
            ).lower().strip()
            if loc_raw in ("memory", "storage", "calldata"):
                location = loc_raw
        except Exception:  # noqa: BLE001
            pass

        return FunctionParameter(
            name=name,
            type=type_str,
            location=location,
            indexed=bool(getattr(param, "indexed", False)),
        )

    # ------------------------------------------------------------------
    # External call conversion
    # ------------------------------------------------------------------

    def _safe_parse_external_call(
        self, node: Any, call_expr: Any
    ) -> Optional[ExternalCallInfo]:
        try:
            return self._parse_external_call(node, call_expr)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Skipping external call: %s", exc)
            return None

    def _parse_external_call(
        self, node: Any, call_expr: Any
    ) -> ExternalCallInfo:
        """Convert a (Slither CFG node, call expression) into ExternalCallInfo."""

        callee = self._safe_str(
            getattr(call_expr, "called",     None)
            or getattr(call_expr, "expression", None)
            or "<unknown call>"
        )

        call_type = _resolve_call_type(call_expr)

        target_contract: Optional[str] = None
        target_function: Optional[str] = None
        try:
            dest = getattr(call_expr, "destination", None)
            if dest is not None:
                target_contract = self._safe_str(
                    getattr(dest, "type", None) or getattr(dest, "name", None)
                )
            fn_called = getattr(call_expr, "function", None)
            if fn_called is not None:
                target_function = self._safe_str(
                    getattr(fn_called, "name", None)
                )
        except Exception:  # noqa: BLE001
            pass

        # value_transfer — check both .value and .call_value across
        # Slither versions; Solidity ≥0.7 call{value: x}("") syntax
        # may expose either attribute depending on Slither version.
        value_transfer = False
        try:
            value_transfer = (
                getattr(call_expr, "value",      None) is not None
                or getattr(call_expr, "call_value", None) is not None
            )
        except Exception:  # noqa: BLE001
            pass

        is_return_checked = self._check_return_used(node, call_expr)

        source_file, start_line, end_line = self._wrapper.get_source_mapping(node)

        return ExternalCallInfo(
            callee=callee,
            call_type=call_type,
            target_contract=target_contract,
            target_function=target_function,
            value_transfer=value_transfer,
            is_return_checked=is_return_checked,
            start_line=start_line,
            end_line=end_line,
            source_file=source_file,
        )

    @staticmethod
    def _check_return_used(node: Any, call_expr: Any) -> bool:
        """
        Determine whether the return value of a call is used.

        Strategy (IR-object based — no string parsing):
          1. call_expr.lvalue present → return value directly assigned
          2. Scan node.irs for an Assignment whose rvalue IS this exact
             call_expr object (identity check — avoids false positives
             from unrelated assignments in the same node)
          3. Slither's is_unchecked marker
          4. Conservative default → True (avoids false positives)

        Note on strategy 2:
            We check  ir.rvalue is call_expr  (identity, not equality).
            This prevents  x = 5  before the call from being mistaken
            for the call's return value being used.
        """
        # Strategy 1 — lvalue directly on the call expression
        try:
            if getattr(call_expr, "lvalue", None) is not None:
                return True
        except Exception:  # noqa: BLE001
            pass

        # Strategy 2 — scan IR ops for Assignment whose rvalue is this call
        try:
            for ir in (getattr(node, "irs", None) or []):
                if _SLITHER_ASSIGNMENT and isinstance(ir, _SLITHER_ASSIGNMENT):
                    if getattr(ir, "rvalue", None) is call_expr:
                        return True
        except Exception:  # noqa: BLE001
            pass

        # Strategy 3 — explicit Slither unchecked marker
        try:
            if bool(getattr(node, "is_unchecked", False)):
                return False
        except Exception:  # noqa: BLE001
            pass

        # Default — conservative, avoids false positives
        return True

    # ------------------------------------------------------------------
    # State variable resolution
    # ------------------------------------------------------------------

    def _resolve_state_vars(
        self,
        slither_vars: list,
        contract_name: str,
        var_map: Dict[str, StateVariable],
    ) -> Tuple[StateVariable, ...]:
        """
        Convert Slither state variable references into our StateVariable
        objects.

        - O(1) lookup for declared variables via var_map
        - Minimal StateVariable for inherited variables
        - seen set prevents duplicates across deep inheritance chains
        """
        resolved: List[StateVariable] = []
        seen: Set[str] = set()

        for sv in slither_vars:
            try:
                name           = self._safe_str(getattr(sv, "name", ""))
                decl_contract  = getattr(sv, "contract", None)
                decl_name      = self._safe_str(
                    getattr(decl_contract, "name", None) or contract_name
                )
                qualified_name = f"{decl_name}.{name}"

                if qualified_name in seen:
                    continue
                seen.add(qualified_name)

                if qualified_name in var_map:
                    resolved.append(var_map[qualified_name])
                else:
                    resolved.append(StateVariable(
                        name=name,
                        qualified_name=qualified_name,
                        type=self._extract_type_str(sv),
                        visibility=_resolve_visibility(
                            getattr(sv, "visibility", "internal") or "internal"
                        ),
                        is_constant=bool(getattr(sv, "is_constant",  False)),
                        is_immutable=bool(getattr(sv, "is_immutable", False)),
                        is_publicly_writable=False,
                        start_line=None,
                        end_line=None,
                        source_file=None,
                    ))
            except Exception as exc:  # noqa: BLE001
                logger.debug("Could not resolve state variable ref: %s", exc)

        return tuple(resolved)

    # ------------------------------------------------------------------
    # Extraction utilities
    # ------------------------------------------------------------------

    def _extract_type_str(self, slither_obj: Any) -> str:
        """
        Extract the Solidity type string from any Slither object.

        Priority per attribute:
          1. canonical_name  — most reliable; handles mappings, arrays,
                               structs correctly
          2. .type           — nested type object
          3. .name           — named type
          4. str(val)        — generic last resort

        Tries attribute names Slither uses across versions.
        """
        for attr in ("type", "type_str", "_variable_type"):
            try:
                val = getattr(slither_obj, attr, None)
                if val is None:
                    continue

                # Priority 1 — canonical_name
                canonical = getattr(val, "canonical_name", None)
                if canonical:
                    return str(canonical)

                # Priority 2 — nested type object
                nested = getattr(val, "type", None)
                if nested is not None:
                    return getattr(nested, "canonical_name", str(nested))

                # Priority 3 — named type
                named = getattr(val, "name", None)
                if named is not None:
                    return str(named)

                # Priority 4 — str()
                type_str = str(val)
                if type_str and type_str != "None":
                    return type_str

            except Exception:  # noqa: BLE001
                pass

        return "unknown"

    def _extract_modifier_names(self, sf: Any) -> Tuple[str, ...]:
        try:
            mods = getattr(sf, "modifiers", None) or []
            return tuple(
                self._safe_str(getattr(m, "name", m)) for m in mods
            )
        except Exception:  # noqa: BLE001
            return tuple()

    def _extract_natspec(self, sf: Any) -> Optional[str]:
        for attr in ("natspec", "documentation", "_doc"):
            try:
                val = getattr(sf, attr, None)
                if val:
                    return str(val)
            except Exception:  # noqa: BLE001
                pass
        return None

    def _extract_solidity_version(
        self,
        sc: Any,
        raw_source: Optional[str],
    ) -> Optional[str]:
        """
        Priority:
          1. Slither compilation_unit.solc_version (no file IO)
          2. Pragma parsed from already-read raw_source (no extra IO)
        """
        try:
            cu = getattr(sc, "compilation_unit", None)
            if cu:
                ver = getattr(cu, "solc_version", None)
                if ver:
                    return str(ver)
        except Exception:  # noqa: BLE001
            pass

        if raw_source:
            return parse_pragma_version(raw_source)
        return None

    def _extract_source_file(self, sc: Any) -> Optional[str]:
        """Extract the absolute source file path for a contract."""
        for attr in ("source_mapping", "compilation_unit"):
            try:
                obj = getattr(sc, attr, None)
                if obj:
                    fn = getattr(obj, "filename", None)
                    if fn:
                        absolute = getattr(fn, "absolute", None)
                        relative = getattr(fn, "relative", None)
                        return str(absolute or relative or fn)
            except Exception:  # noqa: BLE001
                pass
        try:
            fn = getattr(sc, "file_scope", None)
            if fn:
                return str(getattr(fn, "filename", fn))
        except Exception:  # noqa: BLE001
            pass
        return None

    def _read_source_file(self, source_file: Optional[str]) -> Optional[str]:
        """Read raw source text exactly once. Returns None if unreadable."""
        if not source_file:
            return None
        try:
            return Path(source_file).read_text(encoding="utf-8", errors="ignore")
        except Exception:  # noqa: BLE001
            return None

    def _extract_base_contracts(
        self, sc: Any, self_name: str
    ) -> Tuple[str, ...]:
        """Extract parent contract names in C3 linearisation order."""
        try:
            inheritance = getattr(sc, "inheritance", None) or []
            return tuple(
                self._safe_str(getattr(base, "name", base))
                for base in inheritance
                if self._safe_str(getattr(base, "name", base)) != self_name
            )
        except Exception:  # noqa: BLE001
            return tuple()

    def _count_cfg_nodes(self, sf: Any) -> int:
        try:
            nodes = getattr(sf, "nodes", None)
            return len(nodes) if nodes else 0
        except Exception:  # noqa: BLE001
            return 0

    @staticmethod
    def _safe_str(value: Any) -> str:
        """Convert any value to a stripped non-None string."""
        if value is None:
            return ""
        return str(value).strip()
