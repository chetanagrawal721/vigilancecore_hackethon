"""
core/models.py

Production-grade data models for VigilanceCore.

Design rules:
  1. Zero analysis logic — only data containers.
  2. Parsed contract models are frozen dataclasses (immutable).
  3. Mutable analysis outputs (Finding, AnalysisResult) are NOT frozen.
  4. All enums imported from core/enums.py — never redefined here.
  5. External calls are fully structured via ExternalCallInfo.
  6. State variable references carry full objects, not bare name strings.
  7. Finding carries a stable UUID hex ID and validates numeric fields.
  8. AnalysisResult caches confirmed_findings and invalidates on mutation.
  9. Large string fields use repr=False to keep debug output clean.
 10. All models expose a typed as_dict() for JSON serialisation.

Change log:
  v1.1.0  ADD  ScanStats dataclass — per-scan counters produced by
               AnalysisEngine and attached to every AnalysisResult.
               Moved here from analysis_engine.py because it is a
               pure data model, not engine logic.
          FIX  AnalysisResult.contracts renamed from .contract and
               typed as List[ContractInfo] — no metadata loss when a
               file contains multiple contracts.
          ADD  AnalysisResult.source_file: str — scanned .sol path
               always stored in result, even on parse failure.
          ADD  AnalysisResult.stats: ScanStats — replaces bare
               analysis_time_ms field; elapsed_ms lives in ScanStats.
          ADD  AnalysisResult.detector_crash_count property.
          UPD  AnalysisResult.as_dict() updated for new fields.
          UPD  __all__ includes ScanStats.
"""

from __future__ import annotations

import solcx
solcx.set_solc_version("0.8.21")

import hashlib
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.enums import (
    CallType,
    ContractKind,
    Severity,
    StateMutability,
    Visibility,
    VulnerabilityType,
)


# ---------------------------------------------------------------------------
# Immutable sub-models
# ---------------------------------------------------------------------------

@dataclass(slots=True, frozen=True)
class StateVariable:
    """
    Immutable representation of a single Solidity state variable.

    Fields
    ------
    name                : Solidity identifier (e.g. "balances")
    qualified_name      : Contract-scoped name (e.g. "ERC20.balances")
                          Prevents collisions in deep inheritance chains.
    type                : Solidity type string
    visibility          : Visibility modifier
    is_constant         : True if declared `constant`
    is_immutable        : True if declared `immutable`
    is_publicly_writable: True if an unguarded public setter exists
    start_line          : First source line (1-indexed)
    end_line            : Last source line
    source_file         : Path to the .sol file (relative to project root)
    """
    name:                 str
    qualified_name:       str
    type:                 str
    visibility:           Visibility
    is_constant:          bool          = False
    is_immutable:         bool          = False
    is_publicly_writable: bool          = False
    start_line:           Optional[int] = None
    end_line:             Optional[int] = None
    source_file:          Optional[str] = field(default=None, repr=False)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name":                 self.name,
            "qualified_name":       self.qualified_name,
            "type":                 self.type,
            "visibility":           self.visibility.value,
            "is_constant":          self.is_constant,
            "is_immutable":         self.is_immutable,
            "is_publicly_writable": self.is_publicly_writable,
            "start_line":           self.start_line,
            "end_line":             self.end_line,
            "source_file":          self.source_file,
        }


@dataclass(slots=True, frozen=True)
class FunctionParameter:
    """
    Immutable representation of a single function parameter or
    return value.

    Fields
    ------
    name     : Solidity identifier (may be empty for unnamed returns)
    type     : Solidity type string
    location : Data location — "memory" | "storage" | "calldata" | None
               (None for value types)
    indexed  : True for event parameters declared `indexed`
    """
    name:     str
    type:     str
    location: Optional[str] = None
    indexed:  bool           = False

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name":     self.name,
            "type":     self.type,
            "location": self.location,
            "indexed":  self.indexed,
        }


@dataclass(slots=True, frozen=True)
class ExternalCallInfo:
    """
    Structured representation of a single external call made inside
    a function body.

    Using a proper model instead of raw strings lets detectors reason
    precisely about reentrancy, delegatecall, unchecked returns, and
    ETH-transfer patterns without re-parsing source text.

    Fields
    ------
    callee             : Human-readable target expression
                         (e.g. "msg.sender.call", "token.transferFrom")
    call_type          : Broad category — see CallType enum
    target_contract    : Resolved external contract name (or None)
    target_function    : Resolved function name on the target (or None)
    value_transfer     : True if ETH is transferred (call{value: …})
    is_return_checked  : False if the boolean return is discarded entirely
    start_line         : Line of the call expression
    end_line           : End line (same as start_line for one-liners)
    source_file        : Path to the .sol file
    """
    callee:            str
    call_type:         CallType     = CallType.UNKNOWN
    target_contract:   Optional[str] = None
    target_function:   Optional[str] = None
    value_transfer:    bool          = False
    is_return_checked: bool          = True
    start_line:        Optional[int] = None
    end_line:          Optional[int] = None
    source_file:       Optional[str] = field(default=None, repr=False)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "callee":            self.callee,
            "call_type":         self.call_type.value,
            "target_contract":   self.target_contract,
            "target_function":   self.target_function,
            "value_transfer":    self.value_transfer,
            "is_return_checked": self.is_return_checked,
            "start_line":        self.start_line,
            "end_line":          self.end_line,
            "source_file":       self.source_file,
        }


# ---------------------------------------------------------------------------
# Primary contract models — all frozen
# ---------------------------------------------------------------------------

@dataclass(slots=True, frozen=True)
class FunctionInfo:
    """
    Immutable parsed representation of a single Solidity function.

    This is the primary unit passed to every detector.

    Fields
    ------
    name                : Solidity function identifier
    signature           : ABI-style signature string, e.g.
                          "transfer(address,uint256)"
                          Pre-computed once by the parser.
    selector            : 4-byte keccak selector as hex string, e.g.
                          "0xa9059cbb"
                          Used by detectors that match on selectors.
    visibility          : Visibility modifier
    state_mutability    : pure / view / nonpayable / payable
    is_constructor      : True if this is the constructor
    is_fallback         : True if this is fallback()
    is_receive          : True if this is receive()
    is_virtual          : True if declared virtual
    is_override         : True if declared override
    parameters          : Ordered input parameters (frozen tuple)
    returns             : Ordered return parameters (frozen tuple)
    modifiers           : Applied modifier names (frozen tuple)
    state_vars_read     : Full StateVariable objects read in body
                          (tuple preserves declaration order)
    state_vars_written  : Full StateVariable objects written in body
    external_calls      : Structured external call descriptors (ordered
                          by appearance in body)
    events_emitted      : Names of events emitted — used by front-running
                          and logic-error detectors
    cfg_node_count      : Number of CFG nodes (0 until cfg_builder runs)
    dfg_node_count      : Number of DFG nodes (0 until cfg_builder runs)
    has_reentrancy_guard: True if a recognised guard modifier is present
    start_line          : First line of the function signature
    end_line            : Closing brace line
    source_file         : Path to the .sol file
    natspec             : Full NatSpec comment block (if any)
    """
    name:             str
    visibility:       Visibility
    state_mutability: StateMutability

    # Pre-computed ABI identifiers
    signature: Optional[str] = None
    selector:  Optional[str] = None

    is_constructor: bool = False
    is_fallback:    bool = False
    is_receive:     bool = False
    is_virtual:     bool = False
    is_override:    bool = False

    parameters: tuple[FunctionParameter, ...] = field(default_factory=tuple)
    returns:    tuple[FunctionParameter, ...] = field(default_factory=tuple)
    modifiers:  tuple[str, ...]               = field(default_factory=tuple)

    state_vars_read:    tuple[StateVariable, ...]    = field(default_factory=tuple)
    state_vars_written: tuple[StateVariable, ...]    = field(default_factory=tuple)
    external_calls:     tuple[ExternalCallInfo, ...] = field(default_factory=tuple)
    events_emitted:     tuple[str, ...]              = field(default_factory=tuple)

    cfg_node_count:      int  = 0
    dfg_node_count:      int  = 0
    has_reentrancy_guard: bool = False

    start_line:  Optional[int] = None
    end_line:    Optional[int] = None
    source_file: Optional[str] = field(default=None, repr=False)
    natspec:     Optional[str] = field(default=None, repr=False)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name":               self.name,
            "signature":          self.signature,
            "selector":           self.selector,
            "visibility":         self.visibility.value,
            "state_mutability":   self.state_mutability.value,
            "is_constructor":     self.is_constructor,
            "is_fallback":        self.is_fallback,
            "is_receive":         self.is_receive,
            "is_virtual":         self.is_virtual,
            "is_override":        self.is_override,
            "parameters":         [p.as_dict() for p in self.parameters],
            "returns":            [r.as_dict() for r in self.returns],
            "modifiers":          list(self.modifiers),
            "state_vars_read":    [v.as_dict() for v in self.state_vars_read],
            "state_vars_written": [v.as_dict() for v in self.state_vars_written],
            "external_calls":     [c.as_dict() for c in self.external_calls],
            "events_emitted":     list(self.events_emitted),
            "cfg_node_count":     self.cfg_node_count,
            "dfg_node_count":     self.dfg_node_count,
            "has_reentrancy_guard": self.has_reentrancy_guard,
            "start_line":         self.start_line,
            "end_line":           self.end_line,
            "source_file":        self.source_file,
            "natspec":            self.natspec,
        }


@dataclass(slots=True, frozen=True)
class ContractInfo:
    """
    Immutable parsed representation of a single Solidity contract.

    Produced by core/contract_parser.py once per contract.
    Passed read-only to every detector and report generator.
    Slither objects never appear here — the parser absorbs all
    Slither-specific types before constructing this model.

    Fields
    ------
    name              : Contract identifier
    kind              : contract / interface / library
    solidity_version  : Pragma version string (e.g. "^0.8.21")
    source_file       : Path to the .sol file (relative to root)
    contract_address  : Checksummed hex address — set when analysing
                        deployed/on-chain contracts, None otherwise
    contract_hash     : SHA-256 of the raw source — used to detect
                        whether the contract changed between runs and
                        to deduplicate cached results
    state_variables   : All state variables in declaration order
    functions         : All functions (constructor, fallback, receive
                        included)
    base_contracts    : Parent contract names in C3 linearisation order
    derived_contracts : Known child contract names
    raw_source        : Full source text; repr=False to avoid noise in
                        debug output
    """
    name:             str
    kind:             ContractKind
    solidity_version: Optional[str] = None
    source_file:      Optional[str] = None
    contract_address: Optional[str] = None
    contract_hash:    Optional[str] = None

    state_variables:   tuple[StateVariable, ...] = field(default_factory=tuple)
    functions:         tuple[FunctionInfo, ...]   = field(default_factory=tuple)

    base_contracts:    tuple[str, ...] = field(default_factory=tuple)
    derived_contracts: tuple[str, ...] = field(default_factory=tuple)

    raw_source: Optional[str] = field(default=None, repr=False)

    # ------------------------------------------------------------------
    # Query helpers — no mutation, no analysis logic
    # ------------------------------------------------------------------

    def get_functions(self, name: str) -> List[FunctionInfo]:
        """
        Return ALL functions with the given name.

        Solidity supports overloading — two functions can share a name
        but differ in parameter types. Returning a list handles this
        correctly.
        """
        return [fn for fn in self.functions if fn.name == name]

    def get_function_by_signature(
        self,
        name:        str,
        param_types: List[str],
    ) -> Optional[FunctionInfo]:
        """
        Return the function matching both name and exact parameter type
        list. Handles overloaded functions unambiguously.
        """
        for fn in self.functions:
            if fn.name == name and [p.type for p in fn.parameters] == param_types:
                return fn
        return None

    def get_state_variable(self, qualified_name: str) -> Optional[StateVariable]:
        """Lookup a state variable by fully qualified name."""
        for v in self.state_variables:
            if v.qualified_name == qualified_name:
                return v
        return None

    @staticmethod
    def compute_hash(source: str) -> str:
        """
        Compute a stable SHA-256 hex digest of raw source text.
        Call this in the parser when constructing ContractInfo.
        """
        return hashlib.sha256(source.encode("utf-8")).hexdigest()

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name":              self.name,
            "kind":              self.kind.value,
            "solidity_version":  self.solidity_version,
            "source_file":       self.source_file,
            "contract_address":  self.contract_address,
            "contract_hash":     self.contract_hash,
            "state_variables":   [v.as_dict() for v in self.state_variables],
            "functions":         [f.as_dict() for f in self.functions],
            "base_contracts":    list(self.base_contracts),
            "derived_contracts": list(self.derived_contracts),
            "raw_source":        self.raw_source,
        }


# ---------------------------------------------------------------------------
# Finding metadata — typed schema, no Dict[str, Any]
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class FindingMetadata:
    """
    Typed metadata attached to a Finding.

    Only fields relevant to the fired detector need to be populated.
    The `extra` dict is an escape hatch for detector-specific data
    that does not fit any standard field — keep it minimal.

    Fields
    ------
    call_order            : Position of the problematic external call
                            in the function body (1-indexed)
    state_write_line      : Line where state is written after an
                            external call (reentrancy context)
    overflow_operand      : Expression string that may overflow
    unchecked_return_expr : Expression whose return value is discarded
    randomness_source     : Weak entropy source (e.g. "block.timestamp")
    access_variable       : State variable lacking an access guard
    delegatecall_target   : Target expression passed to delegatecall
    tx_origin_expr        : The tx.origin expression found
    extra                 : Escape hatch — document keys if used
    """
    call_order:            Optional[int] = None
    state_write_line:      Optional[int] = None
    overflow_operand:      Optional[str] = None
    unchecked_return_expr: Optional[str] = None
    randomness_source:     Optional[str] = None
    access_variable:       Optional[str] = None
    delegatecall_target:   Optional[str] = None
    tx_origin_expr:        Optional[str] = None
    extra:                 Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "call_order":            self.call_order,
            "state_write_line":      self.state_write_line,
            "overflow_operand":      self.overflow_operand,
            "unchecked_return_expr": self.unchecked_return_expr,
            "randomness_source":     self.randomness_source,
            "access_variable":       self.access_variable,
            "delegatecall_target":   self.delegatecall_target,
            "tx_origin_expr":        self.tx_origin_expr,
            "extra":                 dict(self.extra),
        }


# ---------------------------------------------------------------------------
# Finding — mutable, created by detectors, updated by validation engine
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class Finding:
    """
    Mutable representation of a single discovered vulnerability.

    Lifecycle:
      Detector creates it → Validation engine may flip is_false_positive
      → CVSS engine fills cvss_score/cvss_vector
      → Report generator reads it

    Invariants enforced in __post_init__:
      confidence  ∈ [0.0, 1.0]
      cvss_score  ∈ [0.0, 10.0] (when provided)

    Fields
    ------
    finding_id        : UUID hex string — auto-generated if not supplied.
                        Enables deduplication and CI-pipeline tracking.
    vuln_type         : Vulnerability category
    severity          : Qualitative severity level
    contract_name     : Name of the containing contract
    function_name     : Name of the affected function (None for
                        contract-level findings)
    source_file       : Path to the .sol file
    start_line        : First line of the vulnerable code range
    end_line          : Last line of the vulnerable code range
    title             : One-line summary (≤ 80 chars recommended)
    description       : Full description of the issue
    recommendation    : Concrete remediation steps
    confidence        : Heuristic confidence in [0.0, 1.0]
    cvss_score        : CVSS v3.1 base score in [0.0, 10.0] or None
    cvss_vector       : CVSS v3.1 vector string or None
    detector_id       : Stable detector identifier
                        (e.g. "reentrancy_standard_v1")
    detector_version  : Detector release version string
    is_false_positive : Set True by validation engine to suppress
    exploit_params    : Machine-readable exploit context (Phase 8)
    metadata          : Typed FindingMetadata with structured context
    """
    vuln_type:     VulnerabilityType
    severity:      Severity
    contract_name: str

    function_name: Optional[str] = None
    source_file:   Optional[str] = None
    start_line:    Optional[int] = None
    end_line:      Optional[int] = None
    line_number:   Optional[int] = None
    title:          Optional[str] = None
    description:    Optional[str] = field(default=None, repr=False)
    recommendation: Optional[str] = field(default=None, repr=False)

    confidence:  float          = 0.5
    cvss_score:  Optional[float] = None
    cvss_vector: Optional[str]  = None

    finding_id: str = field(
        default_factory=lambda: uuid.uuid4().hex
    )
    detector_id:      Optional[str] = None
    detector_version: Optional[str] = None

    is_false_positive: bool = False

    exploit_params: Dict[str, Any]  = field(default_factory=dict)
    metadata:       FindingMetadata  = field(default_factory=FindingMetadata)

    def __post_init__(self) -> None:
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(
                f"Finding.confidence must be in [0.0, 1.0]; "
                f"got {self.confidence}"
            )
        if self.cvss_score is not None and not (0.0 <= self.cvss_score <= 10.0):
            raise ValueError(
                f"Finding.cvss_score must be in [0.0, 10.0]; "
                f"got {self.cvss_score}"
            )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "finding_id":        self.finding_id,
            "vuln_type":         self.vuln_type.value,
            "severity":          self.severity.value,
            "contract_name":     self.contract_name,
            "function_name":     self.function_name,
            "source_file":       self.source_file,
            "start_line":        self.start_line,
            "end_line":          self.end_line,
            "title":             self.title,
            "description":       self.description,
            "recommendation":    self.recommendation,
            "confidence":        self.confidence,
            "cvss_score":        self.cvss_score,
            "cvss_vector":       self.cvss_vector,
            "detector_id":       self.detector_id,
            "detector_version":  self.detector_version,
            "is_false_positive": self.is_false_positive,
            "exploit_params":    dict(self.exploit_params),
            "metadata":          self.metadata.as_dict(),
        }


# ---------------------------------------------------------------------------
# ScanStats — ADD v1.1.0
# Per-scan counters produced by AnalysisEngine, attached to AnalysisResult.
# Defined here (not in analysis_engine.py) because it is a pure data model.
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class ScanStats:
    """
    Per-scan counters attached to every AnalysisResult.

    Produced by AnalysisEngine.analyse() and attached directly to
    AnalysisResult.stats. All fields default to 0 so partial results
    remain valid if the engine is interrupted.

    Fields
    ------
    contracts_analyzed   : ContractInfo objects successfully processed
    functions_analyzed   : functions that completed CFG + detectors
    functions_failed     : functions skipped due to CFG/DFG build failure
    functions_skipped    : functions skipped via fast-path before CFG stage
                           (no state writes AND no external calls)
    detectors_attempted  : (detector × function) executions started
    detectors_successful : (detector × function) executions that returned
                           without raising an unhandled exception
                           Crashed detectors increment attempted only.
    findings_total       : total findings emitted across all detectors
    elapsed_ms           : wall-clock time for the entire analyse() call
    """
    contracts_analyzed:   int = 0
    functions_analyzed:   int = 0
    functions_failed:     int = 0
    functions_skipped:    int = 0
    detectors_attempted:  int = 0
    detectors_successful: int = 0
    findings_total:       int = 0
    elapsed_ms:           int = 0

    def __str__(self) -> str:
        return (
            f"ScanStats("
            f"contracts={self.contracts_analyzed}, "
            f"fns_analyzed={self.functions_analyzed}, "
            f"fns_failed={self.functions_failed}, "
            f"fns_skipped={self.functions_skipped}, "
            f"detectors={self.detectors_successful}/{self.detectors_attempted}, "
            f"findings={self.findings_total}, "
            f"elapsed={self.elapsed_ms}ms)"
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "contracts_analyzed":   self.contracts_analyzed,
            "functions_analyzed":   self.functions_analyzed,
            "functions_failed":     self.functions_failed,
            "functions_skipped":    self.functions_skipped,
            "detectors_attempted":  self.detectors_attempted,
            "detectors_successful": self.detectors_successful,
            "findings_total":       self.findings_total,
            "elapsed_ms":           self.elapsed_ms,
        }


# ---------------------------------------------------------------------------
# AnalysisResult — mutable, built by engine, read by report generator
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class AnalysisResult:
    """
    Mutable container for a complete analysis run on one .sol file.

    Cache design:
      confirmed_findings is cached after first access.
      Any mutation (add_finding, add_findings, mark_false_positive)
      invalidates the cache so the next property access recomputes it.

    Fields
    ------
    source_file  : Path to the scanned .sol file — always set,
                   even when parsing fails.
                   ADD v1.1.0
    contracts    : All ContractInfo objects found in the file.
                   Empty list on parse failure, never None.
                   FIX v1.1.0: was Optional[ContractInfo] — now full
                   list so multi-contract files lose no metadata.
    findings     : All Finding objects from all detectors
    stats        : Per-scan counters — see ScanStats.
                   ADD v1.1.0: replaces bare analysis_time_ms field.
    tool_version : VigilanceCore version string
    network      : Network name — "mainnet" / "sepolia" / None
    error        : Error message if the run failed; None on success
    """
    # ADD v1.1.0
    source_file: str

    # FIX v1.1.0: List[ContractInfo] — was Optional[ContractInfo]
    contracts: List[ContractInfo] = field(default_factory=list)

    findings: List[Finding] = field(default_factory=list)

    # ADD v1.1.0: replaces analysis_time_ms
    stats: ScanStats = field(default_factory=ScanStats)

    tool_version: Optional[str] = None
    network:      Optional[str] = None
    error:        Optional[str] = None

    # Internal cache — not part of the public API
    _confirmed_cache: Optional[List[Finding]] = field(
        default=None, init=False, repr=False, compare=False
    )

    # ------------------------------------------------------------------
    # Cache management
    # ------------------------------------------------------------------

    def _invalidate_cache(self) -> None:
        object.__setattr__(self, "_confirmed_cache", None)

    # ------------------------------------------------------------------
    # Mutation helpers
    # ------------------------------------------------------------------

    def add_finding(self, finding: Finding) -> None:
        """Append a single Finding and invalidate the confirmed cache."""
        self.findings.append(finding)
        self._invalidate_cache()

    def add_findings(self, findings: List[Finding]) -> None:
        """
        Bulk-append findings returned by a detector.
        Invalidates the cache once after all appends.
        """
        self.findings.extend(findings)
        self._invalidate_cache()

    def mark_false_positive(self, finding_id: str) -> bool:
        """
        Mark a finding as a false positive by its UUID hex ID.
        Returns True if found and updated, False if ID not found.
        """
        for f in self.findings:
            if f.finding_id == finding_id:
                f.is_false_positive = True
                self._invalidate_cache()
                return True
        return False

    # ------------------------------------------------------------------
    # Aggregate properties (cache-backed O(n) on first call per mutation)
    # ------------------------------------------------------------------

    @property
    def confirmed_findings(self) -> List[Finding]:
        """All findings not flagged as false positives — cached."""
        if self._confirmed_cache is None:
            self._confirmed_cache = [
                f for f in self.findings if not f.is_false_positive
            ]
        return self._confirmed_cache

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(
            1 for f in self.confirmed_findings
            if f.severity == Severity.CRITICAL
        )

    @property
    def high_count(self) -> int:
        return sum(
            1 for f in self.confirmed_findings
            if f.severity == Severity.HIGH
        )

    @property
    def medium_count(self) -> int:
        return sum(
            1 for f in self.confirmed_findings
            if f.severity == Severity.MEDIUM
        )

    @property
    def low_count(self) -> int:
        return sum(
            1 for f in self.confirmed_findings
            if f.severity == Severity.LOW
        )

    @property
    def informational_count(self) -> int:
        return sum(
            1 for f in self.confirmed_findings
            if f.severity == Severity.INFORMATIONAL
        )

    @property
    def detector_crash_count(self) -> int:
        """
        Number of detectors that started but raised an unhandled exception.
        ADD v1.1.0.
        """
        return self.stats.detectors_attempted - self.stats.detectors_successful

    # ------------------------------------------------------------------
    # Grouping
    # ------------------------------------------------------------------

    def group_by_severity(self) -> Dict[Severity, List[Finding]]:
        """Return confirmed findings grouped by severity bucket."""
        buckets: Dict[Severity, List[Finding]] = {s: [] for s in Severity}
        for f in self.confirmed_findings:
            buckets[f.severity].append(f)
        return buckets

    def group_by_vuln_type(self) -> Dict[VulnerabilityType, List[Finding]]:
        """Return confirmed findings grouped by vulnerability type."""
        buckets: Dict[VulnerabilityType, List[Finding]] = {
            v: [] for v in VulnerabilityType
        }
        for f in self.confirmed_findings:
            buckets[f.vuln_type].append(f)
        return buckets

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def as_dict(self) -> Dict[str, Any]:
        confirmed = self.confirmed_findings
        return {
            # ADD v1.1.0
            "source_file":  self.source_file,
            # FIX v1.1.0: list of all contracts, not single Optional
            "contracts":    [c.as_dict() for c in self.contracts],
            "findings":     [f.as_dict() for f in self.findings],
            # ADD v1.1.0
            "stats":        self.stats.as_dict(),
            "tool_version": self.tool_version,
            "network":      self.network,
            "error":        self.error,
            "summary": {
                "total":           self.total_findings,
                "confirmed":       len(confirmed),
                "false_positives": self.total_findings - len(confirmed),
                "critical":        self.critical_count,
                "high":            self.high_count,
                "medium":          self.medium_count,
                "low":             self.low_count,
                "informational":   self.informational_count,
                "detector_crashes": self.detector_crash_count,
            },
        }


# ---------------------------------------------------------------------------
# Public API surface
# ---------------------------------------------------------------------------

__all__ = [
    "StateVariable",
    "FunctionParameter",
    "ExternalCallInfo",
    "FunctionInfo",
    "ContractInfo",
    "FindingMetadata",
    "Finding",
    "ScanStats",        # ADD v1.1.0
    "AnalysisResult",
]
