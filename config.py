# config.py
# VigilanceCore — Global Configuration
#
# Rules for this file:
#   1. No logic. No functions. Only constants, enums, and paths.
#   2. Every other module imports from here — never the reverse.
#   3. If a value needs runtime computation, it goes in the detector, not here.

from enum import Enum
from pathlib import Path

# ──────────────────────────────────────────────────────────────
# PROJECT PATHS
# ──────────────────────────────────────────────────────────────

BASE_DIR      = Path(__file__).parent.resolve()
CONTRACTS_DIR = BASE_DIR / "contracts" / "samples"
REPORTS_DIR   = BASE_DIR / "reports"   / "output"
LOGS_DIR      = BASE_DIR / "logs"

# Create output directories on import so no module ever crashes on missing dirs
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# ──────────────────────────────────────────────────────────────
# SOLIDITY COMPILER
# ──────────────────────────────────────────────────────────────

SOLC_VERSION        = "0.8.19"   # used by SlitherWrapper
SOLC_BINARY         = "solc"     # assumes solc-select is active
SLITHER_TIMEOUT_SEC = 300        # max seconds Slither is allowed per contract

# ──────────────────────────────────────────────────────────────
# SEVERITY LEVELS
# ──────────────────────────────────────────────────────────────

class Severity(str, Enum):
    """
    Inherits from str so Severity.CRITICAL == "CRITICAL" is True.
    This means JSON serialization works without a custom encoder.
    """
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


# Keys are Severity enum members — not raw strings
SEVERITY_WEIGHT: dict[Severity, int] = {
    Severity.CRITICAL : 5,
    Severity.HIGH     : 4,
    Severity.MEDIUM   : 3,
    Severity.LOW      : 2,
    Severity.INFO     : 1,
}

# ──────────────────────────────────────────────────────────────
# VULNERABILITY TYPES
# ──────────────────────────────────────────────────────────────

class VulnType(str, Enum):
    """
    Inherits from str for the same reason as Severity —
    JSON serialization and string comparison work out of the box.
    """
    # ── Standard detectors (Phases 2–3) ───────────────────────
    REENTRANCY            = "REENTRANCY"
    ACCESS_CONTROL        = "ACCESS_CONTROL"
    ARITHMETIC_OVERFLOW   = "ARITHMETIC_OVERFLOW"
    UNCHECKED_RETURN      = "UNCHECKED_RETURN"
    BAD_RANDOMNESS        = "BAD_RANDOMNESS"
    TIME_MANIPULATION     = "TIME_MANIPULATION"
    TX_ORIGIN_AUTH        = "TX_ORIGIN_AUTH"
    DENIAL_OF_SERVICE     = "DENIAL_OF_SERVICE"
    UNSAFE_DELEGATECALL   = "UNSAFE_DELEGATECALL"
    UNPROTECTED_SELFDESTRUCT = "UNPROTECTED_SELFDESTRUCT"  # renamed for clarity

    # ── Novel detectors (Phases 5–7) ──────────────────────────
    LOGIC_ERROR           = "LOGIC_ERROR"      # Novel #1: semantic mismatch
    MULTI_TX_ATTACK       = "MULTI_TX_ATTACK"  # Novel #2: multi-transaction bug
    FRONT_RUNNING         = "FRONT_RUNNING"    # Novel #3: economic exploit


# ──────────────────────────────────────────────────────────────
# DEFAULT SEVERITY PER VULNERABILITY TYPE
#
# These are STARTING points only.
# Each detector can upgrade or downgrade severity dynamically
# based on context (e.g., is function public? is it payable?
# does it handle funds? is there any partial mitigation?)
#
# Source: OWASP Smart Contract Top 10, SWC Registry
# ──────────────────────────────────────────────────────────────

VULN_DEFAULT_SEVERITY: dict[VulnType, Severity] = {
    VulnType.REENTRANCY               : Severity.CRITICAL,
    VulnType.ACCESS_CONTROL           : Severity.CRITICAL,
    VulnType.ARITHMETIC_OVERFLOW      : Severity.HIGH,
    VulnType.UNCHECKED_RETURN         : Severity.MEDIUM,
    VulnType.BAD_RANDOMNESS           : Severity.HIGH,
    VulnType.TIME_MANIPULATION        : Severity.MEDIUM,
    VulnType.TX_ORIGIN_AUTH           : Severity.HIGH,
    VulnType.DENIAL_OF_SERVICE        : Severity.MEDIUM,
    VulnType.UNSAFE_DELEGATECALL      : Severity.CRITICAL,
    VulnType.UNPROTECTED_SELFDESTRUCT : Severity.CRITICAL,

    # LOGIC_ERROR starts at HIGH — not CRITICAL.
    # Reason: "logic error" alone is too broad to auto-assign CRITICAL.
    # The SemanticIntentAnalyzer in Phase 5 upgrades this to CRITICAL
    # only when it can also calculate a financial impact > 0.
    VulnType.LOGIC_ERROR              : Severity.HIGH,

    VulnType.MULTI_TX_ATTACK          : Severity.CRITICAL,
    VulnType.FRONT_RUNNING            : Severity.HIGH,
}


# ──────────────────────────────────────────────────────────────
# BASE CVSS v3.1 SCORES PER VULNERABILITY TYPE
#
# Vector assumed: AV:N/AC:L/PR:N/UI:N (worst-case, network-accessible)
# These are the CEILING scores for each vulnerability class.
#
# The CvssCalculator in Phase 8 adjusts downward based on:
#   - Function visibility  (internal/private → lower)
#   - Authentication required (onlyOwner partially mitigates)
#   - Whether funds are directly at risk
#   - Exploitability confirmed via Hardhat (confirmed = score kept)
#   - Exploitability unconfirmed (score reduced by 1.5)
# ──────────────────────────────────────────────────────────────

VULN_BASE_CVSS: dict[VulnType, float] = {
    VulnType.REENTRANCY               : 9.8,
    VulnType.ACCESS_CONTROL           : 9.1,
    VulnType.ARITHMETIC_OVERFLOW      : 7.5,
    VulnType.UNCHECKED_RETURN         : 5.3,
    VulnType.BAD_RANDOMNESS           : 7.4,
    VulnType.TIME_MANIPULATION        : 5.9,
    VulnType.TX_ORIGIN_AUTH           : 8.1,
    VulnType.DENIAL_OF_SERVICE        : 6.5,
    VulnType.UNSAFE_DELEGATECALL      : 9.8,
    VulnType.UNPROTECTED_SELFDESTRUCT : 9.1,
    VulnType.LOGIC_ERROR              : 8.5,
    VulnType.MULTI_TX_ATTACK          : 8.8,
    VulnType.FRONT_RUNNING            : 7.5,
}


# ──────────────────────────────────────────────────────────────
# RECOMMENDATIONS
#
# There are NO static recommendation strings in this file.
#
# Every detector class implements build_recommendation(context: dict)
# which generates a recommendation using real analysis data:
#   - Exact function name and line number
#   - The specific variable/call that is vulnerable
#   - Whether a partial fix already exists
#   - The precise code change needed
#
# Static strings that say the same thing for every contract are
# useless to a developer. We do not have them.
#
# See: detectors/base_detector.py → build_recommendation()
# ──────────────────────────────────────────────────────────────


# ──────────────────────────────────────────────────────────────
# TERMINAL DISPLAY (Rich library)
# ──────────────────────────────────────────────────────────────

SEVERITY_COLOR: dict[Severity, str] = {
    Severity.CRITICAL : "bold red",
    Severity.HIGH     : "red",
    Severity.MEDIUM   : "yellow",
    Severity.LOW      : "cyan",
    Severity.INFO     : "dim white",
}

SEVERITY_EMOJI: dict[Severity, str] = {
    Severity.CRITICAL : "🔴",
    Severity.HIGH     : "🟠",
    Severity.MEDIUM   : "🟡",
    Severity.LOW      : "🔵",
    Severity.INFO     : "⚪",
}


# ──────────────────────────────────────────────────────────────
# ANALYSIS ENGINE LIMITS
#
# These limits exist to prevent two specific problems:
#
#   1. PATH EXPLOSION — in symbolic execution, the number of
#      execution paths grows as 2^n with each branch.
#      Without a cap, a contract with 10 branches = 1024 paths.
#      With 20 branches = 1,048,576 paths. The engine would
#      never finish. MAX_SYMBOLIC_PATHS hard-stops this.
#
#   2. INFINITE LOOP UNROLLING — loops with symbolic bounds
#      cannot be fully unrolled. MAX_LOOP_UNROLL controls how
#      many times we unroll before applying loop abstraction.
#
#   3. MULTI-TX DEPTH EXPLOSION — each additional transaction
#      in a sequence multiplies state space. Depth 3 covers
#      the vast majority of real-world multi-tx attacks while
#      keeping analysis tractable.
#
# Do NOT increase these without profiling on large contracts first.
# ──────────────────────────────────────────────────────────────

MAX_SYMBOLIC_PATHS    = 500   # max feasible paths explored per function
MAX_LOOP_UNROLL       = 3     # max loop unroll iterations before abstraction
MAX_TX_SEQUENCE_DEPTH = 3     # max transaction chain depth for multi-tx tracer
Z3_SOLVER_TIMEOUT_MS  = 30000 # Z3 timeout per query (30 seconds)


# ──────────────────────────────────────────────────────────────
# REPORTING FLAGS
# ──────────────────────────────────────────────────────────────

REPORT_JSON_INDENT   = 2     # indentation for JSON output files
REPORT_INCLUDE_PATCH = True  # include suggested code patch in report
REPORT_INCLUDE_POC   = True  # include exploit PoC code when available
