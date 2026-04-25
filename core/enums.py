"""
core/enums.py

Single source of truth for all enumerated types in VigilanceCore.

Rules:
  - Every enum lives here and only here.
  - All other modules import from this file.
  - Never redefine these in any other module.
"""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    """
    Qualitative severity levels for vulnerability findings.

    Maps to CVSS v3.1 base score bands:
        CRITICAL      9.0 – 10.0
        HIGH          7.0 –  8.9
        MEDIUM        4.0 –  6.9
        LOW           0.1 –  3.9
        INFORMATIONAL 0.0        (no exploitability score)
    """
    CRITICAL      = "critical"
    HIGH          = "high"
    MEDIUM        = "medium"
    LOW           = "low"
    INFORMATIONAL = "informational"


class VulnerabilityType(str, Enum):
    """
    Canonical vulnerability classification for all detectors.
    Stable identifiers — never rename without a migration plan.
    """
    REENTRANCY        = "reentrancy"
    ACCESS_CONTROL    = "access_control"
    ARITHMETIC        = "arithmetic_issue"
    UNCHECKED_RETURN  = "unchecked_return"
    DOS               = "dos"
    BAD_RANDOMNESS    = "bad_randomness"
    TIME_MANIPULATION = "time_manipulation"
    SHORT_ADDRESS     = "short_address"
    DELEGATECALL      = "delegatecall_issue"
    TX_ORIGIN         = "tx_origin_usage"
    SELFDESTRUCT      = "selfdestruct_issue"
    LOGIC_ERROR       = "logic_error"
    FRONT_RUNNING     = "front_running"
    OTHER             = "other"


class ContractKind(str, Enum):
    """Solidity artifact type."""
    CONTRACT  = "contract"
    INTERFACE = "interface"
    LIBRARY   = "library"


class Visibility(str, Enum):
    """Canonical visibility modifier."""
    PUBLIC   = "public"
    EXTERNAL = "external"
    INTERNAL = "internal"
    PRIVATE  = "private"
    DEFAULT  = "default"


class StateMutability(str, Enum):
    """Solidity state mutability tag."""
    PURE       = "pure"
    VIEW       = "view"
    NONPAYABLE = "nonpayable"
    PAYABLE    = "payable"
    UNKNOWN    = "unknown"


class CallType(str, Enum):
    """
    Broad category of an external call made inside a function.
    Used in ExternalCallInfo.
    """
    CALL         = "call"          # addr.call{value: x}(...)
    DELEGATECALL = "delegatecall"  # addr.delegatecall(...)
    STATICCALL   = "staticcall"    # addr.staticcall(...)
    TRANSFER     = "transfer"      # addr.transfer(amount)
    SEND         = "send"          # addr.send(amount)
    HIGH_LEVEL   = "high_level"    # token.transfer(...) via interface
    UNKNOWN      = "unknown"


__all__ = [
    "Severity",
    "VulnerabilityType",
    "ContractKind",
    "Visibility",
    "StateMutability",
    "CallType",
]
