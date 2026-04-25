"""
detectors/base_detector.py

Abstract base class for all VigilanceCore vulnerability detectors.

Every detector subclasses BaseDetector and implements THREE methods:

detect() — the analysis algorithm
build_recommendation() — detector-specific remediation text
calculate_cvss() — detector-specific CVSS scoring logic

safe_recommendation() and safe_cvss() are implemented once here.
They wrap detector-specific logic with exception safety so the engine
never crashes because one detector produced bad recommendation/CVSS code.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import ClassVar, List, Optional

from core.cfg_builder import CFGGraph, DFGGraph
from core.models import (
    ContractInfo,
    Finding,
    FunctionInfo,
    Severity,
    VulnerabilityType,
)
from core.taint_engine import TaintResult

logger = logging.getLogger(__name__)


class BaseDetector(ABC):
    """
    Abstract base class for all VigilanceCore detectors.

    Every concrete subclass must define the following class variables:

    DETECTOR_ID: stable unique lowercase identifier
    DETECTOR_VERSION: semantic version string
    VULN_TYPE: VulnerabilityType enum value
    DEFAULT_SEVERITY: Severity enum value

    Optional class variable:

    NEEDS_STATELESS_ANALYSIS:
        False -> detector only needs functions with state writes or external calls
        True  -> detector must also run on pure/view/helper functions

    Example detectors that should likely set this to True:
    - TxOriginDetector
    - TimestampDetector
    - RandomnessDetector
    - ArithmeticDetector
    """

    DETECTOR_ID: ClassVar[str]
    DETECTOR_VERSION: ClassVar[str]
    VULN_TYPE: ClassVar[VulnerabilityType]
    DEFAULT_SEVERITY: ClassVar[Severity]

    NEEDS_STATELESS_ANALYSIS: ClassVar[bool] = False

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)

        if getattr(cls, "__abstractmethods__", None):
            return

        required = [
            "DETECTOR_ID",
            "DETECTOR_VERSION",
            "VULN_TYPE",
            "DEFAULT_SEVERITY",
        ]

        missing = [
            attr
            for attr in required
            if not hasattr(cls, attr) or getattr(cls, attr, None) is None
        ]
        if missing:
            raise TypeError(
                f"Detector '{cls.__name__}' is missing required class "
                f"variables: {', '.join(missing)}."
            )

        if not isinstance(cls.DETECTOR_ID, str) or not cls.DETECTOR_ID.strip():
            raise TypeError(
                f"'{cls.__name__}'.DETECTOR_ID must be a non-empty string."
            )

        if not isinstance(cls.DETECTOR_VERSION, str) or not cls.DETECTOR_VERSION.strip():
            raise TypeError(
                f"'{cls.__name__}'.DETECTOR_VERSION must be a non-empty string."
            )

        if not isinstance(cls.VULN_TYPE, VulnerabilityType):
            raise TypeError(
                f"'{cls.__name__}'.VULN_TYPE must be a VulnerabilityType instance."
            )

        if not isinstance(cls.DEFAULT_SEVERITY, Severity):
            raise TypeError(
                f"'{cls.__name__}'.DEFAULT_SEVERITY must be a Severity instance."
            )

        if not isinstance(cls.NEEDS_STATELESS_ANALYSIS, bool):
            raise TypeError(
                f"'{cls.__name__}'.NEEDS_STATELESS_ANALYSIS must be a bool."
            )

        logger.debug(
            "Detector class validated: id=%r version=%r vuln_type=%r stateless=%r",
            cls.DETECTOR_ID,
            cls.DETECTOR_VERSION,
            cls.VULN_TYPE,
            cls.NEEDS_STATELESS_ANALYSIS,
        )

    @abstractmethod
    def detect(
        self,
        contract: ContractInfo,
        fn_info: FunctionInfo,
        cfg: CFGGraph,
        dfg: DFGGraph,
        taint_result: Optional[TaintResult],
    ) -> List[Finding]:
        """
        Run this detector on a single function.

        Parameters
        ----------
        contract:
            Parsed contract that owns the function.
        fn_info:
            Parsed function metadata.
        cfg:
            Control-flow graph for the function.
        dfg:
            Data-flow graph for the function.
        taint_result:
            Taint analysis result for the function, or None if taint failed.

        Returns
        -------
        List[Finding]
            Empty list when nothing is found.
            Detector implementations should prefer returning [] over raising.
        """

    @abstractmethod
    def build_recommendation(self, context: dict) -> str:
        """
        Build detector-specific remediation text for one finding.

        This method should return a non-empty string and should use the
        supplied context to produce a targeted recommendation.
        """

    @abstractmethod
    def calculate_cvss(self, context: dict) -> float:
        """
        Compute a detector-specific CVSS score for one finding.

        Must return a numeric value intended for the range [0.0, 10.0].
        The safe wrapper will clamp invalid values if needed.
        """

    def safe_recommendation(self, context: dict) -> str:
        """
        Exception-safe wrapper around build_recommendation().

        Guarantees a non-empty recommendation string even if the detector's
        implementation raises or returns an empty value.
        """
        try:
            recommendation = self.build_recommendation(context)
            if isinstance(recommendation, str) and recommendation.strip():
                return recommendation

            logger.warning(
                "Detector '%s' build_recommendation() returned empty output.",
                self.DETECTOR_ID,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Detector '%s' build_recommendation() raised: %s",
                self.DETECTOR_ID,
                exc,
                exc_info=True,
            )

        fn_name = context.get("function_name", "unknown")
        contract_name = context.get("contract_name", "unknown")
        return (
            f"Review function '{fn_name}' in contract '{contract_name}' "
            f"for {self.VULN_TYPE.value} issues and apply the appropriate "
            f"security checks or defensive coding patterns."
        )

    def safe_cvss(self, context: dict) -> float:
        """
        Exception-safe wrapper around calculate_cvss().

        Guarantees a float in the range [0.0, 10.0].
        Returns 5.0 if the detector implementation raises or returns
        an invalid value.
        """
        try:
            score = self.calculate_cvss(context)
            return round(max(0.0, min(10.0, float(score))), 1)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Detector '%s' calculate_cvss() raised: %s",
                self.DETECTOR_ID,
                exc,
                exc_info=True,
            )
            return 5.0

    @property
    def detector_name(self) -> str:
        """
        Human-readable detector name fallback.
        """
        return self.__class__.__name__

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"id={self.DETECTOR_ID!r}, "
            f"version={self.DETECTOR_VERSION!r}, "
            f"vuln_type={self.VULN_TYPE.value!r}, "
            f"stateless={self.NEEDS_STATELESS_ANALYSIS!r})"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BaseDetector):
            return NotImplemented
        return self.DETECTOR_ID == other.DETECTOR_ID

    def __hash__(self) -> int:
        return hash(self.DETECTOR_ID)