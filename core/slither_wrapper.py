"""
core/slither_wrapper.py

Controlled containment layer for all Slither and solc interactions.

Design rules:
  1. This is the ONLY file in VigilanceCore that imports from slither.
  2. Raw Slither objects never leave this file.
  3. contract_parser.py calls controlled accessors defined here.
  4. All compiler errors, Slither crashes, and version mismatches are caught
     here and returned as a structured WrapperResult.
  5. solc version switching is handled via py-solc-x (primary) or
     solc-select (fallback). The resolved binary is passed EXPLICITLY to
     Slither so crytic-compile never touches solc-select itself.
  6. Bytecode-only mode decompiles to Solidity IR before handing off to Slither.
  7. self.timeout is enforced end-to-end via ThreadPoolExecutor.

Fix log (v2.0.0):
  — Version promotion: solc < 0.4.11 (unsupported by py-solc-x AND solc-select)
    is promoted to 0.4.11 so analysis can proceed instead of hard-erroring.
  — IR generation failure recovery: "Failed to generate IR" Slither crash
    (old .call.value(amount)() syntax) now retried with discard_ir=True
    so the contract still yields CFG/AST-level findings.
  — Nightly / pre-release pragma: "0.4.15-nightly.*" and similar pre-release
    version strings are cleaned to their release base ("0.4.15") before
    version resolution to avoid mis-installation.
  — parse_pragma_version extended to also capture 2-component versions
    (e.g. pragma solidity ^0.4) and promotes them to x.y.0.
  — switch_solc_version: minimum version guard added; returns structured
    error with actionable message instead of crashing.
  — _invoke_slither: separate IR-retry path; improved error classification
    with new categories: "ir_generation", "invalid_version", "nightly_compiler".
  — WrapperResult: new field `ir_fallback_used` so callers know analysis
    ran without full IR (reduced confidence).
  — All existing functionality and accessors preserved exactly.
"""

from __future__ import annotations

import concurrent.futures
import logging
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Lowest solc version installable by BOTH py-solc-x and solc-select.
# Contracts with pragma < this are compiled with this floor version instead.
# 0.4.11 is the earliest version available on the GitHub release endpoint.
_MINIMUM_INSTALLABLE_SOLC = (0, 4, 11)
_MINIMUM_INSTALLABLE_SOLC_STR = "0.4.11"

# Pre-release / nightly suffix pattern  e.g. "0.4.15-nightly.2017.8.10+..."
_NIGHTLY_SUFFIX_RE = re.compile(r"[-+].*$")


# ---------------------------------------------------------------------------
# WrapperResult
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class WrapperResult:
    """
    Returned by SlitherWrapper.run().

    On success:  success=True,  slither_instance=<Slither obj>,  error=None
    On failure:  success=False, slither_instance=None,           error=<msg>

    ir_fallback_used=True means Slither ran with discard_ir=True because the
    normal IR-generation path crashed (old .call.value() syntax).  Findings
    produced in this mode have reduced confidence.
    """
    success: bool
    slither_instance: Optional[Any] = None   # type: slither.core.slither.Slither
    compiler_version_used: Optional[str] = None
    source_file: Optional[str] = None
    is_bytecode_mode: bool = False
    ir_fallback_used: bool = False           # NEW: True when discard_ir retry succeeded
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def parse_pragma_version(source: str) -> Optional[str]:
    """
    Extract the first Solidity pragma version from source text.

    Handles:
      pragma solidity 0.8.21;          → "0.8.21"
      pragma solidity ^0.8.21;         → "0.8.21"
      pragma solidity >=0.7.0 <0.9;    → "0.7.0"
      pragma solidity ~0.6.12;         → "0.6.12"
      pragma solidity ^0.4;            → "0.4.0"   (2-component promoted)
      pragma solidity 0.4.15-nightly…  → "0.4.15"  (pre-release stripped)

    FIX v2.0.0:
      — Added 2-component capture group (\d+\.\d+) with ".0" promotion.
      — Pre-release suffixes stripped from the returned string.
    """
    # Try 3-component first (most specific)
    pattern3 = re.compile(
        r"pragma\s+solidity\s+"
        r"[^0-9]*"
        r"(\d+\.\d+\.\d+)"
    )
    m = pattern3.search(source)
    if m:
        raw = m.group(1)
        # Strip nightly / pre-release suffix if somehow embedded
        return _NIGHTLY_SUFFIX_RE.sub("", raw)

    # Fall back to 2-component (e.g. "^0.4")
    pattern2 = re.compile(
        r"pragma\s+solidity\s+"
        r"[^0-9]*"
        r"(\d+\.\d+)"
    )
    m2 = pattern2.search(source)
    if m2:
        return m2.group(1) + ".0"

    return None


def _clean_version(version: str) -> str:
    """
    Strip pre-release / nightly suffixes from a version string so py-solc-x
    can install it.  E.g. "0.4.15-nightly.2017.8.10+commit.8b45bddb" → "0.4.15".
    """
    return _NIGHTLY_SUFFIX_RE.sub("", version).strip()


def _promote_version(version: str) -> Tuple[str, bool]:
    """
    If *version* is below _MINIMUM_INSTALLABLE_SOLC, promote it to
    _MINIMUM_INSTALLABLE_SOLC_STR.

    Returns (effective_version, was_promoted).
    """
    try:
        parts = tuple(int(x) for x in version.split(".")[:3])
    except ValueError:
        return version, False

    if parts < _MINIMUM_INSTALLABLE_SOLC:
        logger.warning(
            "solc %s is below the minimum installable version (%s). "
            "Promoting to %s — minor parsing differences possible for very "
            "old syntax.",
            version, _MINIMUM_INSTALLABLE_SOLC_STR, _MINIMUM_INSTALLABLE_SOLC_STR,
        )
        return _MINIMUM_INSTALLABLE_SOLC_STR, True
    return version, False


def _get_solcx_binary(version: str) -> Optional[Path]:
    """
    Locate the solc binary for *version* as installed by py-solc-x.

    py-solc-x Windows layout:  ~/.solcx/solc-v{ver}/solc.exe
    py-solc-x Linux/Mac layout: ~/.solcx/solc-v{ver}
    """
    try:
        import solcx
        import sys

        installed = [str(v) for v in solcx.get_installed_solc_versions()]
        if version not in installed:
            logger.warning(
                "solc %s not installed in solcx. "
                "Run: python -c \"import solcx; solcx.install_solc('%s')\"",
                version, version,
            )
            return None

        try:
            binary = solcx.get_executable(version)
            if Path(binary).exists():
                return Path(binary)
        except Exception as api_exc:
            logger.debug("solcx.get_executable() failed: %s", api_exc)

        solcx_dir = Path.home() / ".solcx"
        if sys.platform == "win32":
            candidate = solcx_dir / f"solc-v{version}" / "solc.exe"
        else:
            candidate = solcx_dir / f"solc-v{version}"

        return candidate if candidate.exists() else None

    except Exception as exc:
        logger.warning("_get_solcx_binary failed unexpectedly: %s", exc)
        return None


def _install_solcx_binary(version: str) -> Tuple[bool, str]:
    """
    Attempt to install solc *version* via py-solc-x (downloads from GitHub).
    Returns (success, message).
    """
    try:
        import solcx  # type: ignore[import]
        logger.info("Installing solc %s via py-solc-x …", version)
        solcx.install_solc(version, show_progress=False)
        solcx.set_solc_version(version)
        logger.info("solc %s installed and activated via py-solc-x.", version)
        return True, version
    except ImportError:
        return False, (
            "py-solc-x is not installed. "
            "Run:  pip install py-solc-x"
        )
    except Exception as exc:  # noqa: BLE001
        return False, f"py-solc-x install failed for {version}: {exc}"


def switch_solc_version(version: str, timeout: int = 120) -> Tuple[bool, str]:
    """
    Ensure solc *version* is available and return (True, version) or
    (False, error_message).

    FIX v2.0.0:
      — version is cleaned of nightly/pre-release suffixes before any
        installation attempt.
      — version is promoted to _MINIMUM_INSTALLABLE_SOLC_STR if it falls
        below the minimum supported by both py-solc-x and solc-select.
      — Structured error returned (no crash) when both strategies fail.

    Strategy:
      1. Clean + promote version string.
      2. Check if solcx already has the binary  → fast path, no network call.
      3. Try py-solc-x install                  → downloads from GitHub.
      4. Try solc-select install/use             → legacy fallback.
    """
    # Step 0: clean pre-release suffixes
    version = _clean_version(version)

    # Step 0b: promote below-minimum versions
    version, was_promoted = _promote_version(version)
    if was_promoted:
        logger.info("Using promoted solc version: %s", version)

    # Fast path — already installed in solcx
    if _get_solcx_binary(version) is not None:
        logger.info("solc %s already available via py-solc-x.", version)
        return True, version

    # Strategy 1 — install via py-solc-x
    ok, msg = _install_solcx_binary(version)
    if ok:
        return True, version
    logger.warning("py-solc-x install failed: %s — trying solc-select.", msg)

    # Strategy 2 — legacy solc-select
    try:
        install = subprocess.run(
            ["solc-select", "install", version],
            capture_output=True, text=True, timeout=timeout,
        )
        if install.returncode != 0:
            return False, (
                f"solc-select install {version} failed:\n"
                f"{install.stderr.strip()}"
            )
        use = subprocess.run(
            ["solc-select", "use", version],
            capture_output=True, text=True, timeout=30,
        )
        if use.returncode != 0:
            return False, (
                f"solc-select use {version} failed:\n{use.stderr.strip()}"
            )
        logger.info("solc switched to %s via solc-select.", version)
        return True, version
    except FileNotFoundError:
        return False, (
            f"Cannot install solc {version}: "
            "py-solc-x install failed and solc-select is not on PATH.\n"
            "Fix: pip install py-solc-x  (then re-run)"
        )
    except subprocess.TimeoutExpired:
        return False, f"solc-select timed out switching to {version}."
    except Exception as exc:  # noqa: BLE001
        return False, f"Unexpected error during solc switch: {exc}"


def _decompile_bytecode_to_sol(
    bytecode_hex: str,
    timeout: int = 180,
) -> Tuple[bool, str, str]:
    """
    Attempt to decompile raw EVM bytecode into Solidity-like source.
    Fallback chain: heimdall-rs → panoramix → minimal stub.
    Returns (decompile_ok, source_text, tool_used).
    """
    bytecode_hex = bytecode_hex.strip().removeprefix("0x")

    try:
        result = subprocess.run(
            ["heimdall", "decompile", bytecode_hex, "--output", "stdout"],
            capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode == 0 and result.stdout.strip():
            logger.info("Bytecode decompiled via heimdall-rs.")
            return True, result.stdout, "heimdall-rs"
    except FileNotFoundError:
        logger.debug("heimdall-rs not found; trying panoramix.")
    except subprocess.TimeoutExpired:
        logger.warning("heimdall-rs timed out during decompilation.")

    try:
        result = subprocess.run(
            ["panoramix", bytecode_hex],
            capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode == 0 and result.stdout.strip():
            logger.info("Bytecode decompiled via panoramix.")
            return True, result.stdout, "panoramix"
    except FileNotFoundError:
        logger.debug("panoramix not found.")
    except subprocess.TimeoutExpired:
        logger.warning("panoramix timed out during decompilation.")

    logger.warning(
        "No decompiler available. Producing minimal stub for bytecode analysis."
    )
    stub = (
        "// SPDX-License-Identifier: UNKNOWN\n"
        "// Auto-generated stub — full source unavailable (bytecode-only mode)\n"
        "pragma solidity 0.8.0;\n"
        "contract DecompiledContract {\n"
        "    // Structural detectors may still run on SlithIR.\n"
        "    // Source-level detectors will produce no findings.\n"
        "}\n"
    )
    return False, stub, "stub"


# ---------------------------------------------------------------------------
# SlitherWrapper
# ---------------------------------------------------------------------------

class SlitherWrapper:
    """
    Controlled interface to the Slither static-analysis framework.

    This is the ONLY class in VigilanceCore that directly uses Slither.
    Everything else works exclusively with our clean model layer.

    Usage — source file:
        wrapper = SlitherWrapper(input_path="contracts/Bank.sol")
        result  = wrapper.run()
        if result.success:
            parser = ContractParser(wrapper)
            ...

    Usage — bytecode:
        wrapper = SlitherWrapper(input_path="0xdeadbeef...", is_bytecode=True)
        result  = wrapper.run()

    Usage — forced solc version:
        wrapper = SlitherWrapper(
            input_path="contracts/Bank.sol",
            solc_version_override="0.6.12",
        )

    Thread safety:
        Each analysis run must use its own SlitherWrapper instance.
        The internal Slither object is NOT thread-safe.
    """

    DEFAULT_SOLC_VERSION = "0.8.21"

    def __init__(
        self,
        input_path: str,
        is_bytecode: bool = False,
        solc_version_override: Optional[str] = None,
        solc_remappings: Optional[List[str]] = None,
        solc_args: Optional[str] = None,
        timeout: int = 300,
    ) -> None:
        self.input_path = input_path
        self.is_bytecode = is_bytecode
        # FIX: clean override immediately so nightly strings never reach
        # version resolution downstream
        self.solc_version_override = (
            _clean_version(solc_version_override)
            if solc_version_override else None
        )
        self.solc_remappings = solc_remappings or []
        self.solc_args = solc_args
        self.timeout = timeout

        # Populated after run()
        self._slither: Optional[Any] = None
        self._compiler_version: Optional[str] = None
        self._resolved_path: Optional[str] = None
        self._tempdir: Optional[tempfile.TemporaryDirectory] = None  # type: ignore[type-arg]

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self) -> WrapperResult:
        """
        Execute the full Slither pipeline and return a WrapperResult.
        All exceptions are caught internally — callers always receive a
        structured WrapperResult, never a raw exception.
        """
        try:
            if self.is_bytecode:
                return self._run_bytecode_mode()
            return self._run_source_mode()
        except Exception as exc:  # noqa: BLE001
            logger.exception("Unexpected error in SlitherWrapper.run()")
            return WrapperResult(
                success=False,
                error=f"Unexpected internal error: {exc}",
                is_bytecode_mode=self.is_bytecode,
            )
        finally:
            if self._tempdir is not None:
                self._tempdir.cleanup()
                self._tempdir = None

    # ------------------------------------------------------------------
    # Source-mode pipeline
    # ------------------------------------------------------------------

    def _run_source_mode(self) -> WrapperResult:
        sol_path = Path(self.input_path).resolve()

        if not sol_path.exists():
            return WrapperResult(
                success=False,
                error=f"Source file not found: {sol_path}",
                is_bytecode_mode=False,
            )
        if sol_path.suffix != ".sol":
            return WrapperResult(
                success=False,
                error=f"Expected a .sol file, got: {sol_path.name}",
                is_bytecode_mode=False,
            )

        self._resolved_path = str(sol_path)

        # Read source
        try:
            source_text = sol_path.read_text(encoding="utf-8")
        except OSError as exc:
            return WrapperResult(
                success=False,
                error=f"Cannot read source file: {exc}",
                is_bytecode_mode=False,
            )

        # Resolve solc version (cleans + promotes internally)
        version = self._resolve_solc_version(source_text)
        self._compiler_version = version

        # Ensure binary is available
        switch_ok, switch_msg = switch_solc_version(version, timeout=self.timeout)
        if not switch_ok:
            return WrapperResult(
                success=False,
                error=switch_msg,
                is_bytecode_mode=False,
                source_file=self._resolved_path,
            )

        return self._invoke_slither(self._resolved_path, is_bytecode_mode=False)

    # ------------------------------------------------------------------
    # Bytecode-mode pipeline
    # ------------------------------------------------------------------

    def _run_bytecode_mode(self) -> WrapperResult:
        bytecode_hex = self.input_path.strip()
        decompile_ok, decompiled_source, tool_used = _decompile_bytecode_to_sol(
            bytecode_hex, timeout=self.timeout
        )
        if not decompile_ok:
            logger.warning(
                "Proceeding with minimal stub after decompilation failure "
                "(tool: %s).", tool_used
            )

        self._tempdir = tempfile.TemporaryDirectory(prefix="vigilance_bytecode_")
        temp_sol = Path(self._tempdir.name) / "decompiled.sol"
        temp_sol.write_text(decompiled_source, encoding="utf-8")
        self._resolved_path = str(temp_sol)

        version = self._resolve_solc_version(decompiled_source)
        self._compiler_version = version

        switch_ok, switch_msg = switch_solc_version(version, timeout=self.timeout)
        if not switch_ok:
            return WrapperResult(
                success=False,
                error=switch_msg,
                is_bytecode_mode=True,
                source_file=self._resolved_path,
            )

        return self._invoke_slither(self._resolved_path, is_bytecode_mode=True)

    # ------------------------------------------------------------------
    # Slither invocation  (with IR-failure retry)
    # ------------------------------------------------------------------

    def _invoke_slither(
        self,
        sol_path: str,
        is_bytecode_mode: bool,
    ) -> WrapperResult:
        """
        Instantiate Slither on the given .sol file.

        The solc binary is resolved explicitly from py-solc-x and passed via
        the `solc=` kwarg.  This prevents crytic-compile from ever calling the
        solc-select wrapper on PATH.

        FIX v2.0.0 — IR generation failure recovery:
          If Slither raises "Failed to generate IR" (triggered by old
          .call.value(amount)() syntax in pre-0.5.0 contracts), the call is
          retried with `discard_ir=True`.  This lets Slither fall back to
          AST-level analysis only.  The resulting WrapperResult has
          ir_fallback_used=True so callers can reduce finding confidence
          accordingly.
        """
        try:
            from slither import Slither  # type: ignore[import]
        except ImportError as exc:
            return WrapperResult(
                success=False,
                error=(
                    f"Slither is not installed or not importable: {exc}. "
                    "Install it with:  pip install slither-analyzer"
                ),
                is_bytecode_mode=is_bytecode_mode,
                source_file=sol_path,
            )

        version = self._compiler_version or self.DEFAULT_SOLC_VERSION
        base_kwargs = self._build_slither_kwargs(version)

        logger.info(
            "Invoking Slither: file=%s  solc=%s  timeout=%ds",
            sol_path, version, self.timeout,
        )

        # ── First attempt: normal IR mode ────────────────────────────────
        result = self._try_slither(Slither, sol_path, base_kwargs, is_bytecode_mode, version)
        if result.success:
            return result

        # ── Classify the error ───────────────────────────────────────────
        error_text = result.error or ""
        if "failed to generate ir" in error_text.lower():
            # IR generation crash — retry without IR
            logger.warning(
                "Slither IR generation failed for '%s'. "
                "Retrying with discard_ir=True (AST-only mode, reduced confidence).",
                sol_path,
            )
            retry_kwargs = {**base_kwargs, "discard_ir": True}
            retry_result = self._try_slither(
                Slither, sol_path, retry_kwargs, is_bytecode_mode, version,
                ir_fallback=True,
            )
            if retry_result.success:
                logger.info(
                    "IR-fallback Slither run succeeded for '%s'. "
                    "Findings will have reduced confidence.",
                    sol_path,
                )
                return retry_result
            # Both attempts failed — return the original (more informative) error
            logger.error(
                "IR-fallback also failed for '%s': %s",
                sol_path, retry_result.error,
            )

        return result  # return first-attempt failure with full error message

    def _build_slither_kwargs(self, version: str) -> Dict[str, Any]:
        """Build the kwargs dict for Slither(). Resolves solc binary explicitly."""
        kwargs: Dict[str, Any] = {}

        if self.solc_remappings:
            kwargs["solc_remaps"] = " ".join(self.solc_remappings)
        if self.solc_args:
            kwargs["solc_args"] = self.solc_args

        solc_bin = _get_solcx_binary(version)
        if solc_bin is not None:
            kwargs["solc"] = str(solc_bin)
            logger.debug("Using explicit solc binary: %s", solc_bin)
        else:
            # Last-resort: set SOLC_VERSION env var so solc-select wrapper
            # at least knows which version to use if it does get called.
            os.environ["SOLC_VERSION"] = version
            logger.warning(
                "py-solc-x binary not found for %s — falling back to PATH solc "
                "with SOLC_VERSION=%s env var.",
                version, version,
            )

        return kwargs

    def _try_slither(
        self,
        Slither: Any,
        sol_path: str,
        slither_kwargs: Dict[str, Any],
        is_bytecode_mode: bool,
        version: str,
        ir_fallback: bool = False,
    ) -> WrapperResult:
        """
        Run Slither(sol_path, **slither_kwargs) in a thread with timeout.
        Returns WrapperResult.  Never raises.
        """
        def _run() -> Any:
            return Slither(sol_path, **slither_kwargs)

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(_run)
                try:
                    slither_instance = future.result(timeout=self.timeout)
                except concurrent.futures.TimeoutError:
                    return WrapperResult(
                        success=False,
                        error=(
                            f"Slither timed out after {self.timeout}s "
                            f"on {sol_path}"
                        ),
                        compiler_version_used=version,
                        source_file=sol_path,
                        is_bytecode_mode=is_bytecode_mode,
                        ir_fallback_used=ir_fallback,
                    )
        except Exception as exc:  # noqa: BLE001
            error_text = str(exc)
            logger.error("Slither failed on %s: %s", sol_path, error_text)
            msg = self._classify_slither_error(error_text, version, sol_path)
            return WrapperResult(
                success=False,
                error=msg,
                compiler_version_used=version,
                source_file=sol_path,
                is_bytecode_mode=is_bytecode_mode,
                ir_fallback_used=ir_fallback,
            )

        self._slither = slither_instance
        logger.info(
            "Slither completed successfully. Contracts found: %d  (ir_fallback=%s)",
            len(slither_instance.contracts), ir_fallback,
        )
        return WrapperResult(
            success=True,
            slither_instance=slither_instance,
            compiler_version_used=version,
            source_file=sol_path,
            is_bytecode_mode=is_bytecode_mode,
            ir_fallback_used=ir_fallback,
            error=None,
        )

    @staticmethod
    def _classify_slither_error(error_text: str, version: str, sol_path: str) -> str:
        """
        Map a raw Slither/solc exception string to a structured, actionable
        error message.

        FIX v2.0.0: added classification for:
          — "failed to generate ir"  (old .call.value() syntax)
          — "invalid version" / "pre-release compiler"  (nightly pragma)
          — solc binary not found
          — compilation error
          — source file pragma mismatch
        """
        et = error_text.lower()

        if "failed to generate ir" in et:
            return (
                f"Slither failed for '{sol_path}': "
                "IR generation failed — contract uses pre-0.5.0 call syntax "
                "(.call.value(amount)()) that Slither cannot fully lower to IR. "
                "Analysis was re-attempted in AST-only mode."
            )

        if "pre-release compiler" in et or "nightly" in et or "invalid version" in et:
            return (
                f"Slither failed for '{sol_path}': "
                f"Source pragma references a nightly/pre-release compiler version. "
                f"The installed solc ({version}) is a release build and rejects it. "
                "Fix: remove the nightly suffix from pragma or pin to a release version."
            )

        if "not found" in et and "solc" in et:
            return (
                f"solc {version} binary not found.\n"
                f"Fix: python -c \"import solcx; solcx.install_solc('{version}')\"\n"
                f"Original: {error_text}"
            )

        if "compilation error" in et:
            return f"Solidity compilation failed: {error_text}"

        if "source file" in et:
            return f"Source file error: {error_text}"

        return f"Slither analysis error: {error_text}"

    # ------------------------------------------------------------------
    # Version resolution
    # ------------------------------------------------------------------

    def _resolve_solc_version(self, source_text: str) -> str:
        """
        Determine the correct solc version to use.

        FIX v2.0.0:
          — Detected version is cleaned of nightly suffixes.
          — Detected version is promoted if below minimum installable.

        Priority:
          1. Explicit override supplied by caller (already cleaned in __init__)
          2. Pragma detected in source (cleaned + promoted here)
          3. Default fallback (DEFAULT_SOLC_VERSION)
        """
        if self.solc_version_override:
            version, _ = _promote_version(self.solc_version_override)
            logger.info("Using caller-supplied solc override: %s", version)
            return version

        detected = parse_pragma_version(source_text)
        if detected:
            cleaned  = _clean_version(detected)
            promoted, was_promoted = _promote_version(cleaned)
            if was_promoted:
                logger.info(
                    "Pragma version %s promoted to %s (below minimum installable).",
                    detected, promoted,
                )
            else:
                logger.info("Detected pragma solidity version: %s", promoted)
            return promoted

        logger.warning(
            "No pragma detected in source. Falling back to solc %s.",
            self.DEFAULT_SOLC_VERSION,
        )
        return self.DEFAULT_SOLC_VERSION

    # ------------------------------------------------------------------
    # Accessors used by ContractParser and CFGAnalyser
    # ------------------------------------------------------------------

    def get_contracts(self) -> List[Any]:
        """Return raw Slither contract objects. Empty list if run failed."""
        if self._slither is None:
            return []
        return list(self._slither.contracts)

    def get_functions(self, slither_contract: Any) -> List[Any]:
        """Return raw Slither function objects declared in this contract."""
        if slither_contract is None:
            return []
        return list(slither_contract.functions_and_modifiers_declared)

    def get_state_variables(self, slither_contract: Any) -> List[Any]:
        """Return raw Slither state variables declared in this contract."""
        if slither_contract is None:
            return []
        return list(slither_contract.state_variables_declared)

    def get_external_calls(
        self, slither_function: Any
    ) -> List[Tuple[Any, Any]]:
        """
        Return (node, call_expression) tuples for every external call in
        the given function's CFG nodes.
        """
        if slither_function is None:
            return []
        external_calls = []
        try:
            for node in slither_function.nodes:
                for call in node.external_calls_as_expressions:
                    external_calls.append((node, call))
        except Exception:  # noqa: BLE001
            logger.warning(
                "Could not retrieve external calls for function '%s'.",
                getattr(slither_function, "name", "unknown"),
            )
        return external_calls

    def get_source_mapping(
        self, slither_node: Any
    ) -> Tuple[Optional[str], Optional[int], Optional[int]]:
        """Return (source_file, start_line, end_line) for a Slither node."""
        try:
            sm = slither_node.source_mapping
            filename = sm.filename.absolute if sm.filename else None
            start_line = sm.lines[0] if sm.lines else None
            end_line = sm.lines[-1] if sm.lines else None
            return filename, start_line, end_line
        except Exception:  # noqa: BLE001
            return None, None, None

    def get_slithir(self, slither_function: Any) -> List[Any]:
        """Return flat list of SlithIR instructions for the function."""
        if slither_function is None:
            return []
        try:
            irs = []
            for node in slither_function.nodes:
                irs.extend(node.irs)
            return irs
        except Exception:  # noqa: BLE001
            logger.warning(
                "Could not retrieve SlithIR for function '%s'.",
                getattr(slither_function, "name", "unknown"),
            )
            return []

    def get_events_emitted(self, slither_function: Any) -> List[str]:
        """Return names of events emitted inside the given function."""
        if slither_function is None:
            return []
        try:
            return [
                event.name
                for node in slither_function.nodes
                for event in node.events_emitted
            ]
        except Exception:  # noqa: BLE001
            return []

    def get_contract_by_name(self, name: str) -> Optional[Any]:
        """Return the Slither contract object with the given name, or None."""
        if self._slither is None:
            return None
        for c in self._slither.contracts:
            if getattr(c, "name", None) == name:
                return c
        return None

    def get_function_by_signature(
        self, slither_contract: Any, signature: str
    ) -> Optional[Any]:
        """Return the function matching *signature* in *slither_contract*."""
        if slither_contract is None:
            return None
        try:
            for fn in slither_contract.functions_and_modifiers_declared:
                if getattr(fn, "full_name", None) == signature:
                    return fn
        except Exception:  # noqa: BLE001
            pass
        return None

    def get_cfg_nodes(self, slither_function: Any) -> List[Any]:
        """Return raw Slither CFG node objects for the given function."""
        if slither_function is None:
            return []
        try:
            return list(slither_function.nodes)
        except Exception:  # noqa: BLE001
            return []