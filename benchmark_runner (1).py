"""
benchmark_runner.py  —  VigilanceCore v1.2.0
SolidiFI + SmartBugs Curated benchmark harness.

Usage
-----
python benchmark_runner.py                        # full run, both datasets
python benchmark_runner.py --only solidifi        # SolidiFI only  ← typical
python benchmark_runner.py --only smartbugs       # SmartBugs only
python benchmark_runner.py --category Reentrancy  # one SolidiFI category
python benchmark_runner.py --max 5                # quick smoke-test (5 per category)
python benchmark_runner.py --workers 4            # parallel (4 threads)
python benchmark_runner.py --install-solc         # pre-install all required solc versions

Outputs (written to ./reports/)
--------------------------------
  benchmark_solidifi_<ts>.json   / benchmark_solidifi_latest.json
  benchmark_solidifi_<ts>.csv    / benchmark_solidifi_latest.csv
  benchmark_results.json         ← flat list; consumed directly by metrics.py

TP / Recall logic
-----------------
SolidiFI contains only intentionally-buggy contracts — every contract has
exactly one injected vulnerability type. A result is a TRUE POSITIVE when the
detector finds the expected vulnerability type in that contract.
Since there are no clean contracts, only RECALL is measured here.
Precision requires a separate clean-contract set (not included in SolidiFI).

Change log
----------
v1.0.0  Initial release
v1.1.0  FIX case-insensitive TP matching; correct VulnType value strings;
        SolidiFI nested-subdir handling; solcx bulk install helper.
v1.2.0  FIX elapsed_ms always-zero bug in exception handler (t0 captured before try)
        FIX JSON schema: add source/vulnerability/fn fields for metrics.py compatibility
        FIX save benchmark_results.json at cwd so metrics.py works out of the box
        FIX detector class names: TimestampDetectorV2, DelegatecallDetector
        FIX CategoryStats: precision removed (no FP data) — recall is the real metric
        FIX progress counter printed during sequential runs
        IMP --only solidifi default hint in help text
        IMP alias groups extended for all SolidiFI categories
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from importlib import import_module
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.WARNING,
    format="%(levelname)s:%(name)s:%(message)s",
)
logger = logging.getLogger("benchmark_runner")

# ---------------------------------------------------------------------------
# Dataset root paths  (edit if your checkouts live elsewhere)
# ---------------------------------------------------------------------------
SMARTBUGS_ROOT = Path("../smartbugs-curated/dataset")
SOLIDIFI_ROOT  = Path("../SolidiFI-benchmark/buggy_contracts")

# ---------------------------------------------------------------------------
# Category → expected vuln_type value
#
# These strings MUST match the .value of the VulnerabilityType enum members
# that your detectors actually emit (lowercase).
# ---------------------------------------------------------------------------

SMARTBUGS_CATEGORY_MAP: Dict[str, Optional[str]] = {
    "access_control":          "access_control",
    "arithmetic":              "arithmetic_overflow",
    "bad_randomness":          "bad_randomness",
    "denial_of_service":       "denial_of_service",
    "front_running":           "front_running",
    "reentrancy":              "reentrancy",
    "time_manipulation":       "time_manipulation",
    "unchecked_low_level_calls": "unchecked_return",
    # skipped
    "other":          None,
    "short_addresses": None,
}

# SolidiFI folder names → expected vuln_type
SOLIDIFI_CATEGORY_MAP: Dict[str, Optional[str]] = {
    "Overflow-Underflow":  "arithmetic_overflow",
    "Reentrancy":          "reentrancy",
    "TOD":                 "front_running",
    "Timestamp":           "time_manipulation",
    "Unchecked-Send":      "unchecked_return",
    "Integer-Overflow":    "arithmetic_overflow",
    "TxOrigin":            "tx_origin_usage",
    "Locked-Ether":        "denial_of_service",
    "Access-Control":      "access_control",
    # skipped
    "Other": None,
}

# ---------------------------------------------------------------------------
# Detector modules  —  tried in order; failures are warned and skipped.
#
# Class names verified against the attached detector source files:
#   arithmetic_detector.py   → ArithmeticDetector   (DETECTOR_ID: arithmetic_v1)
#   timestamp_detector.py    → TimestampDetectorV2  (internal name: timestamp_detector_v2)
#   dos_detector.py          → DosDetector          (detector_id:  dos_v1)
#   delegatecall_detector.py → DelegatecallDetector
# ---------------------------------------------------------------------------
DETECTOR_MODULES: List[Tuple[str, str]] = [
    ("detectors.reentrancy_detector",       "ReentrancyDetector"),
    ("detectors.access_control_detector",   "AccessControlDetector"),
    ("detectors.txorigin_detector",         "TxOriginDetector"),
    ("detectors.timestamp_detector",        "TimestampDetectorV2"),   # FIX v1.2.0
    ("detectors.unchecked_return_detector", "UncheckedReturnDetector"),
    ("detectors.randomness_detector",       "RandomnessDetector"),
    ("detectors.dos_detector",              "DosDetector"),
    ("detectors.arithmetic_detector",       "ArithmeticDetector"),
    ("detectors.delegatecall_detector",     "DelegatecallDetector"),  # FIX v1.2.0
    ("detectors.logic_error_detector",      "LogicErrorDetector"),
    ("detectors.business_logic",            "BusinessLogicDetector"),
    ("detectors.integer_overflow",          "IntegerOverflowDetector"),
]

# ---------------------------------------------------------------------------
# Alias groups
# Multiple VulnerabilityType.value strings that represent the same category.
# ---------------------------------------------------------------------------
_ALIASES: Dict[str, Set[str]] = {
    "arithmetic_overflow":  {"arithmetic_overflow", "integer_overflow", "overflow_underflow", "arithmetic"},
    "integer_overflow":     {"integer_overflow", "arithmetic_overflow", "overflow_underflow", "arithmetic"},
    "denial_of_service":    {"denial_of_service", "dos", "locked_ether"},
    "front_running":        {"front_running", "tod", "transaction_order_dependence"},
    "time_manipulation":    {"time_manipulation", "timestamp", "bad_timestamp", "timestamp_dependence"},
    "access_control":       {"access_control"},
    "tx_origin_usage":      {"tx_origin_usage", "tx_origin", "txorigin"},
    "unchecked_return":     {"unchecked_return", "unchecked_send", "unchecked_low_level", "unchecked_low_level_calls"},
    "bad_randomness":       {"bad_randomness", "randomness", "weak_randomness"},
    "reentrancy":           {"reentrancy"},
    "delegatecall_issue":   {"delegatecall_issue", "delegatecall"},
}

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ContractResult:
    path:          Path
    dataset:       str        # "SolidiFI" or "SmartBugs"
    category:      str
    expected_type: str
    found_types:   List[str]
    is_tp:         bool
    is_error:      bool
    error_msg:     str = ""
    elapsed_ms:    int = 0


@dataclass
class CategoryStats:
    name:  str
    total: int = 0
    tp:    int = 0
    fn:    int = 0
    err:   int = 0

    @property
    def recall(self) -> float:
        """
        Recall = TP / (TP + FN).
        NOTE: Precision is NOT computed here — SolidiFI contains only buggy
        contracts so there are no true negatives or false positives to measure.
        Run against a clean-contract set separately for precision.
        """
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        """F1 with precision assumed == recall (recall-only benchmark)."""
        r = self.recall
        return r  # F1 = 2*P*R/(P+R); when P==R, F1 == P == R

# ---------------------------------------------------------------------------
# Helper: bulk-install all solc versions needed by a dataset
# ---------------------------------------------------------------------------

def _bulk_install_solc(root: Path, max_versions: int = 40) -> None:
    """
    Pre-install every solc version pragma-detected across the dataset.
    Skips versions below 0.4.11 (py-solc-x minimum).
    Call once at startup with --install-solc flag.
    """
    try:
        import solcx
        from core.slither_wrapper import parse_pragma_version
    except ImportError:
        logger.warning("py-solc-x or core.slither_wrapper not available — skipping.")
        return

    versions: Set[str] = set()
    for sol in root.rglob("*.sol"):
        try:
            text = sol.read_text(encoding="utf-8", errors="replace")
            v = parse_pragma_version(text)
            if v:
                parts = [int(x) for x in v.split(".")]
                if parts[0] == 0 and parts[1] == 4 and parts[2] < 11:
                    continue
                versions.add(v)
        except Exception:
            continue

    installed  = {str(v) for v in solcx.get_installed_solc_versions()}
    to_install = sorted(versions - installed)[:max_versions]

    if not to_install:
        print("All required solc versions already installed.")
        return

    print(f"Installing {len(to_install)} solc version(s): {', '.join(to_install)}")
    for v in to_install:
        try:
            solcx.install_solc(v, show_progress=False)
            print(f"  ✓ solc {v}")
        except Exception as e:
            print(f"  ✗ solc {v}: {e}")

# ---------------------------------------------------------------------------
# Helper: build AnalysisEngine with all available detectors
# ---------------------------------------------------------------------------

def _build_engine():
    from core.analysis_engine import AnalysisEngine

    engine = AnalysisEngine()

    for module_path, class_name in DETECTOR_MODULES:
        try:
            mod = import_module(module_path)
            cls = getattr(mod, class_name)
            det = cls()
            if det.DETECTOR_ID not in engine.registered_detectors:
                engine.register(det)
        except Exception as exc:
            logger.warning(
                "Skipping %s.%s — %s: %s",
                module_path, class_name, type(exc).__name__, exc,
            )

    print(
        f"Engine ready — {len(engine.registered_detectors)} detector(s): "
        f"{engine.registered_detectors}"
    )
    return engine

# ---------------------------------------------------------------------------
# Helper: extract normalised vuln_type strings from an AnalysisResult
# ---------------------------------------------------------------------------

def _found_types(result) -> List[str]:
    """Return list of lowercase vuln_type value strings from all findings."""
    out: List[str] = []
    for finding in (result.findings or []):
        vt = finding.vuln_type
        out.append(str(getattr(vt, "value", vt)).lower())
    return out

# ---------------------------------------------------------------------------
# Helper: TP check (case-insensitive + alias groups)
# ---------------------------------------------------------------------------

def _is_tp(expected: str, found: List[str]) -> bool:
    """
    True if `expected` vulnerability type is satisfied by `found`.

    Handles:
    - Exact lowercase match
    - Alias groups (e.g. arithmetic_overflow == integer_overflow)
    """
    exp         = expected.lower().strip()
    found_lower = {f.lower().strip() for f in found}

    if exp in found_lower:
        return True

    for alias_set in _ALIASES.values():
        if exp in alias_set and alias_set & found_lower:
            return True

    return False

# ---------------------------------------------------------------------------
# Core: analyse one .sol file
# ---------------------------------------------------------------------------

def _analyse_contract(
    engine,
    sol_path:      Path,
    expected_type: str,
    category:      str,
    dataset:       str,
) -> ContractResult:
    # FIX v1.2.0: capture t0 BEFORE try so the except block can use it
    t0 = time.monotonic()
    try:
        result  = engine.analyse(str(sol_path))
        elapsed = int((time.monotonic() - t0) * 1000)

        if result.error:
            return ContractResult(
                path          = sol_path,
                dataset       = dataset,
                category      = category,
                expected_type = expected_type,
                found_types   = [],
                is_tp         = False,
                is_error      = True,
                error_msg     = result.error[:120],
                elapsed_ms    = elapsed,
            )

        found = _found_types(result)
        tp    = _is_tp(expected_type, found)

        return ContractResult(
            path          = sol_path,
            dataset       = dataset,
            category      = category,
            expected_type = expected_type,
            found_types   = found,
            is_tp         = tp,
            is_error      = False,
            elapsed_ms    = elapsed,
        )

    except Exception as exc:
        # FIX v1.2.0: was `time.monotonic() - time.monotonic()` → always 0
        elapsed = int((time.monotonic() - t0) * 1000)
        return ContractResult(
            path          = sol_path,
            dataset       = dataset,
            category      = category,
            expected_type = expected_type,
            found_types   = [],
            is_tp         = False,
            is_error      = True,
            error_msg     = f"{type(exc).__name__}: {str(exc)[:100]}",
            elapsed_ms    = elapsed,
        )

# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

_BAR_WIDTH = 28

def _bar(tp: int, total: int) -> str:
    if total == 0:
        return "░" * _BAR_WIDTH
    filled = round(_BAR_WIDTH * tp / total)
    return "█" * filled + "░" * (_BAR_WIDTH - filled)

def _status_char(r: ContractResult) -> str:
    if r.is_error:
        return "[E]"
    return "[✓]" if r.is_tp else "[✗]"

def _found_str(r: ContractResult) -> str:
    if r.is_error:
        return r.error_msg[:60]
    return ", ".join(r.found_types) if r.found_types else "nothing"

def _print_result(r: ContractResult, index: int, total: int) -> None:
    status = _status_char(r)
    name   = r.path.name[:50].ljust(50)
    found  = _found_str(r)[:55]
    exp    = r.expected_type.upper()
    ms     = r.elapsed_ms
    prog   = f"[{index:>3}/{total}]"

    if r.is_error:
        print(f"  {prog} {status} {name} {ms:>6}ms  ERR: {found}")
    elif r.is_tp:
        print(f"  {prog} {status} {name} {ms:>6}ms  ✓ {exp}")
    else:
        print(f"  {prog} {status} {name} {ms:>6}ms  expected: {exp} | found: {found}")

def _print_category_stats(stats: CategoryStats) -> None:
    bar = _bar(stats.tp, max(1, stats.total - stats.err))
    print(
        f"  {stats.name:<35} total={stats.total:3} "
        f"TP={stats.tp:3} FN={stats.fn:3} ERR={stats.err:3} "
        f"Recall={stats.recall:.2f} "
        f"[{bar}]"
    )

# ---------------------------------------------------------------------------
# Dataset: collect contracts
# ---------------------------------------------------------------------------

def _collect_contracts(
    root:              Path,
    category_map:      Dict[str, Optional[str]],
    only_category:     Optional[str],
    max_per_category:  Optional[int],
) -> List[Tuple[Path, str, str]]:
    """Returns list of (sol_path, category_name, expected_type)."""
    contracts: List[Tuple[Path, str, str]] = []

    if not root.exists():
        logger.warning("Dataset root not found: %s", root)
        return contracts

    for category_dir in sorted(root.iterdir()):
        if not category_dir.is_dir():
            continue

        cat = category_dir.name
        if only_category and cat.lower() != only_category.lower():
            continue

        expected = category_map.get(cat)
        if expected is None:
            if cat in category_map:
                logger.debug("Category '%s' is explicitly skipped.", cat)
            else:
                logger.warning("Unknown category '%s' — skipping.", cat)
            continue

        # Flat layout (.sol files directly in category dir)
        sol_files: List[Path] = sorted(category_dir.glob("*.sol"))

        if not sol_files:
            # SolidiFI numbered subdirs: category/1/*.sol, category/2/*.sol …
            for sub in sorted(category_dir.iterdir()):
                if sub.is_dir():
                    sol_files.extend(sorted(sub.glob("*.sol")))

        if max_per_category:
            sol_files = sol_files[:max_per_category]

        for sol in sol_files:
            contracts.append((sol, cat, expected))

    return contracts

# ---------------------------------------------------------------------------
# Dataset runner
# ---------------------------------------------------------------------------

def _run_dataset(
    engine,
    label:             str,
    dataset:           str,
    root:              Path,
    category_map:      Dict[str, Optional[str]],
    only_category:     Optional[str],
    max_per_category:  Optional[int],
    workers:           int,
) -> Tuple[List[ContractResult], Dict[str, CategoryStats]]:

    contracts = _collect_contracts(root, category_map, only_category, max_per_category)
    if not contracts:
        print(f"  No contracts found under {root}")
        return [], {}

    # Group by category for ordered display
    by_cat: Dict[str, List[Tuple[Path, str]]] = {}
    for sol, cat, exp in contracts:
        by_cat.setdefault(cat, []).append((sol, exp))

    all_results: List[ContractResult] = []
    cat_stats:   Dict[str, CategoryStats] = {}

    for cat, items in by_cat.items():
        exp   = items[0][1]
        total = len(items)
        print(f"\n[{label}] {cat} — {total} contract(s)  (expected: {exp})")
        print("  " + "─" * 70)

        stats      = CategoryStats(name=cat)
        cat_results: List[ContractResult] = []

        if workers > 1:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                future_map = {
                    pool.submit(_analyse_contract, engine, sol, exp, cat, dataset): sol
                    for sol, _ in items
                }
                for future in as_completed(future_map):
                    cat_results.append(future.result())
        else:
            for idx, (sol, _) in enumerate(items, start=1):
                r = _analyse_contract(engine, sol, exp, cat, dataset)
                _print_result(r, idx, total)
                cat_results.append(r)

        # Sort parallel results by filename for reproducible output
        if workers > 1:
            cat_results.sort(key=lambda x: x.path.name)
            for idx, r in enumerate(cat_results, start=1):
                _print_result(r, idx, total)

        for r in cat_results:
            stats.total += 1
            if r.is_error:
                stats.err += 1
            elif r.is_tp:
                stats.tp += 1
            else:
                stats.fn += 1

        print()
        _print_category_stats(stats)
        all_results.extend(cat_results)
        cat_stats[cat] = stats

    return all_results, cat_stats

# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def _save_reports(
    all_results: List[ContractResult],
    cat_stats:   Dict[str, CategoryStats],
    label:       str,
    dataset:     str,
) -> None:
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)

    ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
    slug   = label.lower().replace(" ", "_")
    base   = reports_dir / f"benchmark_{slug}_{ts}"
    latest = reports_dir / f"benchmark_{slug}_latest"

    # ── JSON (full report) ────────────────────────────────────────────
    payload = {
        "generated_at": datetime.now().isoformat(),
        "label":        label,
        "dataset":      dataset,
        "summary": {
            cat: {
                "total":  s.total,
                "tp":     s.tp,
                "fn":     s.fn,
                "err":    s.err,
                "recall": round(s.recall, 4),
                "f1":     round(s.f1, 4),
            }
            for cat, s in cat_stats.items()
        },
        # FIX v1.2.0: include source / vulnerability / fn fields for metrics.py
        "contracts": [
            {
                "file":          r.path.name,
                "source":        dataset,          # "SolidiFI" or "SmartBugs"
                "vulnerability": r.category,       # category folder name
                "category":      r.category,
                "expected":      r.expected_type,
                "found":         r.found_types,
                "tp":            int(r.is_tp),
                "fn":            int(not r.is_tp and not r.is_error),
                "error":         int(r.is_error),
                "error_msg":     r.error_msg,
                "elapsed_ms":    r.elapsed_ms,
            }
            for r in all_results
        ],
    }

    for path in (f"{base}.json", f"{latest}.json"):
        Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")

    # ── CSV ───────────────────────────────────────────────────────────
    fieldnames = [
        "file", "source", "vulnerability", "category",
        "expected", "found", "tp", "fn", "error", "error_msg", "elapsed_ms",
    ]
    for path in (f"{base}.csv", f"{latest}.csv"):
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            for r in all_results:
                w.writerow({
                    "file":          r.path.name,
                    "source":        dataset,
                    "vulnerability": r.category,
                    "category":      r.category,
                    "expected":      r.expected_type,
                    "found":         "|".join(r.found_types),
                    "tp":            int(r.is_tp),
                    "fn":            int(not r.is_tp and not r.is_error),
                    "error":         int(r.is_error),
                    "error_msg":     r.error_msg,
                    "elapsed_ms":    r.elapsed_ms,
                })

    print(f"\n  Reports → {base}.json / .csv")

    # FIX v1.2.0: also write benchmark_results.json at cwd for metrics.py
    _save_flat_results(all_results, dataset)


def _save_flat_results(all_results: List[ContractResult], dataset: str) -> None:
    """
    Save a flat benchmark_results.json at the working directory.
    This is the exact format consumed by metrics.py:
        {"source": "SolidiFI", "vulnerability": "Reentrancy", "tp": 1, "fn": 0}
    """
    flat = [
        {
            "source":        dataset,
            "vulnerability": r.category,
            "expected":      r.expected_type,
            "found":         r.found_types,
            "tp":            int(r.is_tp),
            "fn":            int(not r.is_tp and not r.is_error),
            "error":         int(r.is_error),
            "error_msg":     r.error_msg,
            "elapsed_ms":    r.elapsed_ms,
            "file":          r.path.name,
        }
        for r in all_results
    ]

    out_path = Path("benchmark_results.json")
    # If file exists from a previous run, merge (append) rather than overwrite
    existing: List[dict] = []
    if out_path.exists():
        try:
            existing = json.loads(out_path.read_text(encoding="utf-8"))
            if not isinstance(existing, list):
                existing = []
        except Exception:
            existing = []

    merged = existing + flat
    out_path.write_text(json.dumps(merged, indent=2), encoding="utf-8")
    print(f"  benchmark_results.json updated ({len(merged)} total records)")

# ---------------------------------------------------------------------------
# Aggregate summary printer
# ---------------------------------------------------------------------------

def _print_aggregate(cat_stats: Dict[str, CategoryStats], label: str) -> None:
    if not cat_stats:
        return

    total = tp = fn = err = 0
    for s in cat_stats.values():
        total += s.total
        tp    += s.tp
        fn    += s.fn
        err   += s.err

    denom  = tp + fn
    recall = tp / denom if denom else 0.0

    print(f"\n{'='*65}")
    print(f"  {label} — AGGREGATE RESULTS")
    print(f"{'='*65}")
    print(
        f"  Total={total}  TP={tp}  FN={fn}  ERR={err}  "
        f"Recall={recall:.3f}"
    )
    print(f"  [{_bar(tp, max(1, total - err))}]")
    print()

    # Per-category table
    print(f"  {'Category':<35} {'Total':>5} {'TP':>4} {'FN':>4} {'ERR':>4} {'Recall':>7}")
    print("  " + "─" * 65)
    for cat, s in sorted(cat_stats.items()):
        bar_mini = "✅" if s.recall >= 0.70 else ("⚠️ " if s.recall >= 0.40 else "❌")
        print(
            f"  {bar_mini} {s.name:<33} {s.total:>5} {s.tp:>4} {s.fn:>4} "
            f"{s.err:>4} {s.recall:>7.1%}"
        )

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="VigilanceCore benchmark runner — SolidiFI + SmartBugs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python benchmark_runner.py --only solidifi          # SolidiFI full run
  python benchmark_runner.py --only solidifi --max 5  # quick smoke-test
  python benchmark_runner.py --category Reentrancy    # one category only
  python benchmark_runner.py --workers 4              # parallel
  python benchmark_runner.py --install-solc           # pre-install solc versions
        """,
    )
    parser.add_argument(
        "--only", choices=["smartbugs", "solidifi"],
        help="Run only one dataset (default: both)",
    )
    parser.add_argument(
        "--category",
        help="Run only this category folder name (e.g. Reentrancy, Timestamp)",
    )
    parser.add_argument(
        "--max", type=int, default=None,
        metavar="N",
        help="Max contracts per category — useful for quick smoke tests",
    )
    parser.add_argument(
        "--workers", type=int, default=1,
        help="Number of parallel analysis threads (default: 1; use ≥4 for speed)",
    )
    parser.add_argument(
        "--install-solc", action="store_true",
        help="Pre-install all required solc versions then exit",
    )
    parser.add_argument(
        "--reset-results", action="store_true",
        help="Delete benchmark_results.json before running (fresh start)",
    )
    args = parser.parse_args()

    if args.install_solc:
        print("Pre-installing solc versions for SmartBugs …")
        _bulk_install_solc(SMARTBUGS_ROOT)
        print("Pre-installing solc versions for SolidiFI …")
        _bulk_install_solc(SOLIDIFI_ROOT)
        print("Done.")
        return

    if args.reset_results:
        p = Path("benchmark_results.json")
        if p.exists():
            p.unlink()
            print("Cleared benchmark_results.json")

    print("Loading detectors …")
    engine = _build_engine()
    print()

    all_results: List[ContractResult] = []
    all_stats:   Dict[str, CategoryStats] = {}

    # ── SmartBugs ────────────────────────────────────────────────────
    if args.only in (None, "smartbugs"):
        print("\n" + "=" * 65)
        print("  Running SmartBugs Curated …")
        print("=" * 65)
        sb_results, sb_stats = _run_dataset(
            engine, "SmartBugs", "SmartBugs",
            SMARTBUGS_ROOT, SMARTBUGS_CATEGORY_MAP,
            args.category, args.max, args.workers,
        )
        all_results.extend(sb_results)
        all_stats.update({f"sb_{k}": v for k, v in sb_stats.items()})
        _print_aggregate(sb_stats, "SmartBugs")
        _save_reports(sb_results, sb_stats, "smartbugs", "SmartBugs")

    # ── SolidiFI ─────────────────────────────────────────────────────
    if args.only in (None, "solidifi"):
        print("\n" + "=" * 65)
        print("  Running SolidiFI Benchmark …")
        print("=" * 65)
        sf_results, sf_stats = _run_dataset(
            engine, "SolidiFI", "SolidiFI",
            SOLIDIFI_ROOT, SOLIDIFI_CATEGORY_MAP,
            args.category, args.max, args.workers,
        )
        all_results.extend(sf_results)
        all_stats.update({f"sf_{k}": v for k, v in sf_stats.items()})
        _print_aggregate(sf_stats, "SolidiFI")
        _save_reports(sf_results, sf_stats, "solidifi", "SolidiFI")

    # ── Combined summary ─────────────────────────────────────────────
    if args.only is None and all_stats:
        _print_aggregate(all_stats, "COMBINED")

    print("Done.")


if __name__ == "__main__":
    main()
