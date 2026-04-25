"""
messiq_runner.py

VigilanceCore adapter for the Messi-Q Smart Contract Dataset.
https://github.com/Messi-Q/Smart-Contract-Dataset

Dataset structure:
    Smart-Contract-Dataset/
        reentrancy/
            positive/   *.sol   (vulnerable contracts)
            negative/   *.sol   (clean contracts)
        timestamp_dependency/
            positive/   *.sol
            negative/   *.sol
        integer_overflow/
            positive/   *.sol
            negative/   *.sol
        delegate/
            positive/   *.sol
            negative/   *.sol

Why run this?
-------------
The Messi-Q dataset is the standard evaluation dataset used by GNN-based
and deep-learning-based tools (Zhuang et al. IJCAI 2020, DeepSC, etc.)
Running VigilanceCore here places results directly comparable with
neural-network baselines WITHOUT needing a trained model.

TP logic
--------
- Positive contracts (vulnerable):  TP if expected type found, FN otherwise
- Negative contracts (clean):       TN if nothing / FP if false alarm
Precision, Recall, F1 reported per category.

Reports saved to ./reports/benchmark_messiq_<timestamp>.json/csv

Usage
-----
python messiq_runner.py                     # full run
python messiq_runner.py --max 100          # quick test
python messiq_runner.py --workers 4        # parallel
python messiq_runner.py --category reentrancy
python messiq_runner.py --install-solc     # pre-install solc versions
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from importlib import import_module
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

logging.basicConfig(level=logging.WARNING, format="%(levelname)s:%(name)s:%(message)s")
logger = logging.getLogger("messiq_runner")

# ---------------------------------------------------------------------------
# PATH — edit to wherever you cloned the dataset
# ---------------------------------------------------------------------------
MESSIQ_ROOT = Path("../Smart-Contract-Dataset")

# ---------------------------------------------------------------------------
# Category folder name → VulnerabilityType.value
# Handles all known naming variants across Messi-Q versions
# ---------------------------------------------------------------------------
MESSIQ_CATEGORY_MAP: Dict[str, str] = {
    # Reentrancy
    "reentrancy":                "reentrancy",
    "Reentrancy":                "reentrancy",
    "re-entrancy":               "reentrancy",

    # Timestamp
    "timestamp_dependency":      "time_manipulation",
    "timestamp":                 "time_manipulation",
    "Timestamp":                 "time_manipulation",
    "time_manipulation":         "time_manipulation",

    # Integer overflow
    "integer_overflow":          "arithmetic_overflow",
    "integer_overflow_underflow":"arithmetic_overflow",
    "overflow":                  "arithmetic_overflow",
    "arithmetic":                "arithmetic_overflow",
    "Arithmetic":                "arithmetic_overflow",

    # Delegatecall
    "delegate":                  "delegatecall_issue",
    "delegatecall":              "delegatecall_issue",
    "Delegate":                  "delegatecall_issue",

    # Access control (some versions)
    "access_control":            "access_control",
    "AccessControl":             "access_control",

    # Tx origin
    "tx_origin":                 "tx_origin_usage",
    "TxOrigin":                  "tx_origin_usage",

    # Dos
    "dos":                       "denial_of_service",
    "DoS":                       "denial_of_service",
}

# Alias groups for TP matching (same as benchmark_runner.py)
_ALIASES: Dict[str, set] = {
    "arithmetic_overflow": {"integer_overflow", "arithmetic_overflow",
                            "overflow_underflow", "arithmetic_issue"},
    "delegatecall_issue":  {"delegatecall_issue", "delegatecall"},
    "time_manipulation":   {"time_manipulation", "timestamp", "bad_timestamp"},
    "tx_origin_usage":     {"tx_origin_usage", "tx_origin", "txorigin"},
    "denial_of_service":   {"denial_of_service", "dos", "locked_ether"},
    "reentrancy":          {"reentrancy"},
    "access_control":      {"access_control"},
}

DETECTOR_MODULES = [
    ("detectors.reentrancy_detector",       "ReentrancyDetector"),
    ("detectors.access_control_detector",   "AccessControlDetector"),
    ("detectors.txorigin_detector",         "TxOriginDetector"),
    ("detectors.timestamp_detector",        "TimestampDetector"),
    ("detectors.unchecked_return_detector", "UncheckedReturnDetector"),
    ("detectors.randomness_detector",       "RandomnessDetector"),
    ("detectors.dos_detector",              "DosDetector"),
    ("detectors.arithmetic_detector",       "ArithmeticDetector"),
    ("detectors.delegatecall_detector",     "DelegateCallDetector"),
    ("detectors.business_logic",            "BusinessLogicDetector"),
    ("detectors.integer_overflow",          "IntegerOverflowDetector"),
]

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class MessiQResult:
    path: Path
    category: str
    expected_type: str
    is_vulnerable: bool       # True = positive folder, False = negative
    found_types: List[str]
    is_tp: bool
    is_fp: bool
    is_error: bool
    error_msg: str = ""
    elapsed_ms: int = 0

@dataclass
class CatStats:
    name: str
    tp: int = 0
    fn: int = 0
    fp: int = 0
    tn: int = 0
    err: int = 0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2*p*r/(p+r) if (p+r) else 0.0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _build_engine():
    from core.analysis_engine import AnalysisEngine
    engine = AnalysisEngine()
    for mod_path, cls_name in DETECTOR_MODULES:
        try:
            mod = import_module(mod_path)
            cls = getattr(mod, cls_name)
            det = cls()
            if det.DETECTOR_ID not in engine.registered_detectors:
                engine.register(det)
        except Exception as exc:
            logger.warning("Skipping %s — %s", cls_name, exc)
    print(f"Engine ready — {len(engine.registered_detectors)} detector(s)")
    return engine

def _is_tp(expected: str, found: List[str]) -> bool:
    exp = expected.lower().strip()
    found_set = {f.lower().strip() for f in found}
    if exp in found_set:
        return True
    alias_set = _ALIASES.get(exp, {exp})
    return bool(alias_set & found_set)

def _found_types(result) -> List[str]:
    out = []
    for f in (result.findings or []):
        vt = f.vuln_type
        out.append(str(vt.value if hasattr(vt, "value") else vt).lower())
    return out

# ---------------------------------------------------------------------------
# Discover
# ---------------------------------------------------------------------------
def _discover(
    root: Path,
    only_category: Optional[str],
    max_per_split: Optional[int],
) -> List[Tuple[Path, str, str, bool]]:
    """Returns (sol_path, category_name, expected_type, is_vulnerable)."""
    contracts = []

    for cat_dir in sorted(root.iterdir()):
        if not cat_dir.is_dir():
            continue
        cat = cat_dir.name
        expected = MESSIQ_CATEGORY_MAP.get(cat)
        if expected is None:
            logger.debug("Unknown category '%s' — skipping", cat)
            continue
        if only_category and cat.lower() != only_category.lower():
            continue

        # Look for positive/ and negative/ subdirs
        pos_dirs = [d for d in cat_dir.iterdir()
                    if d.is_dir() and d.name.lower() in ("positive", "pos", "vulnerable", "1")]
        neg_dirs = [d for d in cat_dir.iterdir()
                    if d.is_dir() and d.name.lower() in ("negative", "neg", "clean", "0")]

        if not pos_dirs and not neg_dirs:
            # Flat layout — treat all as vulnerable
            sols = sorted(cat_dir.glob("*.sol"))
            if max_per_split:
                sols = sols[:max_per_split]
            for sol in sols:
                contracts.append((sol, cat, expected, True))
            continue

        for pos_dir in pos_dirs:
            sols = sorted(pos_dir.rglob("*.sol"))
            if max_per_split:
                sols = sols[:max_per_split]
            for sol in sols:
                contracts.append((sol, cat, expected, True))

        for neg_dir in neg_dirs:
            sols = sorted(neg_dir.rglob("*.sol"))
            if max_per_split:
                sols = sols[:max_per_split]
            for sol in sols:
                contracts.append((sol, cat, expected, False))

    return contracts

# ---------------------------------------------------------------------------
# Analyse one
# ---------------------------------------------------------------------------
def _analyse_one(
    engine, sol: Path, cat: str, expected: str, is_vuln: bool
) -> MessiQResult:
    t0 = time.monotonic()
    try:
        result = engine.analyse(str(sol))
        elapsed = int((time.monotonic() - t0) * 1000)

        if result.error:
            return MessiQResult(
                path=sol, category=cat, expected_type=expected,
                is_vulnerable=is_vuln, found_types=[],
                is_tp=False, is_fp=False, is_error=True,
                error_msg=result.error[:120], elapsed_ms=elapsed,
            )

        found = _found_types(result)
        tp = is_vuln and _is_tp(expected, found)
        fp = (not is_vuln) and _is_tp(expected, found)

        return MessiQResult(
            path=sol, category=cat, expected_type=expected,
            is_vulnerable=is_vuln, found_types=found,
            is_tp=tp, is_fp=fp, is_error=False, elapsed_ms=elapsed,
        )
    except Exception as exc:
        return MessiQResult(
            path=sol, category=cat, expected_type=expected,
            is_vulnerable=is_vuln, found_types=[],
            is_tp=False, is_fp=False, is_error=True,
            error_msg=f"{type(exc).__name__}: {str(exc)[:100]}", elapsed_ms=0,
        )

# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------
_BAR = 28

def _bar(n: int, total: int) -> str:
    if not total: return "░" * _BAR
    filled = round(_BAR * n / total)
    return "█" * filled + "░" * (_BAR - filled)

def _print_result(r: MessiQResult) -> None:
    split = "pos" if r.is_vulnerable else "neg"
    if r.is_error:
        sym, detail = "[E]", r.error_msg[:60]
    elif r.is_tp:
        sym, detail = "[✓]", f"TP ({r.expected_type})"
    elif r.is_fp:
        sym, detail = "[!]", f"FP — found: {', '.join(r.found_types)}"
    elif r.is_vulnerable and not _is_tp(r.expected_type, r.found_types):
        sym, detail = "[✗]", f"FN — found: {', '.join(r.found_types) or 'nothing'}"
    else:
        sym, detail = "[ ]", "TN"
    name = r.path.name[:50].ljust(50)
    print(f"  {sym} [{split}] {name} {r.elapsed_ms:>6}ms  {detail}")

def _print_stats(s: CatStats) -> None:
    vuln_total = s.tp + s.fn
    print(
        f"  {s.name:<35} TP={s.tp:4} FN={s.fn:4} FP={s.fp:4} "
        f"TN={s.tn:4} ERR={s.err:3}  "
        f"Recall={s.recall:.3f}  Prec={s.precision:.3f}  F1={s.f1:.3f}  "
        f"[{_bar(s.tp, max(1, vuln_total))}]"
    )

# ---------------------------------------------------------------------------
# Save reports
# ---------------------------------------------------------------------------
def _save_reports(results: List[MessiQResult], stats: Dict[str, CatStats]) -> None:
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base   = reports_dir / f"benchmark_messiq_{ts}"
    latest = reports_dir / "benchmark_messiq_latest"

    payload = {
        "generated_at": datetime.now().isoformat(),
        "dataset": "Messi-Q Smart Contract Dataset",
        "github": "https://github.com/Messi-Q/Smart-Contract-Dataset",
        "note": "Standard evaluation dataset for GNN-based vulnerability detection tools",
        "summary": {
            cat: {
                "tp": s.tp, "fn": s.fn, "fp": s.fp, "tn": s.tn, "err": s.err,
                "recall":    round(s.recall, 4),
                "precision": round(s.precision, 4),
                "f1":        round(s.f1, 4),
            }
            for cat, s in stats.items()
        },
        "contracts": [
            {
                "file":          r.path.name,
                "category":      r.category,
                "expected_type": r.expected_type,
                "is_vulnerable": r.is_vulnerable,
                "found_types":   r.found_types,
                "tp": r.is_tp, "fp": r.is_fp,
                "error":         r.is_error,
                "error_msg":     r.error_msg,
                "elapsed_ms":    r.elapsed_ms,
            }
            for r in results
        ],
    }

    for path in (f"{base}.json", f"{latest}.json"):
        Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")

    fieldnames = ["file","category","expected_type","is_vulnerable",
                  "found_types","tp","fp","error","error_msg","elapsed_ms"]
    for path in (f"{base}.csv", f"{latest}.csv"):
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            for r in results:
                w.writerow({
                    "file":r.path.name, "category":r.category,
                    "expected_type":r.expected_type,
                    "is_vulnerable":int(r.is_vulnerable),
                    "found_types":"|".join(r.found_types),
                    "tp":int(r.is_tp), "fp":int(r.is_fp),
                    "error":int(r.is_error), "error_msg":r.error_msg,
                    "elapsed_ms":r.elapsed_ms,
                })

    print(f"\nReports saved: {base}.json / .csv")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description="VigilanceCore Messi-Q benchmark")
    parser.add_argument("--max",      type=int,  default=None, help="Max contracts per pos/neg split")
    parser.add_argument("--workers",  type=int,  default=1,    help="Parallel threads")
    parser.add_argument("--category", default=None,            help="Single category folder")
    parser.add_argument("--install-solc", action="store_true", help="Pre-install solc versions")
    args = parser.parse_args()

    if not MESSIQ_ROOT.exists():
        print(f"[ERROR] Dataset not found at: {MESSIQ_ROOT}")
        print("  Clone: git clone https://github.com/Messi-Q/Smart-Contract-Dataset")
        sys.exit(1)

    if args.install_solc:
        from benchmark_runner import _bulk_install_solc
        _bulk_install_solc(MESSIQ_ROOT)
        return

    print("=" * 70)
    print("VigilanceCore × Messi-Q Smart Contract Vulnerability Benchmark")
    print("Comparable with: Zhuang GNN (IJCAI 2020), DeepSC, contractWard")
    print("=" * 70)

    contracts = _discover(MESSIQ_ROOT, args.category, args.max)
    if not contracts:
        print("[ERROR] No contracts found. Check MESSIQ_ROOT.")
        sys.exit(1)

    n_vuln  = sum(1 for _,_,_,v in contracts if v)
    n_clean = len(contracts) - n_vuln
    print(f"Total: {len(contracts)} contracts ({n_vuln} vulnerable, {n_clean} clean)")

    engine  = _build_engine()
    results: List[MessiQResult] = []
    stats:   Dict[str, CatStats] = {}

    # Group by category
    by_cat: Dict[str, List[Tuple[Path, str, bool]]] = {}
    for sol, cat, exp, is_vuln in contracts:
        by_cat.setdefault(cat, []).append((sol, exp, is_vuln))

    for cat, items in sorted(by_cat.items()):
        n_v = sum(1 for _,_,v in items if v)
        n_c = len(items) - n_v
        print(f"\n[Messi-Q] {cat} — {len(items)} contract(s) "
              f"({n_v} vulnerable, {n_c} clean)")

        s = CatStats(name=cat)
        cat_results: List[MessiQResult] = []

        if args.workers > 1:
            with ThreadPoolExecutor(max_workers=args.workers) as pool:
                futures = {
                    pool.submit(_analyse_one, engine, sol, cat, exp, is_vuln): sol
                    for sol, exp, is_vuln in items
                }
                for future in as_completed(futures):
                    cat_results.append(future.result())
        else:
            for sol, exp, is_vuln in items:
                r = _analyse_one(engine, sol, cat, exp, is_vuln)
                _print_result(r)
                cat_results.append(r)

        if args.workers > 1:
            for r in sorted(cat_results, key=lambda x: x.path.name):
                _print_result(r)

        for r in cat_results:
            if r.is_error:
                s.err += 1
            elif r.is_tp:
                s.tp += 1
            elif r.is_fp:
                s.fp += 1
            elif r.is_vulnerable:
                s.fn += 1
            else:
                s.tn += 1

        _print_stats(s)
        stats[cat] = s
        results.extend(cat_results)

    # Aggregate
    total_tp  = sum(s.tp  for s in stats.values())
    total_fn  = sum(s.fn  for s in stats.values())
    total_fp  = sum(s.fp  for s in stats.values())
    total_tn  = sum(s.tn  for s in stats.values())
    total_err = sum(s.err for s in stats.values())
    macro_rec  = sum(s.recall    for s in stats.values()) / len(stats) if stats else 0
    macro_prec = sum(s.precision for s in stats.values()) / len(stats) if stats else 0
    macro_f1   = sum(s.f1        for s in stats.values()) / len(stats) if stats else 0

    print("\n" + "=" * 70)
    print("MESSI-Q AGGREGATE")
    print("=" * 70)
    print(f"  TP={total_tp}  FN={total_fn}  FP={total_fp}  TN={total_tn}  ERR={total_err}")
    print(f"  Macro Recall:    {macro_rec:.4f}")
    print(f"  Macro Precision: {macro_prec:.4f}")
    print(f"  Macro F1:        {macro_f1:.4f}")
    print(f"  [{_bar(total_tp, max(1, total_tp + total_fn))}]")
    print()
    print("  Published baselines (Zhuang et al. IJCAI 2020):")
    print("    GNN-based tool  Recall~0.89  Precision~0.86  F1~0.87")
    print(f"   VigilanceCore    Recall={macro_rec:.3f}  Precision={macro_prec:.3f}  F1={macro_f1:.3f}")

    _save_reports(results, stats)
    print("\nDone.")

if __name__ == "__main__":
    main()
