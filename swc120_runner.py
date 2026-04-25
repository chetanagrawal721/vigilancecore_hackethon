"""
swc120_runner.py

VigilanceCore adapter for the SWC-120 Bad Randomness benchmark dataset.
https://github.com/HadisRe/BadRandomness-SWC120-Dataset

Dataset structure (two layouts handled automatically):
  Layout A — flat CSV label file:
      BadRandomness-SWC120-Dataset/
          labels.csv          (columns: filename, is_vulnerable, risk_level)
          contracts/
              *.sol

  Layout B — risk-level subdirectories (fallback):
      BadRandomness-SWC120-Dataset/
          Low/    *.sol
          Medium/ *.sol
          High/   *.sol
          Critical/*.sol

Usage
-----
python swc120_runner.py                         # full run
python swc120_runner.py --max 50               # quick test
python swc120_runner.py --workers 4            # parallel
python swc120_runner.py --risk High Critical   # specific risk levels only
python swc120_runner.py --install-solc         # pre-install solc versions

Why this dataset matters
------------------------
Slither  recall = 0% (only checks direct block.* usage)
Mythril  recall = 0% (same limitation)
VigilanceCore uses the TaintEngine to propagate block.timestamp /
block.number / blockhash through intermediate assignments to decision
sinks — catching all the patterns that Slither and Mythril miss.

TP logic
--------
A contract is TP if VulnerabilityType.BAD_RANDOMNESS ("bad_randomness")
appears in any Finding. Contracts labelled is_vulnerable=0 in the CSV
are treated as TRUE NEGATIVES — extra findings on them count as FP.
This runner reports both Recall and Precision.

Reports saved to ./reports/benchmark_swc120_<timestamp>.json/csv
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
from typing import Dict, List, Optional, Set, Tuple

logging.basicConfig(level=logging.WARNING, format="%(levelname)s:%(name)s:%(message)s")
logger = logging.getLogger("swc120_runner")

# ---------------------------------------------------------------------------
# PATH — edit this to wherever you cloned the dataset
# ---------------------------------------------------------------------------
SWC120_ROOT = Path("../BadRandomness-SWC120-Dataset/ground_truth")

RISK_LEVELS = ["ground_truth"]

EXPECTED_VULN_TYPE = "bad_randomness"   # VulnerabilityType.BAD_RANDOMNESS.value

# ---------------------------------------------------------------------------
# Detector modules to load
# ---------------------------------------------------------------------------
DETECTOR_MODULES = [
    ("detectors.randomness_detector",       "RandomnessDetector"),
    ("detectors.timestamp_detector",        "TimestampDetector"),
    ("detectors.reentrancy_detector",       "ReentrancyDetector"),
    ("detectors.access_control_detector",   "AccessControlDetector"),
    ("detectors.arithmetic_detector",       "ArithmeticDetector"),
    ("detectors.unchecked_return_detector", "UncheckedReturnDetector"),
    ("detectors.dos_detector",              "DosDetector"),
    ("detectors.txorigin_detector",         "TxOriginDetector"),
    ("detectors.delegatecall_detector",     "DelegateCallDetector"),
    ("detectors.business_logic",            "BusinessLogicDetector"),
    ("detectors.integer_overflow",          "IntegerOverflowDetector"),
]

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class SWC120Result:
    path: Path
    risk_level: str          # Low / Medium / High / Critical / unknown
    is_vulnerable: bool      # from ground-truth label
    found_bad_randomness: bool
    found_types: List[str]
    is_tp: bool
    is_fp: bool
    is_error: bool
    error_msg: str = ""
    elapsed_ms: int = 0

@dataclass
class RiskStats:
    name: str
    total_vuln: int = 0
    total_clean: int = 0
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
# Build engine
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

# ---------------------------------------------------------------------------
# Discover contracts
# ---------------------------------------------------------------------------
def _discover_contracts(
    root: Path,
    only_risks: Optional[Set[str]],
    max_contracts: Optional[int],
) -> List[Tuple[Path, bool, str]]:
    """
    Returns list of (sol_path, is_vulnerable, risk_level).
    Tries CSV label file first; falls back to folder-per-risk-level layout.
    """
    contracts: List[Tuple[Path, bool, str]] = []

    # ── Layout A: labels CSV ─────────────────────────────────────────────
    label_candidates = list(root.glob("*.csv")) + list(root.glob("labels*"))
    label_file = label_candidates[0] if label_candidates else None

    if label_file and label_file.exists():
        print(f"Found label file: {label_file.name}")
        contracts_dir = root / "contracts"
        if not contracts_dir.exists():
            contracts_dir = root   # flat layout

        with open(label_file, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        for row in rows:
            # Flexible column name matching
            filename  = (row.get("filename") or row.get("file") or row.get("name") or "").strip()
            vuln_flag = (row.get("is_vulnerable") or row.get("vulnerable") or row.get("label") or "0").strip()
            risk      = (row.get("risk_level") or row.get("risk") or "unknown").strip()

            if only_risks and risk not in only_risks:
                continue

            is_vuln = vuln_flag in ("1", "true", "True", "yes", "vulnerable")
            sol_path = contracts_dir / filename
            if not sol_path.exists():
                # try without subdir
                matches = list(root.rglob(filename))
                sol_path = matches[0] if matches else sol_path

            if sol_path.exists():
                contracts.append((sol_path, is_vuln, risk))

        if contracts:
            if max_contracts:
                contracts = contracts[:max_contracts]
            print(f"Loaded {len(contracts)} contracts from CSV labels.")
            return contracts

    # ── Layout B: folder per risk level ─────────────────────────────────
    print("No CSV label file found — using folder-per-risk-level layout.")
    for risk_dir in sorted(root.iterdir()):
        if not risk_dir.is_dir():
            continue
        risk = risk_dir.name
        if risk not in RISK_LEVELS:
            continue
        if only_risks and risk not in only_risks:
            continue
        for sol in sorted(risk_dir.glob("*.sol")):
            contracts.append((sol, True, risk))   # folder layout = all vulnerable

    if max_contracts:
        contracts = contracts[:max_contracts]

    print(f"Loaded {len(contracts)} contracts from folder layout.")
    return contracts

# ---------------------------------------------------------------------------
# Analyse one contract
# ---------------------------------------------------------------------------
def _analyse_one(
    engine,
    sol_path: Path,
    is_vulnerable: bool,
    risk_level: str,
) -> SWC120Result:
    t0 = time.monotonic()
    try:
        result = engine.analyse(str(sol_path))
        elapsed = int((time.monotonic() - t0) * 1000)

        if result.error:
            return SWC120Result(
                path=sol_path, risk_level=risk_level,
                is_vulnerable=is_vulnerable, found_bad_randomness=False,
                found_types=[], is_tp=False, is_fp=False,
                is_error=True, error_msg=result.error[:120], elapsed_ms=elapsed,
            )

        found_types = []
        for f in (result.findings or []):
            vt = f.vuln_type
            found_types.append(str(vt.value if hasattr(vt, "value") else vt).lower())

        found_rand = any(
            "randomness" in t or "bad_rand" in t for t in found_types
        )

        is_tp = is_vulnerable and found_rand
        is_fp = (not is_vulnerable) and found_rand
        is_fn = is_vulnerable and not found_rand

        return SWC120Result(
            path=sol_path, risk_level=risk_level,
            is_vulnerable=is_vulnerable, found_bad_randomness=found_rand,
            found_types=found_types, is_tp=is_tp, is_fp=is_fp,
            is_error=False, elapsed_ms=elapsed,
        )

    except Exception as exc:
        return SWC120Result(
            path=sol_path, risk_level=risk_level,
            is_vulnerable=is_vulnerable, found_bad_randomness=False,
            found_types=[], is_tp=False, is_fp=False,
            is_error=True, error_msg=f"{type(exc).__name__}: {str(exc)[:100]}",
            elapsed_ms=0,
        )

# ---------------------------------------------------------------------------
# Pretty print
# ---------------------------------------------------------------------------
_BAR = 28

def _bar(n: int, total: int) -> str:
    if not total: return "░" * _BAR
    filled = round(_BAR * n / total)
    return "█" * filled + "░" * (_BAR - filled)

def _print_result(r: SWC120Result) -> None:
    if r.is_error:
        sym = "[E]"
        detail = r.error_msg[:60]
    elif r.is_tp:
        sym = "[✓]"
        detail = "TP — bad_randomness detected"
    elif r.is_fp:
        sym = "[!]"
        detail = "FP — flagged clean contract"
    elif r.is_vulnerable and not r.found_bad_randomness:
        sym = "[✗]"
        detail = f"FN — found: {', '.join(r.found_types) or 'nothing'}"
    else:
        sym = "[ ]"
        detail = "TN — clean, no finding"
    name = r.path.name[:55].ljust(55)
    print(f"  {sym} {name} {r.elapsed_ms:>6}ms [{r.risk_level:<8}] {detail}")

def _print_risk_stats(s: RiskStats) -> None:
    vuln_total = s.tp + s.fn
    clean_total = s.fp + s.tn
    print(
        f"  {s.name:<10}  vuln={vuln_total:4}  clean={clean_total:4} "
        f"TP={s.tp:4} FN={s.fn:4} FP={s.fp:4} TN={s.tn:4} ERR={s.err:3} "
        f"Recall={s.recall:.3f}  Prec={s.precision:.3f}  F1={s.f1:.3f}  "
        f"[{_bar(s.tp, max(1,vuln_total))}]"
    )

# ---------------------------------------------------------------------------
# Save reports
# ---------------------------------------------------------------------------
def _save_reports(results: List[SWC120Result], stats: Dict[str, RiskStats]) -> None:
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base    = reports_dir / f"benchmark_swc120_{ts}"
    latest  = reports_dir / "benchmark_swc120_latest"

    payload = {
        "generated_at": datetime.now().isoformat(),
        "dataset": "SWC-120 Bad Randomness",
        "note": "Slither=0% recall, Mythril=0% recall on this dataset",
        "summary": {
            risk: {
                "total_vulnerable": s.total_vuln,
                "total_clean":      s.total_clean,
                "tp": s.tp, "fn": s.fn, "fp": s.fp, "tn": s.tn, "err": s.err,
                "recall":    round(s.recall, 4),
                "precision": round(s.precision, 4),
                "f1":        round(s.f1, 4),
            }
            for risk, s in stats.items()
        },
        "contracts": [
            {
                "file":            r.path.name,
                "risk_level":      r.risk_level,
                "is_vulnerable":   r.is_vulnerable,
                "found_randomness":r.found_bad_randomness,
                "found_types":     r.found_types,
                "tp": r.is_tp, "fp": r.is_fp,
                "error":           r.is_error,
                "error_msg":       r.error_msg,
                "elapsed_ms":      r.elapsed_ms,
            }
            for r in results
        ],
    }

    for path in (f"{base}.json", f"{latest}.json"):
        Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")

    fieldnames = ["file","risk_level","is_vulnerable","found_randomness",
                  "found_types","tp","fp","error","error_msg","elapsed_ms"]
    for path in (f"{base}.csv", f"{latest}.csv"):
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            for r in results:
                w.writerow({
                    "file":r.path.name, "risk_level":r.risk_level,
                    "is_vulnerable":int(r.is_vulnerable),
                    "found_randomness":int(r.found_bad_randomness),
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
    parser = argparse.ArgumentParser(description="VigilanceCore SWC-120 benchmark")
    parser.add_argument("--max",      type=int,   default=None, help="Max contracts total")
    parser.add_argument("--workers",  type=int,   default=1,    help="Parallel threads")
    parser.add_argument("--risk",     nargs="+",  default=None, help="Risk levels to include e.g. High Critical")
    parser.add_argument("--install-solc", action="store_true",  help="Pre-install solc versions then exit")
    args = parser.parse_args()

    if not SWC120_ROOT.exists():
        print(f"[ERROR] Dataset not found at: {SWC120_ROOT}")
        print("  Clone with: git clone https://github.com/HadisRe/BadRandomness-SWC120-Dataset")
        sys.exit(1)

    if args.install_solc:
        from benchmark_runner import _bulk_install_solc
        _bulk_install_solc(SWC120_ROOT)
        return

    only_risks = set(args.risk) if args.risk else None

    print("=" * 70)
    print("VigilanceCore × SWC-120 Bad Randomness Benchmark")
    print("Note: Slither=0% recall, Mythril=0% recall on this dataset")
    print("=" * 70)

    contracts = _discover_contracts(SWC120_ROOT, only_risks, args.max)
    if not contracts:
        print("[ERROR] No contracts discovered. Check SWC120_ROOT path.")
        sys.exit(1)

    engine = _build_engine()

    results: List[SWC120Result] = []
    stats: Dict[str, RiskStats] = {}

    # Group by risk level for display
    by_risk: Dict[str, List[Tuple[Path, bool]]] = {}
    for sol, is_vuln, risk in contracts:
        by_risk.setdefault(risk, []).append((sol, is_vuln))

    for risk in sorted(by_risk.keys()):
        items = by_risk[risk]
        n_vuln  = sum(1 for _, v in items if v)
        n_clean = len(items) - n_vuln
        print(f"\n[SWC-120] {risk} — {len(items)} contract(s) "
              f"({n_vuln} vulnerable, {n_clean} clean)")

        s = RiskStats(name=risk, total_vuln=n_vuln, total_clean=n_clean)
        risk_results: List[SWC120Result] = []

        if args.workers > 1:
            with ThreadPoolExecutor(max_workers=args.workers) as pool:
                futures = {
                    pool.submit(_analyse_one, engine, sol, is_vuln, risk): sol
                    for sol, is_vuln in items
                }
                for future in as_completed(futures):
                    risk_results.append(future.result())
        else:
            for sol, is_vuln in items:
                r = _analyse_one(engine, sol, is_vuln, risk)
                _print_result(r)
                risk_results.append(r)

        if args.workers > 1:
            for r in sorted(risk_results, key=lambda x: x.path.name):
                _print_result(r)

        for r in risk_results:
            if r.is_error:
                s.err += 1
            elif r.is_tp:
                s.tp += 1
            elif r.is_fp:
                s.fp += 1
            elif r.is_vulnerable and not r.found_bad_randomness:
                s.fn += 1
            else:
                s.tn += 1

        _print_risk_stats(s)
        stats[risk] = s
        results.extend(risk_results)

    # Aggregate
    total_vuln  = sum(s.tp + s.fn for s in stats.values())
    total_clean = sum(s.fp + s.tn for s in stats.values())
    total_tp    = sum(s.tp for s in stats.values())
    total_fn    = sum(s.fn for s in stats.values())
    total_fp    = sum(s.fp for s in stats.values())
    total_err   = sum(s.err for s in stats.values())
    macro_rec   = sum(s.recall    for s in stats.values()) / len(stats) if stats else 0
    macro_prec  = sum(s.precision for s in stats.values()) / len(stats) if stats else 0
    macro_f1    = sum(s.f1        for s in stats.values()) / len(stats) if stats else 0

    print("\n" + "=" * 70)
    print("SWC-120 AGGREGATE")
    print("=" * 70)
    print(f"  Vulnerable: {total_vuln}   Clean: {total_clean}")
    print(f"  TP={total_tp}  FN={total_fn}  FP={total_fp}  ERR={total_err}")
    print(f"  Macro Recall:    {macro_rec:.4f}")
    print(f"  Macro Precision: {macro_prec:.4f}")
    print(f"  Macro F1:        {macro_f1:.4f}")
    print(f"  [{_bar(total_tp, max(1, total_vuln))}]")
    print()
    print("  Comparison (from published paper arxiv:2601.09836):")
    print(f"    Slither  recall = 0.000  (direct block.* check only)")
    print(f"    Mythril  recall = 0.000  (direct block.* check only)")
    print(f"    VigilanceCore   = {macro_rec:.3f}  (taint propagation)")

    _save_reports(results, stats)
    print("\nDone.")

if __name__ == "__main__":
    main()
