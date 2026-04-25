"""
patches/register_new_detectors.py
Run once from project root:
    python patches/register_new_detectors.py

Swaps broken detector references for the new v2 versions in
core/analysis_engine.py (the default detector list) so you don't have to
manually edit each file.
"""
import re, shutil
from pathlib import Path

ENGINE = Path("core/analysis_engine.py")
if not ENGINE.exists():
    print(f"[SKIP] {ENGINE} not found")
else:
    src = ENGINE.read_text(encoding="utf-8")
    shutil.copy(ENGINE, ENGINE.with_suffix(".py.bak"))

    replacements = [
        # swap timestamp v1 → v2
        (r"detectors\.timestamp_detector\b", "detectors.timestamp_detector_v2"),
        (r"TimestampDetector\b",             "TimestampDetectorV2"),
        # swap arithmetic v1 → v2
        (r"detectors\.arithmetic_detector\b","detectors.arithmetic_detector_v2"),
        (r"ArithmeticDetector\b",            "ArithmeticDetectorV2"),
        (r"detectors\.integer_overflow\b",   "detectors.arithmetic_detector_v2"),
        (r"IntegerOverflowDetector\b",       "ArithmeticDetectorV2"),
    ]
    for pattern, replacement in replacements:
        src = re.sub(pattern, replacement, src)

    ENGINE.write_text(src, encoding="utf-8")
    print(f"[OK] Updated {ENGINE} with v2 detector references")
    print("     Backup at", ENGINE.with_suffix(".py.bak"))
