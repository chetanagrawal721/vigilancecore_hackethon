"""
apply_reentrancy_patch.py
Run once from your project root:
    python patches/apply_reentrancy_patch.py
Removes the unsupported `line_number=` kwarg from every Finding() call
inside reentrancy_detector.py.
"""
import re, shutil, sys
from pathlib import Path

TARGET = Path("detectors/reentrancy_detector.py")

if not TARGET.exists():
    sys.exit(f"[ERR] {TARGET} not found — run from project root")

shutil.copy(TARGET, TARGET.with_suffix(".py.bak"))

src = TARGET.read_text(encoding="utf-8")

# Remove   line_number=<anything>,   or   line_number=<anything>   (last arg)
patched = re.sub(
    r",?\s*line_number\s*=\s*[^,\n)]+",
    "",
    src,
)

TARGET.write_text(patched, encoding="utf-8")
print(f"[OK] Patched {TARGET}  (backup at {TARGET.with_suffix('.py.bak')})")
print("     Removed all `line_number=` kwargs from Finding() calls.")
