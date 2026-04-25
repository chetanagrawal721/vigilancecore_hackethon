"""
patches/02_fix_base_and_dos.py

Fixes TWO import errors that prevent 3 detectors from loading:

  Problem A — BusinessLogicDetector fails with:
      ImportError: cannot import name 'Confidence' from 'detectors.base_detector'
  Fix      — Injects a Confidence enum into base_detector.py (safe, idempotent).

  Problem B — DosDetector fails with:
      AttributeError: module 'detectors.dos_detector' has no attribute 'DosDetector'
  Fix      — You already replaced dos_detector.py with the full implementation
             from the VigilanceCore patches, so this step just validates it.

Run from your project root:
    python patches/02_fix_base_and_dos.py
"""

import ast, re, shutil, sys
from pathlib import Path

# ══════════════════════════════════════════════════════════════════════════════
# Confidence enum block to inject
# ══════════════════════════════════════════════════════════════════════════════
CONFIDENCE_BLOCK = 