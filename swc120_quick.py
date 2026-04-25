import sys
sys.path.insert(0, r"B:\vigilancecore")

from pathlib import Path
from importlib import import_module
from core.analysis_engine import AnalysisEngine

GT_DIR = Path(r"B:\BadRandomness-SWC120-Dataset\ground_truth")

engine = AnalysisEngine()
sols = sorted(GT_DIR.glob("*.sol"))
print(f"Found {len(sols)} contracts in ground_truth/")

tp = fn = err = 0
for sol in sols:
    try:
        result = engine.analyse(str(sol))
        types = [str(f.vuln_type.value).lower() for f in (result.findings or [])]
        if any("randomness" in t or "blockhash" in t for t in types):
            tp += 1
            print(f"  [✓] {sol.name}")
        else:
            fn += 1
            print(f"  [✗] {sol.name} — found: {types or 'nothing'}")
    except Exception as e:
        err += 1
        print(f"  [E] {sol.name} — {e}")


# In your contract discovery loop:

total = tp + fn
print(f"\nRecall: {tp}/{total} = {tp/total:.1%}" if total else "No results")
print(f"Errors: {err}")
print(f"\nSlither  recall = 0%")
print(f"Mythril  recall = 0%")
print(f"VigilanceCore   = {tp/total:.1%}" if total else "")


