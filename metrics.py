import json
from collections import defaultdict

with open("benchmark_results.json") as f:
    results = json.load(f)

stats = defaultdict(lambda: {"tp": 0, "fn": 0, "total": 0})

for r in results:
    key = f"{r['source']} | {r['vulnerability']}"
    stats[key]["tp"]    += int(r["tp"])
    stats[key]["fn"]    += int(r["fn"])
    stats[key]["total"] += 1

print(f"\n{'Benchmark | Vulnerability':<45} {'Total':>7} {'Detected':>9} {'Missed':>7} {'Recall':>8}")
print("-" * 80)

for key, s in sorted(stats.items()):
    recall = s["tp"] / s["total"] if s["total"] > 0 else 0
    status = "✅" if recall >= 0.7 else "⚠️" if recall >= 0.4 else "❌"
    print(f"{status} {key:<43} {s['total']:>7} {s['tp']:>9} {s['fn']:>7} {recall:>8.1%}")

total_tp = sum(s["tp"] for s in stats.values())
total    = sum(s["total"] for s in stats.values())
print("-" * 80)
print(f"{'OVERALL':<45} {total:>7} {total_tp:>9} {total-total_tp:>7} {total_tp/total:>8.1%}")