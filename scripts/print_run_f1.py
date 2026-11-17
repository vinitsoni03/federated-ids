"""Print the test F1 scores of one run.

    python scripts/print_run_f1.py artifacts/runs/<run>/metrics.json
"""
import json
import sys

t = json.load(open(sys.argv[1], encoding="utf-8"))["test"]
print(f"  macro-F1   {t['macro_f1']:.4f}")
print(f"  accuracy   {t['accuracy']:.4f}")
print(f"  binary F1  {t['binary_f1']:.4f}   (attack vs benign)")
for name, m in t["per_class"].items():
    print(f"    {name:11s} F1 {m['f1']:.3f}")
