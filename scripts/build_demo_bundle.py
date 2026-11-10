"""Build the small, self-contained bundle the demo dashboard (demo/app.py) runs from.

Everything is copied from existing artifacts; nothing is retrained or re-scored here:
  * 8-class v2 MLP seed 0, frozen (WP3)            -> frozen.pt   + its val thresholds
  * the same model after 2 adversarial-training rounds (WP5) -> hardened.pt + its val thresholds
  * the shared train-only preprocessor and the attacker's TTL choices (benign-train TTL quantiles, as in WP5)
  * real raw TEST windows: per attack family N windows from the fixed WP5 test sample, plus N benign test windows
  * Flower Azure+laptop run history (per-round test macro-F1 / benign FPR) and headline result numbers

    python scripts/build_demo_bundle.py [--per-family 40]
Needs the prepared split (data/ work dir). Output: demo/bundle/ (~1 MB, committed so the demo runs from a clone).
"""
from __future__ import annotations

import argparse
import csv
import json
import shutil
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from federated_ids.data.ciciot import CLASS34, family_of_class34  # noqa: E402
from federated_ids.data.dataset import benign_index, load_split, task_labels  # noqa: E402

TASK = "category"
RUNS = ROOT / "artifacts" / "runs"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-family", type=int, default=40)
    ap.add_argument("--out", default=str(ROOT / "demo" / "bundle"))
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    v2dir, wp5dir = RUNS / "centralized_v2" / TASK, RUNS / "wp5_advtrain" / TASK
    cfg = json.loads((v2dir / "config.json").read_text(encoding="utf-8"))
    features, names, benign = cfg["features"], task_labels(TASK), benign_index(TASK)

    th_frozen = json.loads((v2dir / "thresholds.json").read_text(encoding="utf-8"))["v2_mlp_s0"]
    th_hard = json.loads((wp5dir / "eval_mlp_s0_r2.json").read_text(encoding="utf-8"))["thresholds"]
    shutil.copy(v2dir / "mlp_seed0.pt", out / "frozen.pt")
    shutil.copy(wp5dir / "mlp_s0_r2.pt", out / "hardened.pt")
    shutil.copy(v2dir / "preprocessor.json", out / "preprocessor.json")

    tr = load_split("train", features, TASK)
    te = load_split("test", features, TASK)
    ttl_col = features.index("Time_To_Live")
    ttl_choices = [None] + [float(np.nanquantile(tr.X[tr.y == benign, ttl_col], q)) for q in (0.1, 0.5, 0.9)]
    del tr

    rng = np.random.default_rng(0)
    test_idx = np.load(wp5dir / "test_sample_idx.npy")
    fam = family_of_class34(te.y34)
    picks = []
    for c in names:
        pool = np.flatnonzero(te.y == benign) if c == "Benign" else test_idx[fam[test_idx] == c]
        picks.append(np.sort(rng.choice(pool, min(a.per_family, len(pool)), replace=False)))
    idx = np.concatenate(picks)
    windows = [{"id": int(i), "family": names[int(te.y[i])], "attack": CLASS34[int(te.y34[i])],
                "x": [None if np.isnan(v) else float(v) for v in te.X[i]]} for i in idx]

    with open(RUNS / "flower_azure_hybrid_category_iid_s0" / "history.csv", encoding="utf-8") as fh:
        fl_hist = [{k: float(v) for k, v in r.items()} for r in csv.DictReader(fh)]
    fl_metrics = json.loads((RUNS / "flower_azure_hybrid_category_iid_s0" / "metrics.json").read_text(encoding="utf-8"))
    fl_logs = [f.name for f in (RUNS / "flower_azure_hybrid_category_iid_s0" / "flower_logs").glob("*_supernode_*.log")]
    supernodes = {"azure": sum(n.startswith("azure") for n in fl_logs), "laptop": sum(n.startswith("laptop") for n in fl_logs)}

    meta = {"task": TASK, "features": features, "class_names": names, "benign": benign,
            "hidden": cfg["mlp"]["hidden"], "dropout": cfg["mlp"]["dropout"],
            "models": {"frozen": {"file": "frozen.pt", "thresholds": th_frozen,
                                  "source": "artifacts/runs/centralized_v2/category/mlp_seed0.pt (WP3 frozen v2)"},
                       "hardened": {"file": "hardened.pt", "thresholds": th_hard,
                                    "source": "artifacts/runs/wp5_advtrain/category/mlp_s0_r2.pt (WP5 round 2)"}},
            "ttl_choices": ttl_choices,
            "flower": {"history": fl_hist, "wall_clock_seconds": fl_metrics["wall_clock_seconds"],
                       "communication_MB": fl_metrics["communication"]["total_MB_estimate"],
                       "n_parameters": fl_metrics["communication"]["n_parameters"], "supernodes": supernodes, "server_host": fl_metrics["server_host"],
                       "test_macro_f1": fl_metrics["test"]["macro_f1"]}}
    (out / "meta.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")
    (out / "windows.json").write_text(json.dumps(windows), encoding="utf-8")
    print(f"wrote {out}: {len(windows)} windows ({a.per_family}/family), TTL choices {ttl_choices}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
