"""WP4 evaluation: federated runs at calibrated operating points, communication and convergence.

For every finished clean FedAvg run of a task - v1 architecture (`fl_<task>_<part>_fedavg_s<seed>`, M5)
and v2 architecture (`fl_<task>_v2_...`, WP4) - the saved global model is scored like the centralized
detectors in WP3: thresholds for 5 % / 1 % benign FPR are fitted on validation and applied unchanged
to test. Convergence: first round whose val macro-F1 reaches 95 % of the centralized v2 MLP's mean
val macro-F1 (from history.csv; evaluated every 2 rounds). Communication: uncompressed float32 MB
(broadcast + upload) from the run's metrics.

Usage:
    python -m federated_ids.experiments.wp4_eval [--tasks category class34 binary] [--device cuda]
Output: reports/tables/wp4_federated.csv (one row per run and operating point)
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from dataclasses import asdict

import torch

from federated_ids.config import REPO_ROOT, data_config
from federated_ids.data.dataset import benign_index, task_labels
from federated_ids.evaluation.calibration import operating_points
from federated_ids.experiments.centralized import prepare
from federated_ids.experiments.wp3_detectors import TARGETS, load_mlp
from federated_ids.models.mlp import predict_proba, resolve_device

RUNS = REPO_ROOT / "artifacts" / "runs"
NAME = re.compile(r"^fl_(?P<task>category|class34|binary)_(?P<v2>v2_)?(?P<part>iid|dir1\.0|dir0\.1)_fedavg"
                  r"(?:_(?P<variant>part0\.5|c20|le2))?_s(?P<seed>\d+)$")


def rounds_to(history: list[dict], target: float):
    for h in history:
        if float(h["val_macro_f1"]) >= target:
            return int(h["round"]), float(h["comm_MB"])
    return None, None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--tasks", nargs="*", default=["category", "class34", "binary"])
    ap.add_argument("--device", default="cuda")
    a = ap.parse_args(argv)
    device = resolve_device(a.device)
    dcfg = data_config()
    rows = []
    for task in a.tasks:
        names, benign = task_labels(task), benign_index(task)
        v2cfg = json.loads((RUNS / "centralized_v2" / task / "config.json").read_text(encoding="utf-8"))
        target = 0.95 * v2cfg["mlp_val_macro_f1_mean"]
        runs = sorted(d for d in RUNS.iterdir() if (m := NAME.match(d.name)) and m["task"] == task
                      and (d / "metrics.json").exists())
        if not runs:
            continue
        features, pre, data = prepare({"task": task, "feature_set": "window_invariant"}, dcfg)
        va, te = data["val"], data["test"]
        for d in runs:
            m = NAME.match(d.name)
            cfg = json.loads((d / "config.json").read_text(encoding="utf-8"))["experiment"]
            if cfg["poison"].get("kind", "none") != "none" or cfg["federated"]["aggregator"] != "fedavg":
                continue
            if json.loads((d / "preprocessor.json").read_text(encoding="utf-8")) != json.loads(json.dumps(asdict(pre))):
                raise SystemExit(f"{d.name}: preprocessor differs from the centralized one")
            model = load_mlp(d / "global_model.pt", va["Xp"].shape[1], len(names), cfg["model"]["hidden"],
                             cfg["model"]["dropout"], device)
            pv, pt = predict_proba(model, va["Xp"]), predict_proba(model, te["Xp"])
            th = {r["operating_point"]: r["threshold"] for r in operating_points(pv, va["y"], names, benign, TARGETS)
                  if r["threshold"] is not None}
            met = json.loads((d / "metrics.json").read_text(encoding="utf-8"))
            with open(d / "history.csv", encoding="utf-8") as fh:
                hist = list(csv.DictReader(fh))
            r95, mb95 = rounds_to(hist, target)
            base = {"task": task, "run": d.name, "arch": "v2" if m["v2"] else "v1", "partition": m["part"],
                    "variant": m["variant"] or "base", "seed": int(m["seed"]),
                    "n_clients": cfg["federated"]["n_clients"], "participation": cfg["federated"]["participation"],
                    "local_epochs": cfg["federated"]["local_epochs"], "rounds": cfg["federated"]["rounds"],
                    "comm_MB_total": met["communication"]["total_MB"], "wall_s": met["wall_clock_seconds"],
                    "val_f1_target_95pct": round(target, 4), "rounds_to_95pct": r95, "comm_MB_to_95pct": mb95}
            for r in operating_points(pt, te["y"], names, benign, TARGETS, th):
                rows.append({**base, "split": "test", **{k: r[k] for k in ("operating_point", "threshold", "macro_f1",
                                                                          "benign_fpr", "attack_detection_rate", "binary_f1")}})
            print(f"{d.name}: test F1 {rows[-3]['macro_f1']:.4f} | 1% det {rows[-1]['attack_detection_rate']:.4f} "
                  f"FPR {rows[-1]['benign_fpr']:.4f} | rounds->95% {r95}", flush=True)
            del model
            torch.cuda.empty_cache() if device.type == "cuda" else None
    path = REPO_ROOT / "reports" / "tables" / "wp4_federated.csv"
    with open(path, "w", newline="", encoding="utf-8") as fh:
        wr = csv.DictWriter(fh, fieldnames=list(rows[0]))
        wr.writeheader()
        wr.writerows(rows)
    print(f"wrote {path} ({len(rows)} rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
