"""WP3 step 1: MLP hyperparameter grid search on the validation set.

The test split is never loaded here, so search results cannot leak into the frozen evaluation.
Each (task, config, seed) is one run; finished runs are skipped, so the search is resumable.

Usage:
    python -m federated_ids.experiments.hparam_search [--config configs/hparam_search.yaml]
        [--tasks category class34 binary] [--seeds 0] [--device cuda] [--limit N]
        [--top-k K --seeds 1 2]   # seed re-check: rerun the K best seed-0 configs per task
Outputs: artifacts/runs/wp3_hparam_search/<task>/<config_id>_s<seed>/ (model, history, metrics)
         reports/tables/wp3_hparam_search.csv (one row per run, all tasks)
         reports/tables/wp3_hparam_by_config.csv (mean/std over seeds per config)
"""
from __future__ import annotations

import argparse
import csv
import itertools
import json
import statistics
import sys
import time

import torch

from federated_ids.config import REPO_ROOT, data_config, load_yaml
from federated_ids.data.ciciot import FEATURES
from federated_ids.data.dataset import benign_index, load_split, task_labels
from federated_ids.data.preprocess import Preprocessor, select_features
from federated_ids.evaluation.metrics import classification_metrics
from federated_ids.experiments.centralized import train_mlp
from federated_ids.experiments.common import environment, run_dir, write_json
from federated_ids.models.mlp import predict_proba, resolve_device

SEARCH_NAME = "wp3_hparam_search"
CSV_FIELDS = ["task", "config_id", "seed", "hidden", "lr", "class_weighting", "dropout",
              "val_macro_f1", "val_benign_fpr", "val_attack_detection_rate", "val_binary_f1",
              "val_binary_roc_auc", "val_macro_pr_auc_ovr", "best_epoch", "epochs_run", "hit_epoch_cap",
              "n_parameters", "train_seconds"]


def config_id(hidden, lr, class_weighting, dropout) -> str:
    return f"h{'-'.join(map(str, hidden))}_lr{lr:g}_{class_weighting}_do{dropout:g}"


def grid(cfg: dict):
    g = cfg["grid"]
    for hidden, lr, weighting, dropout in itertools.product(g["hidden"], g["lr"], g["class_weighting"], g["dropout"]):
        yield {"hidden": list(hidden), "lr": float(lr), "class_weighting": weighting, "dropout": float(dropout)}


def load_train_val(task: str, feature_set: str, dcfg: dict):
    """Train + val only (no test). Preprocessor fitted on train, as in the centralized runs."""
    features = select_features(FEATURES, dcfg["features"]["window_dependent"], feature_set)
    tr = load_split("train", features, task, dcfg)
    va = load_split("val", features, task, dcfg)
    pre = Preprocessor(features).fit(tr.X)
    return features, pre, {"train": {"Xp": pre.transform(tr.X), "y": tr.y}, "val": {"Xp": pre.transform(va.X), "y": va.y}}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", default="configs/hparam_search.yaml")
    ap.add_argument("--tasks", nargs="*")
    ap.add_argument("--seeds", nargs="*", type=int)
    ap.add_argument("--device")
    ap.add_argument("--limit", type=int, help="stop after N new runs (timing check)")
    ap.add_argument("--top-k", type=int, help="only the K best configs per task by seed-0 val macro-F1")
    a = ap.parse_args(argv)
    cfg = load_yaml(a.config)
    tasks = a.tasks or cfg["tasks"]
    seeds = a.seeds if a.seeds is not None and len(a.seeds) else cfg["seeds"]
    device = resolve_device(a.device or cfg.get("device", "auto"))
    torch.set_num_threads(6)
    dcfg = data_config()
    root = run_dir(SEARCH_NAME)
    write_json(root / ("recheck_config.json" if a.top_k else "search_config.json"),
               {"search": cfg, "tasks": tasks, "seeds": seeds, "top_k": a.top_k,
                "device": str(device), "environment": environment(),
                "command": "python -m federated_ids.experiments.hparam_search " + " ".join(argv or sys.argv[1:])})
    logf = open(root / "log.txt", "a", encoding="utf-8")

    def log(msg):
        print(msg, flush=True)
        logf.write(msg + "\n")
        logf.flush()

    log(f"=== search start {time.strftime('%Y-%m-%d %H:%M:%S')} device {device} tasks {tasks} seeds {seeds}")
    new_runs = 0
    for task in tasks:
        configs = list(grid(cfg))
        if a.top_k:
            top = top_config_ids(root, task, a.top_k)
            configs = [p for p in configs if config_id(**p) in top]
            log(f"[{task}] top-{a.top_k} seed-0 configs: {top}")
        todo = [(p, s) for p in configs for s in seeds
                if not (root / task / f"{config_id(**p)}_s{s}" / "metrics_val.json").exists()]
        log(f"[{task}] {len(todo)} runs to do")
        if not todo:
            continue
        t0 = time.time()
        features, pre, data = load_train_val(task, cfg["feature_set"], dcfg)
        (root / task).mkdir(exist_ok=True)
        pre.to_json(root / task / "preprocessor.json")
        log(f"[{task}] data loaded in {time.time() - t0:.0f}s: train {len(data['train']['y'])} val {len(data['val']['y'])}")
        class_names, benign = task_labels(task), benign_index(task)
        for p, seed in todo:
            if a.limit is not None and new_runs >= a.limit:
                log(f"limit {a.limit} reached")
                return 0
            cid = config_id(**p)
            out = root / task / f"{cid}_s{seed}"
            out.mkdir(parents=True, exist_ok=True)
            run_cfg = {"model": {"hidden": p["hidden"], "dropout": p["dropout"]},
                       "train": {**cfg["train"], "lr": p["lr"], "class_weighting": p["class_weighting"]}}
            log(f"[{task}] {cid} seed {seed}")
            model, hist, train_s = train_mlp(run_cfg, data, len(class_names), seed, class_names, benign,
                                             lambda m: None, device)
            proba = predict_proba(model, data["val"]["Xp"])
            mv = classification_metrics(data["val"]["y"], proba.argmax(1), class_names, benign, proba)
            best_epoch = max(hist, key=lambda h: h["val_macro_f1"])["epoch"]
            meta = {"task": task, "config_id": cid, "seed": seed, **p, "best_epoch": best_epoch,
                    "epochs_run": len(hist), "hit_epoch_cap": len(hist) == cfg["train"]["epochs"],
                    "n_parameters": int(sum(q.numel() for q in model.parameters())),
                    "train_seconds": round(train_s, 1), "features": features, "run_config": run_cfg}
            torch.save(model.state_dict(), out / "mlp.pt")
            with open(out / "history.csv", "w", newline="", encoding="utf-8") as fh:
                wr = csv.DictWriter(fh, fieldnames=list(hist[0]))
                wr.writeheader()
                wr.writerows(hist)
            write_json(out / "metrics_val.json", {**meta, "val": mv})  # written last = run complete
            new_runs += 1
            log(f"[{task}] {cid} seed {seed}: val macroF1 {mv['macro_f1']:.4f} FPR {mv['benign_fpr']:.4f} "
                f"best epoch {best_epoch}/{len(hist)} ({train_s:.0f}s)")
    write_table(root)
    log(f"=== search done {time.strftime('%Y-%m-%d %H:%M:%S')}, {new_runs} new runs")
    return 0


def top_config_ids(root, task: str, k: int) -> list[str]:
    """The k config ids with the highest seed-0 val macro-F1 (requires the full seed-0 grid)."""
    res = [json.loads(f.read_text(encoding="utf-8")) for f in (root / task).glob("*_s0/metrics_val.json")]
    if not res:
        raise SystemExit(f"no seed-0 results for {task}; run the grid first")
    res.sort(key=lambda m: -m["val"]["macro_f1"])
    return [m["config_id"] for m in res[:k]]


def write_table(root) -> None:
    """Collect every finished run into reports/tables/wp3_hparam_search.csv, best first per task."""
    rows = []
    for f in sorted(root.glob("*/*/metrics_val.json")):
        m = json.loads(f.read_text(encoding="utf-8"))
        v = m["val"]
        rows.append({**{k: m[k] for k in ("task", "config_id", "seed", "lr", "class_weighting", "dropout",
                                          "best_epoch", "epochs_run", "hit_epoch_cap", "n_parameters",
                                          "train_seconds")},
                     "hidden": "-".join(map(str, m["hidden"])),
                     "val_macro_f1": v["macro_f1"], "val_benign_fpr": v.get("benign_fpr"),
                     "val_attack_detection_rate": v.get("attack_detection_rate"), "val_binary_f1": v.get("binary_f1"),
                     "val_binary_roc_auc": v.get("binary_roc_auc"), "val_macro_pr_auc_ovr": v.get("macro_pr_auc_ovr")})
    rows.sort(key=lambda r: (r["task"], -r["val_macro_f1"]))
    path = REPO_ROOT / "reports" / "tables" / "wp3_hparam_search.csv"
    with open(path, "w", newline="", encoding="utf-8") as fh:
        wr = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        wr.writeheader()
        wr.writerows(rows)
    # per-config aggregate over seeds (the seed re-check selects on mean val macro-F1)
    groups = {}
    for r in rows:
        groups.setdefault((r["task"], r["config_id"]), []).append(r)
    agg = []
    for (task, cid), rs in groups.items():
        f1 = [r["val_macro_f1"] for r in rs]
        fpr = [r["val_benign_fpr"] for r in rs]
        agg.append({"task": task, "config_id": cid, "n_seeds": len(rs),
                    "seeds": " ".join(str(r["seed"]) for r in sorted(rs, key=lambda r: r["seed"])),
                    "val_macro_f1_mean": statistics.mean(f1), "val_macro_f1_std": statistics.pstdev(f1),
                    "val_macro_f1_min": min(f1), "val_benign_fpr_mean": statistics.mean(fpr)})
    agg.sort(key=lambda r: (r["task"], -r["n_seeds"], -r["val_macro_f1_mean"]))
    with open(path.with_name("wp3_hparam_by_config.csv"), "w", newline="", encoding="utf-8") as fh:
        wr = csv.DictWriter(fh, fieldnames=list(agg[0]))
        wr.writeheader()
        wr.writerows(agg)


if __name__ == "__main__":
    sys.exit(main())
