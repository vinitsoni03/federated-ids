"""WP3 step 5: freeze centralized v2 and evaluate it ONCE on test, at thresholds fitted on validation.

Frozen detectors (student's choice, 2026-11-01): the v2 MLP (best grid config by 3-seed mean val
macro-F1, seeds 0-2) and HistGradientBoosting (seed 0, the model trained in wp3_detectors).
For the v1-vs-v2 table the v1 MLP (seeds 0-2) and the v1 Random Forest are scored the same way.

For every detector/seed: thresholds for 5 % and 1 % benign FPR are re-fitted on validation and must
equal the ones stored by wp3_detectors (the model selection step); they are then applied unchanged to
the test sample, its unseen subset and (seed 0 / single-seed models) the full held-out test pool.
An evaluation file that already exists is never recomputed, so the test set is used once.

Usage:
    python -m federated_ids.experiments.wp3_freeze [--tasks category class34 binary] [--device cuda]
Outputs: artifacts/runs/centralized_v2/<task>/ (frozen models, thresholds.json, eval/*.json)
         reports/tables/wp3_test_operating_points.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import shutil
import sys
import time

import numpy as np
import torch

from federated_ids.config import REPO_ROOT, data_config, load_yaml
from federated_ids.data.dataset import benign_index, split_manifest, task_labels
from federated_ids.evaluation.calibration import (_row, attack_score, operating_points, predict_with_threshold,
                                                  threshold_for_fpr)
from federated_ids.evaluation.full_test import iter_test_pool
from federated_ids.evaluation.metrics import classification_metrics
from federated_ids.experiments.centralized import prepare
from federated_ids.experiments.common import environment, run_dir, write_json
from federated_ids.experiments.wp3_detectors import TARGETS, best_v2_config, load_mlp
from federated_ids.data.dataset import labels_for
from federated_ids.models.mlp import predict_proba, resolve_device

RUN_NAME = "centralized_v2"
OP_NAMES = ["argmax"] + [f"fpr{t * 100:g}" for t in TARGETS]


def full_pool_ops(proba_fn, pre, dcfg, man, features, task, names, benign, thresholds) -> list[dict]:
    """Stream the full test pool once; derive argmax and thresholded predictions from one proba pass."""
    ys, preds = [], {k: [] for k in OP_NAMES}
    t0 = time.time()
    for X, y34, y8 in iter_test_pool(dcfg, man, features):
        p = proba_fn(pre.transform(X))
        ys.append(labels_for(task, y34, y8))
        preds["argmax"].append(p.argmax(1))
        for k, t in thresholds.items():
            preds[k].append(predict_with_threshold(p, benign, t))
    y = np.concatenate(ys)
    rows = []
    for k in OP_NAMES:
        m = classification_metrics(y, np.concatenate(preds[k]), names, benign)
        tgt = None if k == "argmax" else float(k[3:]) / 100
        rows.append(_row(k, tgt, thresholds.get(k), m))
    rows[0]["seconds"] = round(time.time() - t0, 1)
    return rows


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--tasks", nargs="*", default=["category", "class34", "binary"])
    ap.add_argument("--device", default="cuda")
    a = ap.parse_args(argv)
    device = resolve_device(a.device)
    torch.set_num_threads(6)
    dcfg, man = data_config(), split_manifest()
    ccfg = load_yaml("configs/centralized.yaml")
    root = run_dir(RUN_NAME)
    det_root = REPO_ROOT / "artifacts" / "runs" / "wp3_detectors"
    logf = open(root / "log.txt", "a", encoding="utf-8")

    def log(msg):
        print(msg, flush=True)
        logf.write(msg + "\n")
        logf.flush()

    log(f"=== start {time.strftime('%Y-%m-%d %H:%M:%S')} tasks {a.tasks} device {device}")
    for task in a.tasks:
        out = root / task
        (out / "eval").mkdir(parents=True, exist_ok=True)
        names, benign = task_labels(task), benign_index(task)
        features, pre, data = prepare({"task": task, "feature_set": ccfg["feature_set"]}, dcfg)
        pre.to_json(out / "preprocessor.json")
        va, te = data["val"], data["test"]
        n_cls, n_in = len(names), va["Xp"].shape[1]
        v1_dir = REPO_ROOT / "artifacts" / "runs" / f"centralized_{task}_window_invariant"
        best = best_v2_config(task)
        mc = ccfg["model"]

        # freeze: copy the selected artefacts next to their config
        for s, p in best["models"]:
            shutil.copy2(p, out / f"mlp_seed{s}.pt")
        shutil.copy2(det_root / task / "hgb_s0.joblib", out / "hgb_s0.joblib")
        write_json(out / "config.json", {"task": task, "features": features,
                                         "mlp": {k: best[k] for k in ("config_id", "hidden", "dropout", "lr", "class_weighting")},
                                         "mlp_source": [str(p.relative_to(REPO_ROOT)) for _, p in best["models"]],
                                         "mlp_val_macro_f1_mean": best["val_macro_f1_mean"],
                                         "hgb_source": f"artifacts/runs/wp3_detectors/{task}/hgb_s0.joblib",
                                         "targets": list(TARGETS), "environment": environment()})

        def mlp_fn(path, hidden, dropout):
            model = load_mlp(path, n_in, n_cls, hidden, dropout, device)
            return lambda X: predict_proba(model, X)

        def tree_fn(model):
            def f(X):
                p = np.zeros((len(X), n_cls))
                p[:, model.classes_] = model.predict_proba(X)
                return p
            return f

        jobs = [("v1_mlp", s, lambda s=s: mlp_fn(v1_dir / f"mlp_seed{s}.pt", mc["hidden"], mc["dropout"])) for s in (0, 1, 2)]
        jobs += [("v2_mlp", s, lambda s=s: mlp_fn(out / f"mlp_seed{s}.pt", best["hidden"], best["dropout"])) for s, _ in best["models"]]
        jobs += [("hgb", 0, lambda: tree_fn(__import__("joblib").load(out / "hgb_s0.joblib")))]

        def make_rf():
            from sklearn.ensemble import RandomForestClassifier
            rc = ccfg["random_forest"]
            return tree_fn(RandomForestClassifier(n_estimators=rc["n_estimators"], max_depth=rc["max_depth"],
                                                  min_samples_leaf=rc["min_samples_leaf"], class_weight=rc["class_weight"],
                                                  n_jobs=rc["n_jobs"], random_state=rc["seed"]).fit(data["train"]["Xp"], data["train"]["y"]))
        jobs += [("rf", 0, make_rf)]

        thresholds_all = json.loads((out / "thresholds.json").read_text()) if (out / "thresholds.json").exists() else {}
        for det, seed, build in jobs:
            path = out / "eval" / f"{det}_s{seed}.json"
            if path.exists():
                log(f"[{task}] {det} s{seed}: already evaluated on test, skipped")
                continue
            fn = build()
            pv = fn(va["Xp"])
            th = {f"fpr{t * 100:g}": threshold_for_fpr(attack_score(pv, benign), va["y"] == benign, t) for t in TARGETS}
            stored = {r["operating_point"]: r["threshold"] for r in
                      json.loads((det_root / task / f"{det}_s{seed}.json").read_text(encoding="utf-8"))["operating_points"]
                      if r["threshold"] is not None}
            mismatch = {k: (th[k], stored[k]) for k in th if abs(th[k] - stored[k]) > 1e-9}
            if mismatch:
                raise SystemExit(f"{task} {det} s{seed}: val thresholds differ from model selection: {mismatch}")
            pt = fn(te["Xp"])
            seen = te["seen"]
            res = {"task": task, "detector": det, "seed": seed, "thresholds_from": "val", "thresholds": th,
                   "val": operating_points(pv, va["y"], names, benign, TARGETS, th),
                   "test": operating_points(pt, te["y"], names, benign, TARGETS, th),
                   "test_unseen": operating_points(pt[~seen], te["y"][~seen], names, benign, TARGETS, th)}
            if seed == 0:
                res["test_full_pool"] = full_pool_ops(fn, pre, dcfg, man, features, task, names, benign, th)
            write_json(path, res)
            thresholds_all[f"{det}_s{seed}"] = th
            write_json(out / "thresholds.json", thresholds_all)
            o = {r["operating_point"]: r for r in res["test"]}
            log(f"[{task}] {det} s{seed} TEST: " + " | ".join(
                f"{k} F1 {o[k]['macro_f1']:.4f} FPR {o[k]['benign_fpr']:.4f} det {o[k]['attack_detection_rate']:.4f}" for k in OP_NAMES))
            del fn
    write_table(root)
    log(f"=== done {time.strftime('%Y-%m-%d %H:%M:%S')}")
    return 0


def write_table(root) -> None:
    rows = []
    for f in sorted(root.glob("*/eval/*.json")):
        m = json.loads(f.read_text(encoding="utf-8"))
        for split in ("val", "test", "test_unseen", "test_full_pool"):
            for r in m.get(split, []):
                rows.append({"task": m["task"], "detector": m["detector"], "seed": m["seed"], "split": split,
                             **{k: r.get(k) for k in ("operating_point", "target_fpr", "threshold", "macro_f1",
                                                      "benign_fpr", "attack_detection_rate", "binary_f1")}})
    path = REPO_ROOT / "reports" / "tables" / "wp3_test_operating_points.csv"
    with open(path, "w", newline="", encoding="utf-8") as fh:
        wr = csv.DictWriter(fh, fieldnames=list(rows[0]))
        wr.writeheader()
        wr.writerows(rows)


if __name__ == "__main__":
    sys.exit(main())
