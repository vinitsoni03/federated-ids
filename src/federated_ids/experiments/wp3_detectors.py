"""WP3 steps 2-4: calibrated operating points for every candidate detector (validation only).

Detectors per task (category, class34, binary):
  v1_mlp     the Phase-2 baseline MLP (artifacts/runs/centralized_<task>_window_invariant, 3 seeds)
  v2_mlp     the best grid-search config (highest mean val macro-F1 over the most-seeded configs)
  rf         Random Forest, v1 settings (configs/centralized.yaml), retrained because v1 kept no model
  hgb        HistGradientBoosting (balanced class weights, early stopping on an internal train split)
  two_stage  binary v2 MLP (benign vs attack) -> attack-only family/attack MLP on flagged rows
             (category and class34 only; same seed for both stages)
Each detector is scored at plain argmax and at benign FPR targets 5 % and 1 %, with thresholds fitted
on validation (federated_ids.evaluation.calibration). The test split is never loaded: these numbers
select the v2 detector; the frozen detector is evaluated on test once, in a separate step.

Usage:
    python -m federated_ids.experiments.wp3_detectors [--tasks category class34 binary]
        [--detectors v1_mlp v2_mlp rf hgb two_stage] [--device cuda]
Outputs: artifacts/runs/wp3_detectors/<task>/<detector>_s<seed>.json (+ stage-2 / HGB models)
         reports/tables/wp3_operating_points_val.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
import time
from dataclasses import asdict

import numpy as np
import torch

from federated_ids.config import REPO_ROOT, data_config, load_yaml
from federated_ids.data.dataset import benign_index, task_labels
from federated_ids.evaluation.calibration import operating_points
from federated_ids.experiments.centralized import train_mlp
from federated_ids.experiments.common import run_dir, write_json
from federated_ids.experiments.hparam_search import SEARCH_NAME, load_train_val
from federated_ids.models.mlp import MLP, predict_proba, resolve_device

RUN_NAME = "wp3_detectors"
DETECTORS = ["v1_mlp", "v2_mlp", "rf", "hgb", "two_stage"]
TARGETS = (0.05, 0.01)
V1_SEEDS = (0, 1, 2)


def best_v2_config(task: str) -> dict:
    """Best grid config for a task: among configs with the most seeds, highest mean val macro-F1."""
    groups = {}
    for f in (REPO_ROOT / "artifacts" / "runs" / SEARCH_NAME / task).glob("*/metrics_val.json"):
        m = json.loads(f.read_text(encoding="utf-8"))
        groups.setdefault(m["config_id"], []).append((m, f.parent / "mlp.pt"))
    if not groups:
        raise SystemExit(f"no grid-search results for {task}")
    most = max(len(v) for v in groups.values())
    cid, runs = max(((c, v) for c, v in groups.items() if len(v) == most),
                    key=lambda cv: statistics.mean(m["val"]["macro_f1"] for m, _ in cv[1]))
    m0 = runs[0][0]
    return {"config_id": cid, "hidden": m0["hidden"], "dropout": m0["dropout"], "lr": m0["lr"],
            "class_weighting": m0["class_weighting"], "run_config": m0["run_config"],
            "models": sorted((m["seed"], p) for m, p in runs),
            "val_macro_f1_mean": statistics.mean(m["val"]["macro_f1"] for m, _ in runs)}


def load_mlp(path, n_in, n_out, hidden, dropout, device) -> MLP:
    model = MLP(n_in, n_out, hidden, dropout).to(device)
    model.load_state_dict(torch.load(path, map_location=device))
    return model


def mlp_proba(path, X, n_out, hidden, dropout, device) -> np.ndarray:
    return predict_proba(load_mlp(path, X.shape[1], n_out, hidden, dropout, device), X)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--tasks", nargs="*", default=["category", "class34", "binary"])
    ap.add_argument("--detectors", nargs="*", default=DETECTORS, choices=DETECTORS)
    ap.add_argument("--device", default="cuda")
    ap.add_argument("--smoke", type=int, help="code-path test: subsample N rows, 2 epochs, separate output dir")
    a = ap.parse_args(argv)
    device = resolve_device(a.device)
    torch.set_num_threads(6)
    dcfg = data_config()
    ccfg = load_yaml("configs/centralized.yaml")
    feature_set = ccfg["feature_set"]
    root = run_dir(RUN_NAME + ("_smoke" if a.smoke else ""))
    logf = open(root / "log.txt", "a", encoding="utf-8")

    def log(msg):
        print(msg, flush=True)
        logf.write(msg + "\n")
        logf.flush()

    log(f"=== start {time.strftime('%Y-%m-%d %H:%M:%S')} tasks {a.tasks} detectors {a.detectors} device {device}")
    for task in a.tasks:
        out = root / task
        out.mkdir(exist_ok=True)
        names, benign = task_labels(task), benign_index(task)
        features, pre, data = load_train_val(task, feature_set, dcfg)
        # every task must share the v1 preprocessing (same train rows -> identical fit)
        v1_dir = REPO_ROOT / "artifacts" / "runs" / f"centralized_{task}_window_invariant"
        if json.loads((v1_dir / "preprocessor.json").read_text(encoding="utf-8")) != json.loads(json.dumps(asdict(pre))):
            raise SystemExit(f"{task}: preprocessor differs from the v1 run; refusing to compare")
        Xtr, ytr, Xva, yva = data["train"]["Xp"], data["train"]["y"], data["val"]["Xp"], data["val"]["y"]
        if a.smoke:
            rng = np.random.default_rng(0)
            itr, iva = rng.choice(len(ytr), a.smoke, replace=False), rng.choice(len(yva), a.smoke, replace=False)
            Xtr, ytr, Xva, yva = Xtr[itr], ytr[itr], Xva[iva], yva[iva]
        log(f"[{task}] train {len(ytr)} val {len(yva)}, {len(names)} classes")

        def record(detector, seed, proba, extra=None):
            path = out / f"{detector}_s{seed}.json"
            ops = operating_points(proba, yva, names, benign, TARGETS)
            write_json(path, {"task": task, "detector": detector, "seed": seed, "split": "val",
                              "operating_points": ops, **(extra or {})})
            o = {r["operating_point"]: r for r in ops}
            log(f"[{task}] {detector} s{seed}: argmax F1 {o['argmax']['macro_f1']:.4f} FPR {o['argmax']['benign_fpr']:.4f} | "
                + " | ".join(f"{k} det {o[k]['attack_detection_rate']:.4f} F1 {o[k]['macro_f1']:.4f}"
                             for k in ("fpr5", "fpr1")))

        def done(detector, seed):
            return (out / f"{detector}_s{seed}.json").exists()

        if "v1_mlp" in a.detectors:
            mc = ccfg["model"]
            for s in V1_SEEDS:
                if not done("v1_mlp", s):
                    record("v1_mlp", s, mlp_proba(v1_dir / f"mlp_seed{s}.pt", Xva, len(names), mc["hidden"], mc["dropout"], device),
                           {"source": str(v1_dir.relative_to(REPO_ROOT))})

        if "v2_mlp" in a.detectors:
            best = best_v2_config(task)
            log(f"[{task}] v2 config {best['config_id']} seeds {[s for s, _ in best['models']]} "
                f"(mean val macro-F1 {best['val_macro_f1_mean']:.4f})")
            for s, p in best["models"]:
                if not done("v2_mlp", s):
                    record("v2_mlp", s, mlp_proba(p, Xva, len(names), best["hidden"], best["dropout"], device),
                           {"config_id": best["config_id"], "model_path": str(p.relative_to(REPO_ROOT))})

        if "rf" in a.detectors and not done("rf", 0):
            from sklearn.ensemble import RandomForestClassifier

            rc = ccfg["random_forest"]
            t = time.time()
            rf = RandomForestClassifier(n_estimators=rc["n_estimators"], max_depth=rc["max_depth"],
                                        min_samples_leaf=rc["min_samples_leaf"], class_weight=rc["class_weight"],
                                        n_jobs=rc["n_jobs"], random_state=rc["seed"]).fit(Xtr, ytr)
            p = np.zeros((len(Xva), len(names)))
            p[:, rf.classes_] = rf.predict_proba(Xva)
            record("rf", 0, p, {"train_seconds": round(time.time() - t, 1), "params": rc})
            del rf

        if "hgb" in a.detectors and not done("hgb", 0):
            import joblib
            from sklearn.ensemble import HistGradientBoostingClassifier

            params = {"max_iter": 300, "learning_rate": 0.1, "max_leaf_nodes": 31, "early_stopping": True,
                      "validation_fraction": 0.1, "n_iter_no_change": 10, "class_weight": "balanced", "random_state": 0}
            t = time.time()
            hgb = HistGradientBoostingClassifier(**params).fit(Xtr, ytr)
            train_s = time.time() - t
            p = np.zeros((len(Xva), len(names)))
            p[:, hgb.classes_] = hgb.predict_proba(Xva)
            joblib.dump(hgb, out / "hgb_s0.joblib")
            record("hgb", 0, p, {"train_seconds": round(train_s, 1), "n_iter": int(hgb.n_iter_), "params": params})

        if "two_stage" in a.detectors and task != "binary":
            stage1 = best_v2_config("binary")
            best = best_v2_config(task)
            attack_cls = np.array([i for i in range(len(names)) if i != benign])
            remap = np.full(len(names), -1)
            remap[attack_cls] = np.arange(len(attack_cls))
            att_tr, att_va = ytr != benign, yva != benign
            sub = {"train": {"Xp": Xtr[att_tr], "y": remap[ytr[att_tr]]}, "val": {"Xp": Xva[att_va], "y": remap[yva[att_va]]}}
            sub_names = [names[i] for i in attack_cls]
            s2_cfg = best["run_config"]
            if a.smoke:
                s2_cfg = {**s2_cfg, "train": {**s2_cfg["train"], "epochs": 2}}
            for s, p1_path in stage1["models"]:
                if done("two_stage", s):
                    continue
                m2_path = out / f"two_stage_stage2_s{s}.pt"
                if m2_path.exists():
                    m2 = load_mlp(m2_path, Xtr.shape[1], len(attack_cls), best["hidden"], best["dropout"], device)
                    train_s = None
                else:
                    log(f"[{task}] two_stage s{s}: training stage 2 ({len(attack_cls)} attack classes, config {best['config_id']})")
                    m2, _, train_s = train_mlp(s2_cfg, sub, len(attack_cls), s, sub_names, None,
                                               lambda m: None, device)
                    torch.save(m2.state_dict(), m2_path)
                p_att = mlp_proba(p1_path, Xva, 2, stage1["hidden"], stage1["dropout"], device)[:, 1]
                p2 = predict_proba(m2, Xva)
                proba = np.zeros((len(Xva), len(names)))
                proba[:, benign] = 1.0 - p_att
                proba[:, attack_cls] = p_att[:, None] * p2
                record("two_stage", s, proba, {"stage1_config": stage1["config_id"], "stage1_model": str(p1_path.relative_to(REPO_ROOT)),
                                               "stage2_config": best["config_id"], "stage2_model": str(m2_path.relative_to(REPO_ROOT)),
                                               "stage2_train_seconds": None if train_s is None else round(train_s, 1)})
    write_table(root, a.smoke)
    log(f"=== done {time.strftime('%Y-%m-%d %H:%M:%S')}")
    return 0


def write_table(root, smoke=None) -> None:
    rows = []
    for f in sorted(root.glob("*/*_s*.json")):
        m = json.loads(f.read_text(encoding="utf-8"))
        for r in m["operating_points"]:
            rows.append({"task": m["task"], "detector": m["detector"], "seed": m["seed"],
                         **{k: v for k, v in r.items() if k != "per_class_f1"}})
    path = root / "operating_points_val.csv" if smoke else REPO_ROOT / "reports" / "tables" / "wp3_operating_points_val.csv"
    with open(path, "w", newline="", encoding="utf-8") as fh:
        wr = csv.DictWriter(fh, fieldnames=list(rows[0]))
        wr.writeheader()
        wr.writerows(rows)


if __name__ == "__main__":
    sys.exit(main())
