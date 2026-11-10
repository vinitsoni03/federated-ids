"""Milestone 4: centralized MLP (several seeds) and Random Forest baseline on the fixed split.

Usage:
    python -m federated_ids.experiments.centralized [--config configs/centralized.yaml]
        [--task category] [--feature-set window_invariant] [--seeds 0 1 2] [--run-name NAME]
        [--no-rf] [--no-full-test]
Outputs go to artifacts/runs/<run-name>/.
"""
from __future__ import annotations

import argparse
import csv
import sys
import time

import numpy as np
import torch

from federated_ids.config import data_config, load_yaml
from federated_ids.data.ciciot import FEATURES
from federated_ids.data.dataset import benign_index, load_split, split_manifest, task_labels
from federated_ids.data.preprocess import Preprocessor, select_features
from federated_ids.evaluation.full_test import predict_full_test
from federated_ids.evaluation.metrics import classification_metrics, summary_row
from federated_ids.experiments.common import environment, evaluate_bundle, peak_rss_mb, run_dir, write_json
from federated_ids.models.mlp import MLP, as_tensor, class_weights, predict_proba, resolve_device, set_seed, train_epochs


def prepare(cfg: dict, dcfg: dict):
    features = select_features(FEATURES, dcfg["features"]["window_dependent"], cfg["feature_set"])
    tr = load_split("train", features, cfg["task"], dcfg)
    va = load_split("val", features, cfg["task"], dcfg)
    te = load_split("test", features, cfg["task"], dcfg)
    pre = Preprocessor(features).fit(tr.X)  # fitted on TRAIN only
    data = {"train": {"Xp": pre.transform(tr.X), "y": tr.y, "y34": tr.y34},
            "val": {"Xp": pre.transform(va.X), "y": va.y, "seen": va.seen_in_train, "y34": va.y34},
            "test": {"Xp": pre.transform(te.X), "y": te.y, "seen": te.seen_in_train, "y34": te.y34}}
    return features, pre, data


def train_mlp(cfg: dict, data: dict, n_classes: int, seed: int, class_names, benign, log, device=None):
    device = device or resolve_device(cfg.get("device", "auto"))
    set_seed(seed)
    model = MLP(data["train"]["Xp"].shape[1], n_classes, cfg["model"]["hidden"], cfg["model"]["dropout"]).to(device)
    w = class_weights(data["train"]["y"], n_classes, cfg["train"]["class_weighting"])
    Xtr = as_tensor(data["train"]["Xp"], device)  # moved to the device once
    best, best_state, bad, hist = -1.0, None, 0, []
    t0 = time.time()
    for ep in range(cfg["train"]["epochs"]):
        loss = train_epochs(model, Xtr, data["train"]["y"], w, 1, cfg["train"]["lr"],
                            cfg["train"]["batch_size"], seed * 1000 + ep)
        pv = predict_proba(model, data["val"]["Xp"]).argmax(1)
        mv = classification_metrics(data["val"]["y"], pv, class_names, benign)
        hist.append({"epoch": ep + 1, "train_loss": loss, "val_macro_f1": mv["macro_f1"],
                     "val_benign_fpr": mv.get("benign_fpr"), "elapsed_s": round(time.time() - t0, 1)})
        log(f"  seed {seed} epoch {ep + 1}: loss {loss:.4f} val macroF1 {mv['macro_f1']:.4f}")
        if mv["macro_f1"] > best + 1e-4:
            best, bad = mv["macro_f1"], 0
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
        else:
            bad += 1
            if bad >= cfg["train"]["patience"]:
                break
    model.load_state_dict(best_state)
    return model, hist, time.time() - t0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", default="configs/centralized.yaml")
    ap.add_argument("--task")
    ap.add_argument("--feature-set")
    ap.add_argument("--seeds", nargs="*", type=int)
    ap.add_argument("--run-name")
    ap.add_argument("--no-rf", action="store_true")
    ap.add_argument("--no-full-test", action="store_true")
    ap.add_argument("--device", help="auto | cpu | cuda (default: config, else auto)")
    a = ap.parse_args(argv)
    cfg = load_yaml(a.config)
    if a.task:
        cfg["task"] = a.task
    if a.feature_set:
        cfg["feature_set"] = a.feature_set
    if a.seeds:
        cfg["seeds"] = a.seeds
    if a.no_rf:
        cfg["random_forest"]["enabled"] = False
    if a.no_full_test:
        cfg["full_test"] = False
    if a.device:
        cfg["device"] = a.device
    name = a.run_name or f"centralized_{cfg['task']}_{cfg['feature_set']}"
    out = run_dir(name)
    logf = open(out / "log.txt", "w", encoding="utf-8")

    def log(msg):
        print(msg, flush=True)
        logf.write(msg + "\n")
        logf.flush()

    torch.set_num_threads(6)
    device = resolve_device(cfg.get("device", "auto"))
    cfg["device_resolved"] = str(device)
    dcfg = data_config()
    man = split_manifest(dcfg)
    class_names = task_labels(cfg["task"])
    benign = benign_index(cfg["task"])
    features, pre, data = prepare(cfg, dcfg)
    pre.to_json(out / "preprocessor.json")
    write_json(out / "config.json", {"experiment": cfg, "data": dcfg, "features": features,
                                     "command": "python -m federated_ids.experiments.centralized " + " ".join(argv or sys.argv[1:])})
    write_json(out / "environment.json", environment())
    log(f"device {device}")
    log(f"run {name}: train {len(data['train']['y'])} val {len(data['val']['y'])} test {len(data['test']['y'])}, "
        f"{len(features)} features")
    rows = []
    for seed in cfg["seeds"]:
        model, hist, train_s = train_mlp(cfg, data, len(class_names), seed, class_names, benign, log, device)
        torch.save(model.state_dict(), out / f"mlp_seed{seed}.pt")
        with open(out / f"history_seed{seed}.csv", "w", newline="", encoding="utf-8") as fh:
            wr = csv.DictWriter(fh, fieldnames=list(hist[0]))
            wr.writeheader()
            wr.writerows(hist)
        res = evaluate_bundle(lambda X: predict_proba(model, X), {k: data[k] for k in ("val", "test")},
                              class_names, benign)
        res["train_seconds"] = round(train_s, 1)
        res["epochs_run"] = len(hist)
        res["n_parameters"] = int(sum(p.numel() for p in model.parameters()))
        if cfg["full_test"] and seed == cfg["seeds"][0]:
            t = time.time()
            yt, yp = predict_full_test(dcfg, man, features, cfg["task"],
                                       lambda X: predict_proba(model, pre.transform(X)).argmax(1))
            res["test_full_pool"] = classification_metrics(yt, yp, class_names, benign)
            res["test_full_pool"]["seconds"] = round(time.time() - t, 1)
        res["peak_rss_mb"] = peak_rss_mb()
        write_json(out / f"metrics_mlp_seed{seed}.json", res)
        for split in [k for k in ("val", "test", "test_unseen", "test_full_pool") if k in res]:
            rows.append({"model": "mlp", "seed": seed, "split": split, **summary_row(res[split]),
                         "train_seconds": res["train_seconds"]})
        log(f"seed {seed}: test macroF1 {res['test']['macro_f1']:.4f} unseen {res['test_unseen']['macro_f1']:.4f}"
            f" FPR {res['test']['benign_fpr']:.4f} ({train_s:.0f}s)")

    rf_cfg = cfg["random_forest"]
    if rf_cfg["enabled"]:
        from sklearn.ensemble import RandomForestClassifier

        rf = RandomForestClassifier(n_estimators=rf_cfg["n_estimators"], max_depth=rf_cfg["max_depth"],
                                    min_samples_leaf=rf_cfg["min_samples_leaf"], class_weight=rf_cfg["class_weight"],
                                    n_jobs=rf_cfg["n_jobs"], random_state=rf_cfg["seed"])
        t = time.time()
        rf.fit(data["train"]["Xp"], data["train"]["y"])
        train_s = time.time() - t

        def rf_proba(X):
            p = np.zeros((len(X), len(class_names)))
            p[:, rf.classes_] = rf.predict_proba(X)
            return p

        res = evaluate_bundle(rf_proba, {k: data[k] for k in ("val", "test")}, class_names, benign)
        res["train_seconds"] = round(train_s, 1)
        res["feature_importance"] = dict(sorted(zip(features, rf.feature_importances_.tolist()),
                                                key=lambda kv: -kv[1]))
        if cfg["full_test"]:
            t = time.time()
            yt, yp = predict_full_test(dcfg, man, features, cfg["task"],
                                       lambda X: rf_proba(pre.transform(X)).argmax(1))
            res["test_full_pool"] = classification_metrics(yt, yp, class_names, benign)
            res["test_full_pool"]["seconds"] = round(time.time() - t, 1)
        res["peak_rss_mb"] = peak_rss_mb()
        write_json(out / "metrics_rf.json", res)
        for split in [k for k in ("val", "test", "test_unseen", "test_full_pool") if k in res]:
            rows.append({"model": "random_forest", "seed": rf_cfg["seed"], "split": split,
                         **summary_row(res[split]), "train_seconds": res["train_seconds"]})
        log(f"RF: test macroF1 {res['test']['macro_f1']:.4f} unseen {res['test_unseen']['macro_f1']:.4f} ({train_s:.0f}s)")

    with open(out / "summary.csv", "w", newline="", encoding="utf-8") as fh:
        wr = csv.DictWriter(fh, fieldnames=list(rows[0]))
        wr.writeheader()
        wr.writerows(rows)
    log(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
