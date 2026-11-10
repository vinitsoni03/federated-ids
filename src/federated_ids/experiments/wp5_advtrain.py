"""WP5: adversarial training against the M7 constrained evasion attacker, evaluated at fixed benign FPR.

Threat model unchanged (reports/threat_models.md §C, federated_ids.attacks.evasion): black-box
label-only queries; the attacker pads its own packets, slows them down and sets a benign-typical
TTL; grid <= 112 queries per window; budgets r_min in {1, 0.5, 0.25, 0.1}.

Defended models (WP3 frozen detectors): v2 MLP (seeds 0-2) and HistGradientBoosting (seed 0).
Adversarial training, per round k = 1..R:
  1. Attack the current model (round 0 = frozen v2 model) on a fixed sample of TRAIN attack windows,
     at the model's 1 %-FPR decision rule (threshold fitted on clean validation), loosest budget.
  2. Add every successful adversarial window, with its TRUE label, to a cumulative pool.
  3. Retrain from scratch on clean train + pool (same architecture/hyperparameters; MLP early
     stopping on clean validation). The preprocessor stays the one fitted on clean train.
Evaluation of every round's model (round 0 = undefended):
  * clean test metrics at argmax and at val-calibrated 5 % / 1 % benign FPR (cost of the defence);
  * evasion on ONE fixed test sample (<= per_family attack windows per family, seed 0, identical for all
    models) at each operating point: the attacker re-runs its search against that model (adaptive).
    evasion_rate = evaded / detected; robust_detection = detected and not evaded / all sampled windows.
    Successful adversarial windows are re-checked against the constraints and re-queried (as in M7).
Nothing is selected on test: every round is reported.

Usage:
    python -m federated_ids.experiments.wp5_advtrain [--tasks category class34 binary]
        [--models mlp hgb] [--rounds 2] [--train-per-family 20000] [--test-per-family 3000] [--device cuda]
Outputs: artifacts/runs/wp5_advtrain/<task>/ (models, adversarial pools, eval_*.json)
         reports/tables/wp5_evasion.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import time

import numpy as np
import torch

from federated_ids.attacks.evasion import SLOWDOWN, apply_perturbation, check_constraints, evade
from federated_ids.config import REPO_ROOT, data_config
from federated_ids.data.ciciot import CATEGORIES, family_of_class34
from federated_ids.data.dataset import benign_index, load_split, task_labels
from federated_ids.data.preprocess import Preprocessor
from federated_ids.evaluation.calibration import (attack_score, operating_points, predict_with_threshold,
                                                  threshold_for_fpr)
from federated_ids.experiments.centralized import train_mlp
from federated_ids.experiments.common import run_dir, write_json
from federated_ids.experiments.wp3_detectors import TARGETS, load_mlp
from federated_ids.models.mlp import predict_proba, resolve_device

RUN_NAME = "wp5_advtrain"
R_MIN = min(SLOWDOWN)
BUDGETS = sorted(SLOWDOWN, reverse=True)  # 1.0, 0.5, 0.25, 0.1
OPS = ["argmax"] + [f"fpr{t * 100:g}" for t in TARGETS]
GEN_OP = "fpr1"  # decision rule attacked when generating training examples
HGB_PARAMS = {"max_iter": 300, "learning_rate": 0.1, "max_leaf_nodes": 31, "early_stopping": True,
              "validation_fraction": 0.1, "n_iter_no_change": 10, "class_weight": "balanced", "random_state": 0}


def evasion_by_budget(detected: np.ndarray, evaded: np.ndarray, chosen_r: np.ndarray, budgets=BUDGETS) -> dict:
    """The attacker's grid tries larger r (less slow-down) first, so a window evaded with chosen r is
    also evaded under every budget r_min <= r. Returns per-budget evasion rate (among detected) and
    robust detection (detected and not evaded, among all windows)."""
    out = {}
    n, nd = len(detected), int(detected.sum())
    for b in budgets:
        ev = evaded & detected & (chosen_r >= b - 1e-12)
        out[str(b)] = {"evasion_rate": float(ev.sum() / nd) if nd else None,
                       "robust_detection": float((detected & ~ev).sum() / n) if n else None}
    return out


def rebuild(X: np.ndarray, chosen: np.ndarray, features: list[str]) -> np.ndarray:
    """Re-apply each row's chosen (r, p, ttl) perturbation; vectorised per unique setting."""
    Z = np.empty((len(X), X.shape[1]))
    keys = np.nan_to_num(chosen, nan=-1.0)
    for k in np.unique(keys, axis=0):
        m = (keys == k).all(1)
        r, pad, ttl = k
        Z[m] = apply_perturbation(X[m], features, pad, r, None if ttl == -1.0 else ttl)
    return Z


def sample_per_family(fam: np.ndarray, mask: np.ndarray, k: int, rng) -> np.ndarray:
    idx = []
    for c in CATEGORIES:
        if c == "Benign":
            continue
        i = np.flatnonzero((fam == c) & mask)
        idx.append(np.sort(rng.choice(i, k, replace=False)) if i.size > k else i)
    return np.concatenate(idx)


class Detector:
    """A model + preprocessor + val-calibrated thresholds; decides on RAW feature rows."""

    def __init__(self, proba_fn, pre: Preprocessor, Xva_p, yva, benign):
        self.proba_fn, self.pre, self.benign = proba_fn, pre, benign
        pv = proba_fn(Xva_p)
        self.th = {f"fpr{t * 100:g}": threshold_for_fpr(attack_score(pv, benign), yva == benign, t) for t in TARGETS}

    def decide(self, op: str):
        if op == "argmax":
            return lambda Z: self.proba_fn(self.pre.transform(Z)).argmax(1)
        t = self.th[op]
        return lambda Z: predict_with_threshold(self.proba_fn(self.pre.transform(Z)), self.benign, t)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--tasks", nargs="*", default=["category", "class34", "binary"])
    ap.add_argument("--models", nargs="*", default=["mlp", "hgb"], choices=["mlp", "hgb"])
    ap.add_argument("--seeds", nargs="*", type=int, default=[0, 1, 2], help="MLP seeds (HGB: seed 0 only)")
    ap.add_argument("--rounds", type=int, default=2)
    ap.add_argument("--train-per-family", type=int, default=20000)
    ap.add_argument("--test-per-family", type=int, default=3000)
    ap.add_argument("--device", default="cuda")
    ap.add_argument("--run-name", default=RUN_NAME, help="output dir under artifacts/runs (smoke tests)")
    a = ap.parse_args(argv)
    device = resolve_device(a.device)
    torch.set_num_threads(6)
    dcfg = data_config()
    root = run_dir(a.run_name)
    logf = open(root / "log.txt", "a", encoding="utf-8")

    def log(msg):
        print(msg, flush=True)
        logf.write(msg + "\n")
        logf.flush()

    log(f"=== start {time.strftime('%Y-%m-%d %H:%M:%S')} {vars(a)}")
    for task in a.tasks:
        out = root / task
        out.mkdir(exist_ok=True)
        v2dir = REPO_ROOT / "artifacts" / "runs" / "centralized_v2" / task
        v2 = json.loads((v2dir / "config.json").read_text(encoding="utf-8"))
        features = v2["features"]
        pre = Preprocessor.from_json(v2dir / "preprocessor.json")
        names, benign = task_labels(task), benign_index(task)
        tr, va, te = (load_split(s, features, task, dcfg) for s in ("train", "val", "test"))
        Xtr_p, Xva_p, Xte_p = pre.transform(tr.X), pre.transform(va.X), pre.transform(te.X)
        ttl_col = features.index("Time_To_Live")
        ttl_choices = [None] + [float(np.nanquantile(tr.X[tr.y == benign, ttl_col], q)) for q in (0.1, 0.5, 0.9)]
        fam_tr, fam_te = family_of_class34(tr.y34), family_of_class34(te.y34)
        gen_idx = sample_per_family(fam_tr, tr.y != benign, a.train_per_family, np.random.default_rng(0))
        test_idx = sample_per_family(fam_te, te.y != benign, a.test_per_family, np.random.default_rng(0))
        np.save(out / "test_sample_idx.npy", test_idx)
        log(f"[{task}] train attack sample {len(gen_idx)}, test attack sample {len(test_idx)}, TTL choices {ttl_choices}")
        mcfg = v2["mlp"]
        run_cfg = {"model": {"hidden": mcfg["hidden"], "dropout": mcfg["dropout"]},
                   "train": {"epochs": 50, "batch_size": 512, "patience": 5, "lr": mcfg["lr"],
                             "class_weighting": mcfg["class_weighting"]}}

        def evaluate(det: Detector, tag: str, extra: dict):
            path = out / f"eval_{tag}.json"
            if path.exists():
                return
            pt = det.proba_fn(Xte_p)
            res = {"task": task, **extra, "thresholds": det.th,
                   "clean_test": operating_points(pt, te.y, names, benign, TARGETS, det.th),
                   "clean_val": operating_points(det.proba_fn(Xva_p), va.y, names, benign, TARGETS, det.th),
                   "evasion": {}}
            X0, f0 = te.X[test_idx], fam_te[test_idx]
            for op in OPS:
                decide = det.decide(op)
                detected = decide(X0) != benign
                e = evade(decide, X0[detected], features, benign, ttl_choices, R_MIN)
                evaded = np.zeros(len(X0), bool)
                chosen_r = np.full(len(X0), np.nan)
                evaded[detected], chosen_r[detected] = e["evaded"], e["chosen"][:, 0]
                viol = {}
                if e["evaded"].any():  # constraint audit + re-query, as in M7
                    Xd, ch = X0[detected][e["evaded"]], e["chosen"][e["evaded"]]
                    Zs = rebuild(Xd, ch, features)
                    viol = check_constraints(Xd, Zs, features, R_MIN)
                    assert sum(viol.values()) == 0, viol
                    assert (decide(Zs) == benign).all()
                per_family = {}
                for c in sorted(set(f0)):
                    m = f0 == c
                    per_family[c] = {"n": int(m.sum()), "detected": float(detected[m].mean()),
                                     **evasion_by_budget(detected[m], evaded[m], chosen_r[m])}
                res["evasion"][op] = {"n": len(X0), "detected": float(detected.mean()),
                                      "by_budget": evasion_by_budget(detected, evaded, chosen_r),
                                      "per_family": per_family, "constraint_violations": viol,
                                      "mean_queries": float(e["queries"].mean()) if len(e["queries"]) else None}
            write_json(path, res)
            ct = {r["operating_point"]: r for r in res["clean_test"]}
            log(f"[{task}] {tag}: clean 1% det {ct['fpr1']['attack_detection_rate']:.4f} FPR {ct['fpr1']['benign_fpr']:.4f} F1 "
                f"{ct['argmax']['macro_f1']:.4f} | evasion@0.1 " + " ".join(
                    f"{op} {res['evasion'][op]['by_budget']['0.1']['evasion_rate']:.3f}" for op in OPS)
                + f" | robust@0.1 fpr1 {res['evasion']['fpr1']['by_budget']['0.1']['robust_detection']:.3f}")

        def generate(det: Detector, pool_path):
            """Attack the detector's 1 %-FPR rule on the train sample; returns successful windows (raw) + true labels."""
            if pool_path.exists():
                d = np.load(pool_path)
                return d["Z"], d["y"]
            decide = det.decide(GEN_OP)
            X0 = tr.X[gen_idx]
            detected = decide(X0) != benign
            e = evade(decide, X0[detected], features, benign, ttl_choices, R_MIN)
            Xd, yd, ch = X0[detected][e["evaded"]], tr.y[gen_idx][detected][e["evaded"]], e["chosen"][e["evaded"]]
            Z = rebuild(Xd, ch, features) if len(Xd) else np.empty((0, len(features)))
            np.savez_compressed(pool_path, Z=Z, y=yd)
            log(f"[{task}] {pool_path.stem}: {len(Z)} new adversarial train windows "
                f"({detected.sum()} detected of {len(X0)}, {e['evaded'].mean() if detected.any() else 0:.3f} evaded)")
            return Z, yd

        jobs = []
        if "mlp" in a.models:
            jobs += [("mlp", s) for s in a.seeds]
        if "hgb" in a.models:
            jobs += [("hgb", 0)]
        for kind, seed in jobs:
            tag0 = f"{kind}_s{seed}"
            if kind == "mlp":
                def build(path, kind=kind, seed=seed):
                    m = load_mlp(path, Xtr_p.shape[1], len(names), mcfg["hidden"], mcfg["dropout"], device)
                    return lambda X: predict_proba(m, X)
                proba_fn = build(v2dir / f"mlp_seed{seed}.pt")
            else:
                import joblib
                def tree_fn(model):
                    def f(X):
                        p = np.zeros((len(X), len(names)))
                        p[:, model.classes_] = model.predict_proba(X)
                        return p
                    return f
                proba_fn = tree_fn(joblib.load(v2dir / "hgb_s0.joblib"))
            det = Detector(proba_fn, pre, Xva_p, va.y, benign)
            evaluate(det, f"{tag0}_r0", {"model": kind, "seed": seed, "round": 0, "pool_size": 0})
            pool_Z, pool_y = np.empty((0, len(features))), np.empty(0, dtype=np.int64)
            for rnd in range(1, a.rounds + 1):
                Z, yz = generate(det, out / f"pool_{tag0}_r{rnd}.npz")
                pool_Z, pool_y = np.vstack([pool_Z, Z]), np.concatenate([pool_y, yz])
                Xa, ya = np.vstack([Xtr_p, pre.transform(pool_Z)]), np.concatenate([tr.y, pool_y])
                t = time.time()
                if kind == "mlp":
                    mpath = out / f"mlp_s{seed}_r{rnd}.pt"
                    if not mpath.exists():
                        model, hist, _ = train_mlp(run_cfg, {"train": {"Xp": Xa, "y": ya}, "val": {"Xp": Xva_p, "y": va.y}},
                                                   len(names), seed, names, benign, lambda m: None, device)
                        torch.save(model.state_dict(), mpath)
                    proba_fn = build(mpath)
                else:
                    import joblib
                    from sklearn.ensemble import HistGradientBoostingClassifier
                    mpath = out / f"hgb_s0_r{rnd}.joblib"
                    if not mpath.exists():
                        joblib.dump(HistGradientBoostingClassifier(**HGB_PARAMS).fit(Xa, ya), mpath)
                    proba_fn = tree_fn(joblib.load(mpath))
                log(f"[{task}] {tag0} round {rnd}: trained on {len(ya)} rows (pool {len(pool_y)}) in {time.time() - t:.0f}s")
                det = Detector(proba_fn, pre, Xva_p, va.y, benign)
                evaluate(det, f"{tag0}_r{rnd}", {"model": kind, "seed": seed, "round": rnd, "pool_size": int(len(pool_y))})
    write_table(root, a.run_name != RUN_NAME)
    log(f"=== done {time.strftime('%Y-%m-%d %H:%M:%S')}")
    return 0


def write_table(root, smoke=False) -> None:
    rows = []
    for f in sorted(root.glob("*/eval_*.json")):
        m = json.loads(f.read_text(encoding="utf-8"))
        ct = {r["operating_point"]: r for r in m["clean_test"]}
        for op in OPS:
            ev = m["evasion"][op]
            rows.append({"task": m["task"], "model": m["model"], "seed": m["seed"], "round": m["round"],
                         "pool_size": m["pool_size"], "operating_point": op, "threshold": m["thresholds"].get(op),
                         "clean_test_macro_f1": ct[op]["macro_f1"], "clean_test_benign_fpr": ct[op]["benign_fpr"],
                         "clean_test_detection": ct[op]["attack_detection_rate"], "sample_detected": ev["detected"],
                         **{f"evasion_r{b}": ev["by_budget"][str(b)]["evasion_rate"] for b in BUDGETS},
                         **{f"robust_det_r{b}": ev["by_budget"][str(b)]["robust_detection"] for b in BUDGETS}})
    path = root / "wp5_evasion.csv" if smoke else REPO_ROOT / "reports" / "tables" / "wp5_evasion.csv"
    with open(path, "w", newline="", encoding="utf-8") as fh:
        wr = csv.DictWriter(fh, fieldnames=list(rows[0]))
        wr.writeheader()
        wr.writerows(rows)


if __name__ == "__main__":
    sys.exit(main())
