"""Run the constrained black-box evasion experiment (Milestone 7) against the centralized
MLP (seed 0 of the baseline run) and a Random Forest trained with the baseline config.

Usage:
    python -m federated_ids.experiments.evasion_exp [--baseline-run centralized_category_window_invariant]
        [--per-class 3000] [--seed 0]
"""
from __future__ import annotations

import argparse
import csv
import sys
import time

import numpy as np
import torch

from federated_ids.attacks.evasion import apply_perturbation, check_constraints, evade
from federated_ids.config import REPO_ROOT, data_config, load_yaml
from federated_ids.data.ciciot import CATEGORIES, family_of_class34
from federated_ids.data.dataset import benign_index, load_split, task_labels
from federated_ids.data.preprocess import Preprocessor
from federated_ids.experiments.common import run_dir, write_json
from federated_ids.models.mlp import MLP, predict_proba


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--baseline-run", default="centralized_category_window_invariant")
    ap.add_argument("--per-class", type=int, default=3000)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--budgets", nargs="*", type=float, default=[1.0, 0.5, 0.25, 0.1])
    a = ap.parse_args(argv)
    torch.set_num_threads(6)
    base = REPO_ROOT / "artifacts" / "runs" / a.baseline_run
    bcfg = load_yaml(base / "config.json")  # JSON is valid YAML
    cfg, features = bcfg["experiment"], bcfg["features"]
    pre = Preprocessor.from_json(base / "preprocessor.json")
    names = task_labels(cfg["task"])
    benign = benign_index(cfg["task"])
    dcfg = data_config()
    tr = load_split("train", features, cfg["task"], dcfg)
    te = load_split("test", features, cfg["task"], dcfg)

    mlp = MLP(len(features), len(names), cfg["model"]["hidden"], cfg["model"]["dropout"])
    mlp.load_state_dict(torch.load(base / f"mlp_seed{cfg['seeds'][0]}.pt", map_location="cpu"))
    from sklearn.ensemble import RandomForestClassifier

    rfc = cfg["random_forest"]
    rf = RandomForestClassifier(n_estimators=rfc["n_estimators"], max_depth=rfc["max_depth"],
                                min_samples_leaf=rfc["min_samples_leaf"], class_weight=rfc["class_weight"],
                                n_jobs=rfc["n_jobs"], random_state=rfc["seed"]).fit(pre.transform(tr.X), tr.y)
    targets = {"mlp": lambda Z: predict_proba(mlp, pre.transform(Z)).argmax(1),
               "random_forest": lambda Z: rf.classes_[rf.predict_proba(pre.transform(Z)).argmax(1)]}

    ttl_col = features.index("Time_To_Live")
    ben_ttl = tr.X[tr.y == benign, ttl_col]
    ttl_q = [float(np.nanquantile(ben_ttl, q)) for q in (0.1, 0.5, 0.9)]
    ttl_choices = [None] + ttl_q
    rng = np.random.default_rng(a.seed)
    out = run_dir("evasion_" + a.baseline_run)
    results = {"threat_model": "black-box label-only; padding/slow-down/TTL on attacker's own packets",
               "ttl_choices_benign_train_quantiles_10_50_90": ttl_q, "per_class_sample": a.per_class, "targets": {}}
    rows = []
    for tname, predict in targets.items():
        t0 = time.time()
        clean_pred = predict(te.X)
        res_t = {"task": cfg["task"], "clean_benign_fpr": float((clean_pred[te.y == benign] != benign).mean()), "budgets": {}}
        # attack windows the IDS currently detects (predicted as some attack class), grouped by
        # attack FAMILY so results are comparable across the 8-class, 34-class and binary tasks
        fam = family_of_class34(te.y34)
        pool = {}
        for cname in CATEGORIES:
            if cname == "Benign":
                continue
            idx = np.flatnonzero((fam == cname) & (clean_pred != benign))
            if idx.size > a.per_class:
                idx = np.sort(rng.choice(idx, a.per_class, replace=False))
            pool[cname] = idx
            res_t.setdefault("clean_detection_rate", {})[cname] = float((clean_pred[fam == cname] != benign).mean())
        for r_min in a.budgets:
            per = {}
            for cname, idx in pool.items():
                X0 = te.X[idx]
                e = evade(predict, X0, features, benign, ttl_choices, r_min)
                # constraint audit on the successful adversarial windows
                ok = e["evaded"]
                viol = {}
                if ok.any():
                    Zs = np.vstack([apply_perturbation(X0[i:i + 1], features, e["chosen"][i, 1], e["chosen"][i, 0],
                                                       None if np.isnan(e["chosen"][i, 2]) else e["chosen"][i, 2])
                                    for i in np.flatnonzero(ok)])
                    viol = check_constraints(X0[ok], Zs, features, r_min)
                    assert sum(viol.values()) == 0, viol
                    # re-query: adversarial windows really are predicted Benign
                    assert (predict(Zs) == benign).all()
                per[cname] = {"n": int(idx.size), "evasion_rate": float(ok.mean()) if idx.size else None,
                              "mean_queries": float(e["queries"].mean()) if idx.size else None,
                              "chosen_slowdown_counts": {str(k): int((e["chosen"][ok, 0] == k).sum()) for k in (1.0, 0.5, 0.25, 0.1)},
                              "median_padding_bytes": float(np.median(e["chosen"][ok, 1])) if ok.any() else None,
                              "constraint_violations": viol}
                rows.append({"target": tname, "r_min": r_min, "class": cname, "n": per[cname]["n"],
                             "evasion_rate": per[cname]["evasion_rate"], "mean_queries": per[cname]["mean_queries"]})
            tot = sum(v["n"] for v in per.values())
            res_t["budgets"][str(r_min)] = {"per_class": per, "overall_evasion_rate":
                                            sum(v["evasion_rate"] * v["n"] for v in per.values() if v["n"]) / tot,
                                            "grid_size": len([r for r in (1.0, 0.5, 0.25, 0.1) if r >= r_min]) * 7 * len(ttl_choices)}
            print(f"{tname} r_min={r_min}: overall evasion {res_t['budgets'][str(r_min)]['overall_evasion_rate']:.3f} "
                  + " ".join(f"{k}:{v['evasion_rate']:.2f}" for k, v in per.items()), flush=True)
        # knob ablation at the loosest budget
        ab = {}
        for knob, kw in {"padding_only": dict(padding=[0, 50, 100, 200, 400, 800, 1450], slowdown=[1.0], tt=[None]),
                         "slowdown_only": dict(padding=[0], slowdown=[1.0, 0.5, 0.25, 0.1], tt=[None]),
                         "ttl_only": dict(padding=[0], slowdown=[1.0], tt=ttl_choices)}.items():
            per = {}
            for cname, idx in pool.items():
                e = evade(predict, te.X[idx], features, benign, kw["tt"], min(a.budgets), kw["padding"], kw["slowdown"])
                per[cname] = float(e["evaded"].mean()) if idx.size else None
            ab[knob] = per
        res_t["knob_ablation_at_loosest_budget"] = ab
        res_t["seconds"] = round(time.time() - t0, 1)
        results["targets"][tname] = res_t
    write_json(out / "metrics.json", results)
    with open(out / "evasion_rates.csv", "w", newline="", encoding="utf-8") as fh:
        wr = csv.DictWriter(fh, fieldnames=list(rows[0]))
        wr.writeheader()
        wr.writerows(rows)
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
