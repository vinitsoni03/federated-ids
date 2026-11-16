"""Operating-point sensitivity: detection and evasion at benign FPR targets of 0.5, 1, 2, 3, 5 and 10 %.

    python scripts/fpr_sweep.py [--device cuda] [--no-evasion]

The 1 % (and 5 %) operating points were fixed in the project plan before any test run; this script is a
post-hoc sensitivity analysis and changes no choice. For every target, the threshold is fitted on
VALIDATION benign windows (evaluation/calibration.py) and applied unchanged to test, exactly as in WP3.
Detectors: the frozen v2 MLP (seeds 0-2) and HGB from artifacts/runs/centralized_v2/<task>/.
Evasion (8-class only): the WP5 attacker (same grid, same fixed test sample, r >= 0.1) against the
frozen v2 MLP seed 0, HGB and the adversarially trained MLP (WP5 round 2), at each target.

Writes reports/tables/fpr_sweep.csv, fpr_sweep_evasion.csv and reports/figures/fpr_sweep.png.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from federated_ids.attacks.evasion import SLOWDOWN, evade  # noqa: E402
from federated_ids.config import data_config  # noqa: E402
from federated_ids.data.dataset import benign_index, load_split, task_labels  # noqa: E402
from federated_ids.data.preprocess import Preprocessor  # noqa: E402
from federated_ids.evaluation.calibration import attack_score, predict_with_threshold, threshold_for_fpr  # noqa: E402
from federated_ids.evaluation.metrics import classification_metrics  # noqa: E402
from federated_ids.experiments.wp3_detectors import load_mlp  # noqa: E402
from federated_ids.models.mlp import predict_proba, resolve_device  # noqa: E402

TARGETS = [0.005, 0.01, 0.02, 0.03, 0.05, 0.10]
EVASION_TARGETS = [0.01, 0.02, 0.03, 0.05]
RUNS = ROOT / "artifacts" / "runs"
TABLES, FIGS = ROOT / "reports" / "tables", ROOT / "reports" / "figures"


def tree_proba(model, n_cls):
    # trees only know the classes they saw; place their probabilities in the right columns
    def f(X):
        p = np.zeros((len(X), n_cls))
        p[:, model.classes_] = model.predict_proba(X)
        return p
    return f


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--device", default="cuda")
    ap.add_argument("--no-evasion", action="store_true")
    ap.add_argument("--plot-only", action="store_true", help="redraw the figure from the saved tables")
    a = ap.parse_args()
    if a.plot_only:
        plot(pd.read_csv(TABLES / "fpr_sweep.csv"), pd.read_csv(TABLES / "fpr_sweep_evasion.csv"))
        return 0
    import joblib

    device = resolve_device(a.device)
    torch.set_num_threads(6)
    dcfg = data_config()
    rows, ev_rows = [], []
    for task in ("category", "class34", "binary"):
        v2dir = RUNS / "centralized_v2" / task
        cfg = json.loads((v2dir / "config.json").read_text(encoding="utf-8"))
        features, mc = cfg["features"], cfg["mlp"]
        pre = Preprocessor.from_json(v2dir / "preprocessor.json")
        names, benign = task_labels(task), benign_index(task)
        va, te = load_split("val", features, task, dcfg), load_split("test", features, task, dcfg)
        Xva, Xte = pre.transform(va.X), pre.transform(te.X)
        models = {f"v2_mlp_s{s}": (lambda m: (lambda X: predict_proba(m, X)))(
                      load_mlp(v2dir / f"mlp_seed{s}.pt", Xva.shape[1], len(names), mc["hidden"], mc["dropout"], device))
                  for s in (0, 1, 2)}
        models["hgb"] = tree_proba(joblib.load(v2dir / "hgb_s0.joblib"), len(names))
        for name, fn in models.items():
            pv, pt = fn(Xva), fn(Xte)
            for tgt in TARGETS:
                # fit on validation benign, apply unchanged to test
                t = threshold_for_fpr(attack_score(pv, benign), va.y == benign, tgt)
                m = classification_metrics(te.y, predict_with_threshold(pt, benign, t), names, benign)
                rows.append({"task": task, "detector": name, "target_fpr": tgt, "threshold": t,
                             "test_benign_fpr": m["benign_fpr"], "test_detection": m["attack_detection_rate"],
                             "test_macro_f1": m["macro_f1"]})
            print(f"[{task}] {name}: " + " ".join(f"{r['target_fpr']:.3f}->{r['test_detection']:.3f}"
                                                  for r in rows if r["task"] == task and r["detector"] == name), flush=True)

        if task != "category" or a.no_evasion:
            continue
        # evasion at each target, same attacker and test sample as WP5
        wp5 = RUNS / "wp5_advtrain" / task
        idx = np.load(wp5 / "test_sample_idx.npy")
        tr = load_split("train", features, task, dcfg)
        ttl_col = features.index("Time_To_Live")
        ttl = [None] + [float(np.nanquantile(tr.X[tr.y == benign, ttl_col], q)) for q in (0.1, 0.5, 0.9)]
        del tr
        X0 = te.X[idx]
        hard = load_mlp(wp5 / "mlp_s0_r2.pt", Xva.shape[1], len(names), mc["hidden"], mc["dropout"], device)
        targets = {"v2_mlp_s0": models["v2_mlp_s0"], "hgb": models["hgb"],
                   "v2_mlp_s0_advtrained": lambda X: predict_proba(hard, X)}
        for name, fn in targets.items():
            pv = fn(Xva)
            for tgt in EVASION_TARGETS:
                t = threshold_for_fpr(attack_score(pv, benign), va.y == benign, tgt)
                decide = lambda Z, t=t, fn=fn: predict_with_threshold(fn(pre.transform(Z)), benign, t)  # noqa: E731
                det = decide(X0) != benign
                e = evade(decide, X0[det], features, benign, ttl, min(SLOWDOWN))
                ev_rows.append({"task": task, "detector": name, "target_fpr": tgt, "sample": len(X0),
                                "detected": float(det.mean()), "evasion_rate": float(e["evaded"].mean()),
                                "robust_detection": float((det.sum() - e["evaded"].sum()) / len(X0))})
                print(f"[evasion] {name} @ {tgt:.2f}: detected {det.mean():.3f} evaded {e['evaded'].mean():.3f}", flush=True)

    df = pd.DataFrame(rows)
    df.to_csv(TABLES / "fpr_sweep.csv", index=False)
    if ev_rows:
        pd.DataFrame(ev_rows).to_csv(TABLES / "fpr_sweep_evasion.csv", index=False)
    plot(df, pd.DataFrame(ev_rows))
    return 0


def plot(df: pd.DataFrame, ev: pd.DataFrame) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(1, 2 if len(ev) else 1, figsize=(11 if len(ev) else 5.5, 3.8), squeeze=False)
    ax = axes[0][0]
    d = df.assign(model=df.detector.str.replace(r"_s\d$", "", regex=True))
    g = d.groupby(["task", "model", "target_fpr"], as_index=False)[["test_benign_fpr", "test_detection"]].mean()
    style = {"category": "-", "class34": "--", "binary": ":"}
    color = {"v2_mlp": "#2a63d6", "hgb": "#1d9a6c"}
    for (task, model), s in g.groupby(["task", "model"]):
        ax.plot(100 * s.test_benign_fpr, 100 * s.test_detection, style[task], color=color[model], marker="o", ms=3,
                label=f"{'MLP' if model == 'v2_mlp' else 'HGB'}, {dict(category='8-class', class34='34-class', binary='binary')[task]}")
    ax.axvline(1, color="#999", lw=1, ls="--")
    ax.set_xlabel("benign FPR on test (%)"); ax.set_ylabel("attack detection on test (%)")
    ax.set_title("Detection vs false alarms"); ax.grid(alpha=.3); ax.legend(fontsize=7)
    if len(ev):
        ax = axes[0][1]
        lab = {"v2_mlp_s0": "v2 MLP", "hgb": "HGB", "v2_mlp_s0_advtrained": "v2 MLP, adv. trained"}
        col = {"v2_mlp_s0": color["v2_mlp"], "hgb": color["hgb"], "v2_mlp_s0_advtrained": "#7a52c7"}
        for name, s in ev.groupby("detector"):
            ax.plot(100 * s.target_fpr, 100 * s.evasion_rate, marker="o", color=col[name], label=lab[name])
        ax.set_xlabel("target benign FPR (%)"); ax.set_ylabel("evasion rate (%)")
        ax.set_title("Evasion vs operating point (8-class)"); ax.grid(alpha=.3); ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(FIGS / "fpr_sweep.png", dpi=160)


if __name__ == "__main__":
    sys.exit(main())
