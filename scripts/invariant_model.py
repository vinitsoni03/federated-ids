"""Improved detector: attacker-invariant inputs (8-class).

    python scripts/invariant_model.py [--seeds 0 1 2] [--device cuda]

The evasion attacker (attacks/evasion.py) can only pad its packets (+p bytes on Min, Max, AVG, Tot size),
slow down (Rate * r, IAT / r) and set the TTL. This model replaces those 7 raw inputs with 3 that the
attacker cannot change: Max-Min and AVG-Min (the same p is added to both terms), and Rate*IAT (the r
cancels); the TTL is dropped. All other inputs are the same 26 window-invariant features as before, so the
model sees 29 features. Architecture, training recipe, early stopping and the 1 %/5 % validation thresholds
are exactly those of the frozen v2 MLP, so any difference comes from the inputs.

Evaluation: test detection at the 1 % rule (vs the frozen v2 MLP) and the WP5 attacker on the same fixed
test sample (r >= 0.1), where the attacker still perturbs the RAW traffic features.
Writes reports/tables/invariant_model.csv.
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
from federated_ids.config import data_config, load_yaml  # noqa: E402
from federated_ids.data import preprocess  # noqa: E402
from federated_ids.data.dataset import benign_index, load_split, task_labels  # noqa: E402
from federated_ids.evaluation.calibration import attack_score, predict_with_threshold, threshold_for_fpr  # noqa: E402
from federated_ids.evaluation.metrics import classification_metrics  # noqa: E402
from federated_ids.experiments.centralized import train_mlp  # noqa: E402
from federated_ids.models.mlp import predict_proba, resolve_device  # noqa: E402

TASK = "category"
RUNS = ROOT / "artifacts" / "runs"
CONTROLLED = ["Min", "Max", "AVG", "Tot size", "Rate", "IAT", "Time_To_Live"]
NEW = ["Max-Min", "AVG-Min", "Rate*IAT"]
# the new columns are heavy-tailed like the ones they replace, so they get the same signed log
preprocess.LOG_COLUMNS.update(NEW)


def invariant(X: np.ndarray, features: list[str]) -> tuple[np.ndarray, list[str]]:
    """Raw 33-feature rows -> 29 inputs that padding, slow-down and TTL changes leave unchanged."""
    c = {f: i for i, f in enumerate(features)}
    X = np.array(X, dtype=np.float64)
    with np.errstate(invalid="ignore", over="ignore"):
        extra = np.column_stack([X[:, c["Max"]] - X[:, c["Min"]], X[:, c["AVG"]] - X[:, c["Min"]],
                                 X[:, c["Rate"]] * X[:, c["IAT"]]])
    keep = [f for f in features if f not in CONTROLLED]
    return np.hstack([X[:, [c[f] for f in keep]], extra]), keep + NEW


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--seeds", nargs="*", type=int, default=[0])
    ap.add_argument("--device", default="cuda")
    a = ap.parse_args()
    device = resolve_device(a.device)
    torch.set_num_threads(6)
    dcfg = data_config()
    v2dir = RUNS / "centralized_v2" / TASK
    v2 = json.loads((v2dir / "config.json").read_text(encoding="utf-8"))
    raw_features = v2["features"]
    search = load_yaml(ROOT / "configs" / "hparam_search.yaml")
    run_cfg = {"model": {"hidden": v2["mlp"]["hidden"], "dropout": v2["mlp"]["dropout"]},
               "train": {**search["train"], "lr": v2["mlp"]["lr"], "class_weighting": v2["mlp"]["class_weighting"]}}
    names, benign = task_labels(TASK), benign_index(TASK)
    tr, va, te = (load_split(s, raw_features, TASK, dcfg) for s in ("train", "val", "test"))
    Xtr, feats = invariant(tr.X, raw_features)
    pre = preprocess.Preprocessor(feats).fit(Xtr)
    data = {"train": {"Xp": pre.transform(Xtr), "y": tr.y},
            "val": {"Xp": pre.transform(invariant(va.X, raw_features)[0]), "y": va.y}}
    Xte_p = pre.transform(invariant(te.X, raw_features)[0])
    print(f"invariant inputs: {len(feats)} features ({', '.join(NEW)} replace {', '.join(CONTROLLED)})", flush=True)

    # attacker setup identical to WP5: same fixed test sample, same TTL choices, r >= 0.1
    idx = np.load(RUNS / "wp5_advtrain" / TASK / "test_sample_idx.npy")
    ttl_col = raw_features.index("Time_To_Live")
    ttl = [None] + [float(np.nanquantile(tr.X[tr.y == benign, ttl_col], q)) for q in (0.1, 0.5, 0.9)]
    X0 = te.X[idx]

    rows = []
    out_dir = RUNS / "invariant_model" / TASK
    out_dir.mkdir(parents=True, exist_ok=True)
    pre.to_json(out_dir / "preprocessor.json")
    for seed in a.seeds:
        model, hist, secs = train_mlp(run_cfg, data, len(names), seed, names, benign, lambda m: None, device)
        torch.save(model.state_dict(), out_dir / f"mlp_seed{seed}.pt")
        pv = predict_proba(model, data["val"]["Xp"])
        pt = predict_proba(model, Xte_p)
        row = {"model": "invariant_mlp", "seed": seed, "train_s": round(secs, 1),
               "test_macro_f1_argmax": classification_metrics(te.y, pt.argmax(1), names, benign)["macro_f1"]}
        for tgt in (0.05, 0.01):
            t = threshold_for_fpr(attack_score(pv, benign), va.y == benign, tgt)
            m = classification_metrics(te.y, predict_with_threshold(pt, benign, t), names, benign)
            row[f"fpr{tgt * 100:g}_test_benign_fpr"] = m["benign_fpr"]
            row[f"fpr{tgt * 100:g}_test_detection"] = m["attack_detection_rate"]
            row[f"fpr{tgt * 100:g}_test_macro_f1"] = m["macro_f1"]
            if tgt == 0.01:
                # the attacker perturbs raw traffic; the model only ever sees the invariant inputs
                decide = lambda Z, t=t: predict_with_threshold(  # noqa: E731
                    predict_proba(model, pre.transform(invariant(Z, raw_features)[0])), benign, t)
                det = decide(X0) != benign
                e = evade(decide, X0[det], raw_features, benign, ttl, min(SLOWDOWN))
                row["sample_detected"] = float(det.mean())
                row["evasion_rate_fpr1"] = float(e["evaded"].mean())
        rows.append(row)
        print(json.dumps({k: (round(v, 4) if isinstance(v, float) else v) for k, v in row.items()}), flush=True)
    # keep earlier seeds in the table; replace only the seeds run now
    path = ROOT / "reports" / "tables" / "invariant_model.csv"
    new = pd.DataFrame(rows)
    if path.exists():
        old = pd.read_csv(path)
        new = pd.concat([old[~old.seed.isin(new.seed)], new]).sort_values("seed")
    new.to_csv(path, index=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
