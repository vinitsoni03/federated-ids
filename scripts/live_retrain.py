"""Real-traffic test, part 3: does adding local benign traffic to training fix the false alarms?

    python scripts/live_retrain.py [--features <features.csv>] [--factors 1 5] [--seeds 0 1 2] [--device cuda]

The capture's windows (features.csv from federated_ids.live.score) are split chronologically: the first
half is added to the CICIoT2023 training split as Benign (repeated `factor` times), the second half is
only scored. The 8-class v2 MLP (WP3 frozen config) is retrained from scratch per seed with exactly the
WP3 recipe: train-only preprocessor (the original one, fitted on CICIoT2023 train), early stopping on
CICIoT2023 validation macro-F1, 5 % / 1 % thresholds fitted on CICIoT2023 validation benign. The local
second half is never used for training, early stopping or thresholds.
Control: the frozen v2 models (artifacts/runs/centralized_v2/category/mlp_seed*.pt, same recipe without
local data).

Writes reports/tables/live_retrain.csv (one row per variant/seed), live_retrain_summary.csv (mean over
seeds); models go to <work_dir>/live/retrain/ (outside the repository). Aggregate numbers only.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
import torch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from federated_ids.config import data_config, load_yaml, work_dir  # noqa: E402
from federated_ids.data.dataset import benign_index, task_labels  # noqa: E402
from federated_ids.evaluation.calibration import attack_score, operating_points, predict_with_threshold, threshold_for_fpr  # noqa: E402
from federated_ids.experiments.centralized import prepare, train_mlp  # noqa: E402
from federated_ids.live.features import ALL_FEATURES  # noqa: E402
from federated_ids.live.score import service  # noqa: E402
from federated_ids.models.mlp import MLP, predict_proba, resolve_device  # noqa: E402

TABLES = ROOT / "reports" / "tables"
V2 = ROOT / "artifacts" / "runs" / "centralized_v2" / "category"
TARGETS = (0.05, 0.01)


# training takes a while; stop the laptop from going to sleep halfway
def keep_awake(on: bool) -> None:
    """Ask Windows not to sleep while this process runs (no power-setting change)."""
    if sys.platform == "win32":
        ES_CONTINUOUS, ES_SYSTEM_REQUIRED = 0x80000000, 0x00000001
        ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS | (ES_SYSTEM_REQUIRED if on else 0))


def alarm_rate(P: np.ndarray, benign: int, rule: str, th: dict, mask: np.ndarray | None = None) -> float:
    pred = P.argmax(1) if rule == "argmax" else predict_with_threshold(P, benign, th[rule])
    a = pred != benign
    if mask is not None:
        a = a[mask]
    return round(float(a.mean()), 4) if len(a) else float("nan")


def main(argv: list[str] | None = None) -> int:
    dcfg = data_config(ROOT / "configs" / "data.yaml")
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--features", type=Path, default=work_dir(dcfg) / "live" / "benign_laptop_1" / "features.csv")
    ap.add_argument("--factors", nargs="*", type=int, default=[1, 5], help="times the local train half is repeated")
    ap.add_argument("--seeds", nargs="*", type=int, default=[0, 1, 2])
    ap.add_argument("--device", default="cuda")
    a = ap.parse_args(argv)
    device = resolve_device(a.device)
    torch.set_num_threads(6)
    keep_awake(True)
    t_start = time.time()

    task = "category"
    names, benign = task_labels(task), benign_index(task)
    v2cfg = json.loads((V2 / "config.json").read_text(encoding="utf-8"))
    search = load_yaml(ROOT / "configs" / "hparam_search.yaml")
    # exact same model settings as the frozen v2 detector, the only change is the extra data
    run_cfg = {"model": {"hidden": v2cfg["mlp"]["hidden"], "dropout": v2cfg["mlp"]["dropout"]},
               "train": {**search["train"], "lr": v2cfg["mlp"]["lr"], "class_weighting": v2cfg["mlp"]["class_weighting"]}}
    features, pre, data = prepare({"task": task, "feature_set": search["feature_set"]}, dcfg)
    assert features == v2cfg["features"]
    tr, va, te = data["train"], data["val"], data["test"]
    print(f"CICIoT2023 train {len(tr['y'])} (benign {int((tr['y'] == benign).sum())}), val {len(va['y'])}, test {len(te['y'])}")

    # local capture: chronological halves, model features in v2 order, the original train-only preprocessor
    df = pd.read_csv(a.features)
    half = len(df) // 2
    # local windows go through the ORIGINAL preprocessor, same as everything else
    X_loc = pre.transform(df[ALL_FEATURES].to_numpy(np.float64)[:, [ALL_FEATURES.index(f) for f in features]])
    services = np.array([service(r) for r in df[ALL_FEATURES].to_dict("records")])
    udp = (df.UDP >= 0.5).to_numpy()
    first, second = slice(0, half), slice(half, None)
    comp = {k: pd.Series(services[s]).value_counts(normalize=True).round(3).head(4).to_dict()
            for k, s in (("first half", first), ("second half", second))}
    print(f"local windows {len(df)}: train half {half} ({df.t_start_s.iloc[half]:.0f} s), test half {len(df) - half}")
    print(f"  services: {comp}")

    out_dir = work_dir(dcfg) / "live" / "retrain"
    out_dir.mkdir(parents=True, exist_ok=True)
    n_in, n_cls = len(features), len(names)
    rows = []

    # for each model: false alarms on the unseen second half, and detection on CICIoT2023 test (did it get worse?)
    def evaluate(variant: str, factor: int, seed: int, model, epochs: str):
        pv = predict_proba(model, va["Xp"])
        th = {f"fpr{t * 100:g}": threshold_for_fpr(attack_score(pv, benign), va["y"] == benign, t) for t in TARGETS}
        pt, pl = predict_proba(model, te["Xp"]), predict_proba(model, X_loc)
        ops = {r["operating_point"]: r for r in operating_points(pt, te["y"], names, benign, TARGETS, th)}
        vops = {r["operating_point"]: r for r in operating_points(pv, va["y"], names, benign, TARGETS, th)}
        row = {"variant": variant, "local_factor": factor, "seed": seed, "epochs": epochs,
               "one_minus_t_fpr1": f"{1 - th['fpr1']:.1e}",
               "val_macro_f1_argmax": round(vops["argmax"]["macro_f1"], 4)}
        for rule in ("argmax", "fpr5", "fpr1"):
            row[f"local_test_alarm_{rule}"] = alarm_rate(pl[second], benign, rule, th)
        row["local_test_alarm_fpr1_tcp"] = alarm_rate(pl[second], benign, "fpr1", th, ~udp[second])
        row["local_test_alarm_fpr1_udp"] = alarm_rate(pl[second], benign, "fpr1", th, udp[second])
        row["local_train_alarm_fpr1"] = alarm_rate(pl[first], benign, "fpr1", th)
        for rule in ("fpr5", "fpr1", "argmax"):
            o = ops[rule]
            row[f"ciciot_test_benign_fpr_{rule}"] = round(o["benign_fpr"], 4)
            row[f"ciciot_test_attack_det_{rule}"] = round(o["attack_detection_rate"], 4)
            row[f"ciciot_test_macro_f1_{rule}"] = round(o["macro_f1"], 4)
        rows.append(row)
        print(f"[{variant} s{seed}] local test alarms fpr1 {row['local_test_alarm_fpr1']:.1%} "
              f"(tcp {row['local_test_alarm_fpr1_tcp']:.1%}, udp {row['local_test_alarm_fpr1_udp']:.1%}) | "
              f"CICIoT test fpr1: benign FPR {row['ciciot_test_benign_fpr_fpr1']:.2%} det {row['ciciot_test_attack_det_fpr1']:.1%} "
              f"F1 {row['ciciot_test_macro_f1_fpr1']:.4f} | val F1 {row['val_macro_f1_argmax']:.4f}", flush=True)

    # control: the original models, trained without any local traffic
    for seed in a.seeds:
        model = MLP(n_in, n_cls, run_cfg["model"]["hidden"], run_cfg["model"]["dropout"]).to(device)
        model.load_state_dict(torch.load(V2 / f"mlp_seed{seed}.pt", map_location=device))
        evaluate("frozen v2 (no local data)", 0, seed, model, "-")

    # add the first half of the capture as extra Benign rows (factor = how many copies), retrain from scratch
    for factor in a.factors:
        Xl, yl = np.repeat(X_loc[first], factor, axis=0), np.full(half * factor, benign, dtype=tr["y"].dtype)
        aug = {"train": {"Xp": np.concatenate([tr["Xp"], Xl]), "y": np.concatenate([tr["y"], yl])}, "val": va}
        for seed in a.seeds:
            t0 = time.time()
            model, hist, _ = train_mlp(run_cfg, aug, n_cls, seed, names, benign, lambda m: None, device)
            best = max(hist, key=lambda h: h["val_macro_f1"])["epoch"]
            torch.save(model.state_dict(), out_dir / f"mlp_local_x{factor}_s{seed}.pt")
            print(f"  trained +local x{factor} seed {seed}: best epoch {best}/{len(hist)} ({time.time() - t0:.0f} s)")
            evaluate(f"retrained + local x{factor}", factor, seed, model, f"{best}/{len(hist)}")
        del aug

    res = pd.DataFrame(rows)
    res.to_csv(TABLES / "live_retrain.csv", index=False)
    num = [c for c in res.columns if c.startswith(("local_", "ciciot_", "val_")) and c != "local_factor"]
    summ = res.groupby(["variant", "local_factor"], sort=False)[num].mean().round(4).reset_index()
    summ.insert(2, "seeds", len(a.seeds))
    summ.to_csv(TABLES / "live_retrain_summary.csv", index=False)
    pd.set_option("display.width", 250)
    print("\n", summ[["variant", "local_test_alarm_argmax", "local_test_alarm_fpr5", "local_test_alarm_fpr1",
                      "local_test_alarm_fpr1_tcp", "local_test_alarm_fpr1_udp", "ciciot_test_benign_fpr_fpr1",
                      "ciciot_test_attack_det_fpr1", "ciciot_test_macro_f1_fpr1"]].to_string(index=False))
    print(f"\ndone in {time.time() - t_start:.0f} s; models in {out_dir}")
    keep_awake(False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
