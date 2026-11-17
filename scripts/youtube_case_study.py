"""Case study: real YouTube traffic, and what slowing packets down does to each detector (8-class, 1 % rule).

    python scripts/youtube_case_study.py --features <work_dir>/live/youtube_case/features.csv [--device cuda]

The capture is this laptop's own Wi-Fi traffic while a YouTube video streams (recorded with dumpcap, turned
into CICIoT2023 windows by federated_ids.live.score). It contains no attack, so every alarm is a false alarm.
Detectors (3 seeds each, thresholds fitted on CICIoT2023 validation benign for a 1 % FPR, as everywhere else):
  frozen     the v2 MLP (WP3)
  hardened   the adversarially trained v2 MLP (WP5 round 2)
  invariant  the attacker-invariant MLP (scripts/invariant_model.py)
  local      the v2 MLP retrained with 2.6 min of the laptop's benign traffic from 14 Nov (scripts/live_retrain.py),
             i.e. a cross-day test: that traffic was recorded three days before this capture
Parts:
  1  false alarms on the YouTube windows, by TCP / UDP window
  2  the evasion attacker's own changes (slow-down r, padding p, TTL) applied to the real YouTube windows:
     share of windows whose verdict (benign / attack) changes - a detector that ignores these changes
     gives the same answer whatever the sender does
  3  the same slow-down applied to the CICIoT2023 attack windows of the WP5 test sample (all windows slowed
     by the same r, no padding): share still detected
Writes reports/tables/youtube_case_{alarms,perturb,slowdown}.csv and reports/figures/youtube_case.png.
Aggregate numbers only; the capture itself stays outside the repository.
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
sys.path.insert(0, str(ROOT / "scripts"))

from federated_ids.attacks.evasion import apply_perturbation  # noqa: E402
from federated_ids.config import data_config, work_dir  # noqa: E402
from federated_ids.data.dataset import benign_index, load_split, task_labels  # noqa: E402
from federated_ids.data.preprocess import Preprocessor  # noqa: E402
from federated_ids.evaluation.calibration import attack_score, predict_with_threshold, threshold_for_fpr  # noqa: E402
from federated_ids.models.mlp import MLP, predict_proba, resolve_device  # noqa: E402
from invariant_model import invariant  # noqa: E402

TASK = "category"
RUNS = ROOT / "artifacts" / "runs"
TABLES, FIGS = ROOT / "reports" / "tables", ROOT / "reports" / "figures"
SEEDS = (0, 1, 2)
SLOW = [1.0, 0.5, 0.25, 0.1]
# (name, slow-down r, padding p in bytes, TTL) applied to the real YouTube windows in part 2
PERTURB = [("slow-down r=0.5", 0.5, 0, None), ("slow-down r=0.25", 0.25, 0, None), ("slow-down r=0.1", 0.1, 0, None),
           ("padding +100 B", 1.0, 100, None), ("padding +400 B", 1.0, 400, None), ("TTL set to 64", 1.0, 0, 64.0),
           ("all three (r=0.1, +400 B, TTL 64)", 0.1, 400, 64.0)]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--features", type=Path, default=work_dir(data_config()) / "live" / "youtube_case" / "features.csv")
    ap.add_argument("--device", default="cuda")
    ap.add_argument("--plot-only", action="store_true", help="redraw the figure from the saved tables")
    a = ap.parse_args()
    if a.plot_only:
        plot(pd.read_csv(TABLES / "youtube_case_perturb.csv"), pd.read_csv(TABLES / "youtube_case_slowdown.csv"))
        return 0
    device = resolve_device(a.device)
    dcfg = data_config()
    v2dir = RUNS / "centralized_v2" / TASK
    v2 = json.loads((v2dir / "config.json").read_text(encoding="utf-8"))
    raw = v2["features"]
    names, benign = task_labels(TASK), benign_index(TASK)
    hidden, dropout = v2["mlp"]["hidden"], v2["mlp"]["dropout"]

    # real traffic: one row per 10-packet window, columns in the dataset's order
    yt = pd.read_csv(a.features)
    Xyt = yt[raw].to_numpy(dtype=np.float64)
    udp = (yt.UDP >= 0.5).to_numpy()
    va, te = load_split("val", raw, TASK, dcfg), load_split("test", raw, TASK, dcfg)
    idx = np.load(RUNS / "wp5_advtrain" / TASK / "test_sample_idx.npy")
    Xatk = te.X[idx][te.y[idx] != benign]          # attack windows of the WP5 test sample
    print(f"YouTube windows {len(Xyt)} (UDP {udp.mean():.1%}); CICIoT2023 attack windows in the sample {len(Xatk)}")

    pre_v2 = Preprocessor.from_json(v2dir / "preprocessor.json")
    pre_inv = Preprocessor.from_json(RUNS / "invariant_model" / TASK / "preprocessor.json")
    # each detector: weights file, and how raw rows become its inputs
    to_v2 = pre_v2.transform
    to_inv = lambda X: pre_inv.transform(invariant(X, raw)[0])  # noqa: E731
    local_dir = work_dir(dcfg) / "live" / "retrain"
    detectors = {"frozen": [(v2dir / f"mlp_seed{s}.pt", to_v2, len(raw)) for s in SEEDS],
                 "hardened": [(RUNS / "wp5_advtrain" / TASK / f"mlp_s{s}_r2.pt", to_v2, len(raw)) for s in SEEDS],
                 "invariant": [(RUNS / "invariant_model" / TASK / f"mlp_seed{s}.pt", to_inv, len(raw) - 4) for s in SEEDS],
                 "local (14 Nov)": [(local_dir / f"mlp_local_x1_s{s}.pt", to_v2, len(raw)) for s in SEEDS]}

    alarms, perturb, slow = [], [], []
    for det, members in detectors.items():
        for seed, (path, to_in, n_in) in zip(SEEDS, members):
            model = MLP(n_in, len(names), hidden, dropout).to(device)
            model.load_state_dict(torch.load(path, map_location=device))
            # 1 % rule: threshold from CICIoT2023 validation benign, never from the capture
            t = threshold_for_fpr(attack_score(predict_proba(model, to_in(va.X)), benign), va.y == benign, 0.01)
            flag = lambda X: predict_with_threshold(predict_proba(model, to_in(X)), benign, t) != benign  # noqa: E731

            base = flag(Xyt)
            alarms.append({"detector": det, "seed": seed, "threshold": t, "alarm_rate": base.mean(),
                           "alarm_rate_tcp": base[~udp].mean(), "alarm_rate_udp": base[udp].mean()})
            for name, r, p, ttl in PERTURB:
                changed = flag(apply_perturbation(Xyt, raw, p, r, ttl)) != base
                perturb.append({"detector": det, "seed": seed, "change": name, "verdict_changed": changed.mean()})
            for r in SLOW:
                slow.append({"detector": det, "seed": seed, "r": r,
                             "detected": flag(apply_perturbation(Xatk, raw, 0, r, None)).mean()})
            print(f"[{det} s{seed}] t={t:.6f} YouTube alarms {base.mean():.1%} | attacks detected "
                  + " ".join(f"r={s['r']}: {s['detected']:.1%}" for s in slow[-len(SLOW):]), flush=True)

    TABLES.mkdir(parents=True, exist_ok=True)
    out = {}
    for key, rows, by in (("alarms", alarms, ["detector"]), ("perturb", perturb, ["detector", "change"]),
                          ("slowdown", slow, ["detector", "r"])):
        df = pd.DataFrame(rows)
        df.to_csv(TABLES / f"youtube_case_{key}_seeds.csv", index=False)
        num = [c for c in df.columns if c not in by + ["seed", "threshold"]]
        g = df.groupby(by, sort=False)[num]
        summ = g.mean().round(4).add_suffix("_mean").join(g.std().round(4).add_suffix("_sd")).reset_index()
        summ.to_csv(TABLES / f"youtube_case_{key}.csv", index=False)
        out[key] = summ
        print("\n" + summ.to_string(index=False))
    plot(out["perturb"], out["slowdown"])
    return 0


def plot(perturb: pd.DataFrame, slow: pd.DataFrame) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    colors = {"frozen": "#4C72B0", "hardened": "#DD8452", "invariant": "#2CA02C", "local (14 Nov)": "#8C8C8C"}
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 3.8))
    changes = [c for c, *_ in PERTURB]
    w = 0.2
    for i, det in enumerate(colors):
        d = perturb[perturb.detector == det].set_index("change").reindex(changes)
        y = np.arange(len(changes)) + (i - 1.5) * w
        ax1.barh(y, 100 * d.verdict_changed_mean, w, color=colors[det], label=det)
        # a bar of length 0 is invisible: write the 0 so the invariant model can be seen
        for yy, v in zip(y, d.verdict_changed_mean):
            if v == 0:
                ax1.text(0.2, yy, "0", va="center", fontsize=7, color=colors[det], fontweight="bold")
    ax1.set_yticks(np.arange(len(changes)), changes, fontsize=8)
    ax1.invert_yaxis()
    ax1.set_xlabel("YouTube windows whose verdict changes (%)")
    ax1.set_title("Real YouTube traffic, sender's changes applied", fontsize=10)
    for det, c in colors.items():
        d = slow[slow.detector == det]
        ax2.errorbar(d.r, 100 * d.detected_mean, yerr=100 * d.detected_sd, marker="o", color=c, label=det, capsize=3)
    ax2.set_xscale("log")
    ax2.set_xticks(SLOW, ["1 (none)", "0.5", "0.25", "0.1"])
    ax2.invert_xaxis()
    ax2.set_xlabel("slow-down factor r (packet rate x r)")
    ax2.set_ylabel("CICIoT2023 attacks detected (%)")
    ax2.set_title("Attack windows slowed down, 1 % rule", fontsize=10)
    ax2.grid(alpha=0.3)
    ax2.legend(fontsize=8, loc="center right")
    fig.tight_layout()
    FIGS.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIGS / "youtube_case.png", dpi=200)
    print(f"figure: {FIGS / 'youtube_case.png'}")


if __name__ == "__main__":
    sys.exit(main())
