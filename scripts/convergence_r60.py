"""WP1 convergence check: did 30 federated rounds plateau?

Reads the 60-round runs of the `m5_r60` grid (scripts/run_fl_grid.py) and compares round 30 with round 60:
IID FedAvg seed 0 (best case) and Dirichlet alpha=0.1 FedAvg seeds 0-2 (worst case), for each task.
Also checks that round 30 of each 60-round run equals the final round of the matching 30-round run
(same seed and partition, so the first 30 rounds must be identical).

Writes reports/tables/m5_r60_convergence.{csv,md} and reports/figures/m5_r60_convergence.png.
    python scripts/convergence_r60.py
"""
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
RUNS = ROOT / "artifacts" / "runs"
TASKS = {"category": "8-class", "class34": "34-class", "binary": "binary"}
SETTINGS = [("iid", 0)] + [("dir0.1", s) for s in (0, 1, 2)]


def history(name: str) -> pd.DataFrame:
    return pd.read_csv(RUNS / name / "history.csv").set_index("round")


def main() -> int:
    rows = []
    for task in TASKS:
        for part, seed in SETTINGS:
            h60 = history(f"fl_{task}_{part}_fedavg_r60_s{seed}")
            h30 = history(f"fl_{task}_{part}_fedavg_s{seed}")
            r30, r60 = h60.loc[30], h60.loc[60]
            rows.append({
                "task": task, "partition": part, "seed": seed,
                "test_macro_f1_r30": r30.test_macro_f1, "test_macro_f1_r60": r60.test_macro_f1,
                "delta_macro_f1": r60.test_macro_f1 - r30.test_macro_f1,
                "benign_fpr_r30": r30.test_benign_fpr, "benign_fpr_r60": r60.test_benign_fpr,
                "best_round": int(h60.test_macro_f1.idxmax()), "best_test_macro_f1": h60.test_macro_f1.max(),
                "comm_MB_r60": r60.comm_MB,
                "r30_matches_30round_run": bool(abs(r30.test_macro_f1 - h30.loc[30].test_macro_f1) < 1e-9),
            })
    df = pd.DataFrame(rows)
    out = ROOT / "reports" / "tables" / "m5_r60_convergence"
    df.to_csv(out.with_suffix(".csv"), index=False)
    fmt = lambda v: f"{v:.4f}" if isinstance(v, float) else str(v)
    md = ["| " + " | ".join(df.columns) + " |", "|" + "---|" * len(df.columns)]
    md += ["| " + " | ".join(fmt(v) for v in r) + " |" for r in df.itertuples(index=False)]
    out.with_suffix(".md").write_text("\n".join(md) + "\n", encoding="utf-8")

    fig, axes = plt.subplots(1, 3, figsize=(15, 4.2), sharey=True)
    for ax, (task, label) in zip(axes, TASKS.items()):
        for part, seed in SETTINGS:
            h = history(f"fl_{task}_{part}_fedavg_r60_s{seed}")
            iid = part == "iid"
            ax.plot(h.index, h.test_macro_f1, color="#1f5fd1" if iid else "#e0622e", lw=2.2 if iid else 1.6,
                    alpha=1 if iid else 0.85, label="IID (seed 0)" if iid else f"Dirichlet α=0.1 (seed {seed})",
                    ls="-" if iid else ["-", "--", ":"][seed])
        ax.axvline(30, color="#888", lw=1, ls="--")
        ax.text(30.5, 0.12, "30 rounds\n(main grid)", fontsize=8, color="#555")
        ax.set_title(label)
        ax.set_xlabel("Round")
        ax.grid(alpha=0.3)
    axes[0].set_ylabel("Test macro-F1 (FedAvg)")
    axes[0].set_ylim(0.1, 0.85)
    axes[0].legend(fontsize=8, loc="lower right")
    fig.suptitle("Convergence check: 60 rounds instead of 30", fontsize=12)
    fig.tight_layout()
    fig.savefig(ROOT / "reports" / "figures" / "m5_r60_convergence.png", dpi=110)

    print(df.round(4).to_string(index=False))
    if not df.r30_matches_30round_run.all():
        print("WARNING: round 30 of a 60-round run differs from the 30-round run")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
