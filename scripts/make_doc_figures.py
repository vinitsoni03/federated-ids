"""Figures for the written deliverables (final report, literature review, IEEE paper).

* reports/figures/doc_architecture.png   system architecture (data -> detectors -> federation -> attacks -> serving)
* reports/figures/doc_usecase.png        use-case diagram (actors and what each does with the system)
* reports/figures/doc_lit_comparison.png reported CICIoT2023 F1 in the reviewed papers vs this project,
                                         grouped by evaluation protocol

The literature numbers are copied from the papers' own tables (cited in reports/literature_review.md);
this project's numbers are read from reports/tables/*.csv so they cannot drift from the results.

Usage: python scripts/make_doc_figures.py
"""
from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402
from matplotlib.patches import Ellipse, FancyArrowPatch, FancyBboxPatch  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
FIG = ROOT / "reports" / "figures"
TAB = ROOT / "reports" / "tables"
plt.rcParams.update({"font.family": "serif", "font.serif": ["Times New Roman", "DejaVu Serif"],
                     "font.size": 9})

NAVY, BLUE, GREEN, RED, GREY = "#1f3a5f", "#d6e4f0", "#dcefdc", "#f6d5d5", "#eeeeee"


def box(ax, x, y, w, h, text, fc=BLUE, ec=NAVY, size=8.5, bold=False):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.012,rounding_size=0.02",
                                fc=fc, ec=ec, lw=1.0))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=size,
            fontweight="bold" if bold else "normal", wrap=True)


def arrow(ax, x1, y1, x2, y2, color=NAVY, style="-|>", ls="-"):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style, mutation_scale=10,
                                 color=color, lw=1.0, linestyle=ls))


def architecture() -> None:
    fig, ax = plt.subplots(figsize=(10, 6.2))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    # Lane titles
    for x, t in [(0.02, "1. Data"), (0.25, "2. Detectors"), (0.50, "3. Federated training"),
                 (0.77, "4. Robustness & serving")]:
        ax.text(x, 0.97, t, fontsize=10, fontweight="bold", color=NAVY)

    # 1. Data lane
    box(ax, 0.02, 0.78, 0.20, 0.14, "CICIoT2023\n309 CSV files\n46.8 M windows, 39 features", GREY)
    box(ax, 0.02, 0.58, 0.20, 0.14, "Provenance & leakage audit\nduplicates, cross-label rows,\nwindow-size shortcut")
    box(ax, 0.02, 0.38, 0.20, 0.14, "Leakage-aware split\nfile-level + purged time blocks,\nde-duplication, caps")
    box(ax, 0.02, 0.18, 0.20, 0.14, "Preprocessing (train only)\nimpute, signed log, scale;\n33 window-invariant features")
    for y in (0.78, 0.58, 0.38):
        arrow(ax, 0.12, y, 0.12, y - 0.06)
    box(ax, 0.02, 0.02, 0.20, 0.11, "GridStratLLM (separate)\n436 LLM-planned sessions,\nleave-one-LLM-out", GREY, size=8)

    # 2. Detectors lane
    box(ax, 0.25, 0.70, 0.21, 0.16, "Centralized detectors\nMLP v1 / v2, Random Forest,\nHistGradientBoosting")
    box(ax, 0.25, 0.48, 0.21, 0.16, "Operating points\nthresholds for 5 % / 1 %\nbenign FPR (fit on validation)")
    box(ax, 0.25, 0.26, 0.21, 0.16, "Evaluation\nmacro-F1, balanced acc.,\ndetection @ FPR, unseen test")
    # Data bus: preprocessing -> detectors (lane 2) and -> federated clients (lane 3).
    ax.plot([0.22, 0.235, 0.235], [0.25, 0.25, 0.78], color=NAVY, lw=1.0)
    arrow(ax, 0.235, 0.78, 0.25, 0.78)
    ax.plot([0.235, 0.485, 0.485], [0.45, 0.45, 0.55], color=NAVY, lw=1.0, ls="--")
    arrow(ax, 0.485, 0.55, 0.505, 0.55, ls="--")
    arrow(ax, 0.355, 0.70, 0.355, 0.64)
    arrow(ax, 0.355, 0.48, 0.355, 0.42)

    # 3. Federated lane
    box(ax, 0.50, 0.74, 0.24, 0.16,
        "Aggregation server\nFedAvg / FedProx /\nmedian / trimmed mean / norm clip", fc=BLUE)
    for i, x in enumerate((0.505, 0.59, 0.675)):
        lab = "client\n(malicious)" if i == 2 else f"client {i + 1}"
        box(ax, x, 0.50, 0.06, 0.10, lab, fc=RED if i == 2 else GREEN, size=7.5)
        arrow(ax, x + 0.03, 0.60, x + 0.03, 0.74, style="<|-|>")
    ax.text(0.645, 0.465, "IID / Dirichlet α = 1.0 / α = 0.1 partitions", ha="center", fontsize=7.5)
    box(ax, 0.50, 0.24, 0.24, 0.17,
        "Flower deployment of the same setup\nSuperLink on Azure VM 1\n5 SuperNodes on Azure VM 2 + 5 on laptop\n"
        "TLS across the internet", fc=GREY, size=8)

    # 4. Robustness & serving
    box(ax, 0.77, 0.74, 0.21, 0.16, "Model-update poisoning\nsign-flip x5; DDoS→Benign\n+ boosting; 10-30 % clients",
        fc=RED)
    box(ax, 0.77, 0.50, 0.21, 0.16,
        "Inference-time evasion\nagainst the lane-2 detectors;\nlabel-only: pad / slow / re-TTL", fc=RED)
    box(ax, 0.77, 0.30, 0.21, 0.13, "Adversarial training\n2 rounds, adaptive re-attack", fc=GREEN)
    box(ax, 0.77, 0.06, 0.21, 0.15, "Serving\nFastAPI endpoint on Azure\n(HTTPS, API key) + demo dashboard",
        fc=GREY, size=8)
    arrow(ax, 0.77, 0.82, 0.74, 0.82)
    arrow(ax, 0.875, 0.50, 0.875, 0.43)
    arrow(ax, 0.745, 0.30, 0.77, 0.17)

    fig.savefig(FIG / "doc_architecture.png", dpi=200, bbox_inches="tight")
    plt.close(fig)


def stick(ax, x, y, name):
    ax.add_patch(plt.Circle((x, y + 0.055), 0.018, fill=False, ec=NAVY, lw=1.1))
    ax.plot([x, x], [y + 0.037, y - 0.015], color=NAVY, lw=1.1)
    ax.plot([x - 0.025, x + 0.025], [y + 0.02, y + 0.02], color=NAVY, lw=1.1)
    ax.plot([x, x - 0.02], [y - 0.015, y - 0.05], color=NAVY, lw=1.1)
    ax.plot([x, x + 0.02], [y - 0.015, y - 0.05], color=NAVY, lw=1.1)
    ax.text(x, y - 0.075, name, ha="center", va="top", fontsize=8.5, fontweight="bold")


def usecase() -> None:
    fig, ax = plt.subplots(figsize=(9, 6))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    ax.add_patch(FancyBboxPatch((0.22, 0.03), 0.56, 0.92, boxstyle="round,pad=0.01", fc="white",
                                ec=NAVY, lw=1.2))
    ax.text(0.5, 0.925, "Federated IDS evaluation system", ha="center", fontsize=10, fontweight="bold")
    cases = {
        "audit": (0.5, 0.84, "Audit dataset & build\nleakage-aware split"),
        "train": (0.5, 0.735, "Train / calibrate\ndetector"),
        "fl": (0.5, 0.63, "Run federated round\n(local training + upload)"),
        "agg": (0.5, 0.525, "Aggregate updates\n(robust rule)"),
        "score": (0.5, 0.42, "Score traffic windows\n(endpoint / dashboard)"),
        "alert": (0.5, 0.315, "Review alerts at\nchosen FPR"),
        "poison": (0.5, 0.205, "Send poisoned update"),
        "evade": (0.5, 0.10, "Query & perturb own\ntraffic to evade"),
    }
    for _k, (x, y, t) in cases.items():
        ax.add_patch(Ellipse((x, y), 0.30, 0.085, fc=BLUE, ec=NAVY, lw=0.9))
        ax.text(x, y, t, ha="center", va="center", fontsize=7.8)
    actors = {"Researcher /\nML engineer": (0.09, 0.76), "Site operator\n(FL client)": (0.09, 0.50),
              "Security analyst\n(SOC)": (0.91, 0.40), "Attacker": (0.91, 0.16),
              "Aggregation\nserver": (0.91, 0.62)}
    for name, (x, y) in actors.items():
        stick(ax, x, y, name)
    links = [((0.09, 0.76), "audit"), ((0.09, 0.76), "train"), ((0.09, 0.50), "fl"),
             ((0.91, 0.62), "agg"), ((0.91, 0.40), "score"), ((0.91, 0.40), "alert"),
             ((0.91, 0.16), "poison"), ((0.91, 0.16), "evade")]
    for (ax0, ay0), k in links:
        x, y, _ = cases[k]
        x_edge = x - 0.15 if ax0 < 0.5 else x + 0.15
        ax.plot([ax0 + (0.03 if ax0 < 0.5 else -0.03), x_edge], [ay0 + 0.02, y], color=NAVY, lw=0.8)
    fig.savefig(FIG / "doc_usecase.png", dpi=200, bbox_inches="tight")
    plt.close(fig)


def lit_comparison() -> None:
    m4 = pd.read_csv(TAB / "m4_centralized.csv")

    def ours(task, model, split="test"):
        r = m4[(m4.task == task) & (m4.model == model) & (m4.split == split)
               & ~m4.setting.str.contains("ablation")]
        return float(r.macro_f1.iloc[0])

    m5 = pd.read_csv(TAB / "m5_federated.csv")
    fl_iid = m5[(m5.task == "category") & (m5.setting == "IID") & (m5.algorithm == "fedavg")]

    rows = [
        # label, F1, group (protocol)
        ("Nayak & Reddy 2026\nbinary, FL (any rule)", 0.990, "Balanced / random sample"),
        ("Bilal et al. 2026\n8-class, FedNova-Transf.", 0.952, "Balanced / random sample"),
        ("Bilal et al. 2026\n8-class, FedAvg-LSTM", 0.920, "Balanced / random sample"),
        ("Neto et al. 2023\nbinary, RF", 0.965, "Random 80/20, all rows"),
        ("Neto et al. 2023\n8-class, RF", 0.719, "Random 80/20, all rows"),
        ("Neto et al. 2023\n8-class, DNN", 0.697, "Random 80/20, all rows"),
        ("This project\nbinary, MLP (full pool)", ours("binary", "mlp", "test_full_pool"),
         "File/time split, de-duplicated"),
        ("This project\nbinary, MLP", ours("binary", "mlp"), "File/time split, de-duplicated"),
        ("This project\n8-class, RF", ours("category", "random_forest"), "File/time split, de-duplicated"),
        ("This project\n8-class, MLP", ours("category", "mlp"), "File/time split, de-duplicated"),
    ]
    if len(fl_iid):
        rows.append(("This project\n8-class, FedAvg IID", float(fl_iid.macro_f1.iloc[0]),
                     "File/time split, de-duplicated"))
    colors = {"Balanced / random sample": "#c9c9c9", "Random 80/20, all rows": "#8fb0d0",
              "File/time split, de-duplicated": NAVY}
    fig, ax = plt.subplots(figsize=(7.2, 4.6))
    labels = [r[0] for r in rows][::-1]
    vals = [r[1] for r in rows][::-1]
    cols = [colors[r[2]] for r in rows][::-1]
    bars = ax.barh(range(len(rows)), vals, color=cols, edgecolor="black", lw=0.4)
    for b, v in zip(bars, vals):
        ax.text(v + 0.005, b.get_y() + b.get_height() / 2, f"{v:.3f}", va="center", fontsize=7.5)
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels(labels, fontsize=7.5)
    ax.set_xlim(0.5, 1.04)
    ax.set_xlabel("Reported F1 on CICIoT2023 (macro-F1 for multi-class)")
    handles = [plt.Rectangle((0, 0), 1, 1, color=c, ec="black", lw=0.4) for c in colors.values()]
    ax.legend(handles, colors.keys(), loc="lower right", fontsize=7.5, title="Evaluation protocol",
              title_fontsize=7.5)
    ax.grid(axis="x", lw=0.3, alpha=0.6)
    fig.tight_layout()
    fig.savefig(FIG / "doc_lit_comparison.png", dpi=200)
    plt.close(fig)


def confusion() -> None:
    """Row-normalised test confusion matrices: 8-class MLP (seed 0) and RF, and binary MLP (seed 0)."""
    import json

    import numpy as np

    runs = ROOT / "artifacts" / "runs"
    panels = [("centralized_category_window_invariant", "metrics_mlp_seed0.json", "8-class MLP (seed 0)"),
              ("centralized_category_window_invariant", "metrics_rf.json", "8-class Random Forest"),
              ("centralized_binary_window_invariant", "metrics_mlp_seed0.json", "Binary MLP (seed 0)")]
    fig, axes = plt.subplots(1, 3, figsize=(14, 4.6), gridspec_kw={"width_ratios": [1, 1, 0.42], "wspace": 0.42})
    for ax, (run, fname, title) in zip(axes, panels):
        t = json.loads((runs / run / fname).read_text())["test"]
        cm = np.array(t["confusion_matrix"], dtype=float)
        cm = cm / cm.sum(axis=1, keepdims=True)
        names = t["class_names"]
        im = ax.imshow(cm, cmap="Blues", vmin=0, vmax=1)
        for i in range(len(names)):
            for j in range(len(names)):
                if cm[i, j] >= 0.01:
                    ax.text(j, i, f"{cm[i, j]:.2f}", ha="center", va="center", fontsize=7,
                            color="white" if cm[i, j] > 0.6 else "black")
        ax.set_xticks(range(len(names)))
        ax.set_xticklabels(names, rotation=45, ha="right", fontsize=8)
        ax.set_yticks(range(len(names)))
        ax.set_yticklabels(names, fontsize=8)
        ax.set_xlabel("Predicted")
        ax.set_title(f"{title}\nacc. {t['accuracy']:.3f}, macro-F1 {t['macro_f1']:.3f}", fontsize=9)
    axes[0].set_ylabel("True class")
    fig.colorbar(im, ax=axes, shrink=0.8, label="share of true class")
    fig.savefig(FIG / "doc_confusion.png", dpi=200, bbox_inches="tight")
    plt.close(fig)


if __name__ == "__main__":
    architecture()
    usecase()
    lit_comparison()
    confusion()
    print("wrote doc_architecture.png, doc_usecase.png, doc_lit_comparison.png, doc_confusion.png")
