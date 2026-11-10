"""Build every report table (CSV/Markdown) and figure (PNG) from experiment artifacts only.

    python scripts/make_figures.py [--no-family-eval]
Reads artifacts/runs/*/ and reports/gridstrat/results.json; writes reports/tables/ and
reports/figures/. Missing runs are skipped (and listed), never imputed. Every table has a
`task` column (category = 8-class, class34, binary).

Per-family "predicted Benign" rates of federated runs are recomputed here, identically for
every run, from the run's saved `global_model.pt` on the fixed test sample (runs without an
attack do not log them, and they are needed as the clean reference for the targeted attack).
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
RUNS = ROOT / "artifacts" / "runs"
TAB = ROOT / "reports" / "tables"
FIG = ROOT / "reports" / "figures"
TAB.mkdir(parents=True, exist_ok=True)
FIG.mkdir(parents=True, exist_ok=True)
TASKS = [("category", "8-class"), ("class34", "34-class"), ("binary", "binary")]

# reference categorical palette (fixed order), light surface, text tokens
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
plt.rcParams.update({"figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "axes.edgecolor": INK2,
                     "axes.labelcolor": INK, "xtick.color": INK2, "ytick.color": INK2, "text.color": INK,
                     "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.8, "axes.spines.top": False,
                     "axes.spines.right": False, "font.size": 9, "axes.titlesize": 10, "legend.frameon": False,
                     "lines.linewidth": 2})
missing: list[str] = []
FAMILY_EVAL = True


def load(p: Path):
    if not p.exists():
        missing.append(str(p.relative_to(ROOT)))
        return None
    return json.loads(p.read_text(encoding="utf-8"))


def write_table(name: str, rows: list[dict]) -> None:
    if not rows:
        return
    cols = list(dict.fromkeys(k for r in rows for k in r))
    with open(TAB / f"{name}.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

    def f(v):
        return f"{v:.4f}" if isinstance(v, float) else ("" if v is None else str(v))
    md = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    md += ["| " + " | ".join(f(r.get(c)) for c in cols) + " |" for r in rows]
    (TAB / f"{name}.md").write_text("\n".join(md) + "\n", encoding="utf-8")


def mean_sd(xs):
    xs = [x for x in xs if x is not None]
    if not xs:
        return None, None
    return float(np.mean(xs)), (float(np.std(xs, ddof=1)) if len(xs) > 1 else 0.0)


# ---------- per-family predicted-Benign rates from saved FL models ----------
_family_cache: dict = {}


def family_benign_rates(run: Path, task: str) -> dict | None:
    """{family: share of that family's test rows predicted Benign} for a run's global model."""
    if not FAMILY_EVAL or not (run / "global_model.pt").exists():
        return None
    import torch

    from federated_ids.data.ciciot import CATEGORIES, family_of_class34
    from federated_ids.data.dataset import benign_index, load_split, task_labels
    from federated_ids.data.preprocess import Preprocessor
    from federated_ids.models.mlp import MLP, predict_proba

    cfg = json.loads((run / "config.json").read_text(encoding="utf-8"))
    feats = cfg["features"]
    key = (task, tuple(feats))
    if key not in _family_cache:
        te = load_split("test", feats, task)
        _family_cache[key] = (te, family_of_class34(te.y34))
    te, fam = _family_cache[key]
    pre = Preprocessor.from_json(run / "preprocessor.json")
    m = cfg.get("experiment", {}).get("model", {"hidden": [128, 64], "dropout": 0.1})
    model = MLP(len(feats), len(task_labels(task)), m["hidden"], m["dropout"])
    model.load_state_dict(torch.load(run / "global_model.pt", map_location="cpu"))
    pred = predict_proba(model, pre.transform(te.X)).argmax(1)
    b = benign_index(task)
    return {c: float((pred[fam == c] == b).mean()) for c in CATEGORIES if c != "Benign"}


# ---------- M4 centralized ----------
def centralized():
    rows = []
    settings = [(t, f"{lab}, 33 features", f"centralized_{t}_window_invariant") for t, lab in TASKS]
    settings.append(("category", "8-class, all 39 features (shortcut ablation)", "centralized_category_all39"))
    for task, label, run in settings:
        d = RUNS / run
        if not (d / "summary.csv").exists():
            missing.append(f"artifacts/runs/{run}/summary.csv")
            continue
        S = list(csv.DictReader(open(d / "summary.csv", encoding="utf-8")))
        for model in ("mlp", "random_forest"):
            for split in ("test", "test_unseen", "test_full_pool"):
                rs = [r for r in S if r["model"] == model and r["split"] == split]
                if not rs:
                    continue
                g = lambda k: mean_sd([float(r[k]) if r[k] not in ("", "None") else None for r in rs])
                mf, msd = g("macro_f1")
                rows.append({"task": task, "setting": label, "model": model, "split": split, "n_seeds": len(rs),
                             "macro_f1": mf, "macro_f1_sd": msd, "macro_f1_per_seed": " / ".join(f"{float(r['macro_f1']):.4f}" for r in rs),
                             "weighted_f1": g("weighted_f1")[0], "balanced_accuracy": g("balanced_accuracy")[0],
                             "benign_fpr": g("benign_fpr")[0], "attack_detection_rate": g("attack_detection_rate")[0],
                             "macro_pr_auc": g("macro_pr_auc_ovr")[0], "train_seconds": g("train_seconds")[0]})
    write_table("m4_centralized", rows)
    pcs = []
    for task, _ in TASKS:
        m = load(RUNS / f"centralized_{task}_window_invariant" / "metrics_mlp_seed0.json")
        rf = load(RUNS / f"centralized_{task}_window_invariant" / "metrics_rf.json")
        if not (m and rf):
            continue
        for c, v in m["test"]["per_class"].items():
            pcs.append({"task": task, "class": c, "mlp_precision": v["precision"], "mlp_recall": v["recall"],
                        "mlp_f1": v["f1"], "rf_f1": rf["test"]["per_class"][c]["f1"], "support": v["support"]})
        if task == "category":
            cm = np.array(m["test"]["confusion_matrix"], dtype=float)
            names = m["test"]["class_names"]
            cmn = cm / cm.sum(1, keepdims=True)
            fig, ax = plt.subplots(figsize=(5.6, 4.8))
            ax.grid(False)
            im = ax.imshow(cmn, cmap=matplotlib.colors.LinearSegmentedColormap.from_list(
                "blue", ["#ffffff", "#cde2fb", "#6da7ec", "#2a78d6", "#184f95"]), vmin=0, vmax=1)
            ax.set_xticks(range(len(names)), names, rotation=45, ha="right")
            ax.set_yticks(range(len(names)), names)
            for i in range(len(names)):
                for j in range(len(names)):
                    if cmn[i, j] >= 0.01:
                        ax.text(j, i, f"{cmn[i, j]:.2f}", ha="center", va="center", fontsize=7,
                                color="#ffffff" if cmn[i, j] > 0.55 else INK)
            ax.set_xlabel("Predicted")
            ax.set_ylabel("True")
            ax.set_title("Centralized MLP (8-class, seed 0), test sample: row-normalised confusion matrix")
            fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04, label="share of true class")
            fig.tight_layout()
            fig.savefig(FIG / "m4_confusion_mlp.png", dpi=160)
            plt.close(fig)
    write_table("m4_per_class_test", pcs)


# ---------- M5 federated ----------
FL_SETTINGS = [("iid", "IID"), ("dir1.0", "Dirichlet α=1.0"), ("dir0.1", "Dirichlet α=0.1")]


def federated():
    rows = []
    for task, tlab in TASKS:
        central = [x for x in (load(RUNS / f"centralized_{task}_window_invariant" / f"metrics_mlp_seed{s}.json")
                               for s in (0, 1, 2)) if x]
        if central:
            rows.append({"task": task, "setting": "centralized", "algorithm": "-", "n_seeds": len(central),
                         "macro_f1": mean_sd([c["test"]["macro_f1"] for c in central])[0],
                         "macro_f1_sd": mean_sd([c["test"]["macro_f1"] for c in central])[1],
                         "benign_fpr": mean_sd([c["test"]["benign_fpr"] for c in central])[0],
                         "attack_detection_rate": mean_sd([c["test"]["attack_detection_rate"] for c in central])[0],
                         "macro_f1_unseen": mean_sd([c["test_unseen"]["macro_f1"] for c in central])[0],
                         "wall_clock_s": mean_sd([c["train_seconds"] for c in central])[0], "comm_MB": 0.0,
                         "mean_tv_label_skew": 0.0})
        curves = {}
        for p, plabel in FL_SETTINGS:
            for al in ("fedavg", "fedprox"):
                ms, hs = [], []
                for s in (0, 1, 2):
                    d = RUNS / f"fl_{task}_{p}_{al}_s{s}"
                    mm = load(d / "metrics.json")
                    if mm:
                        ms.append(mm)
                        hs.append(list(csv.DictReader(open(d / "history.csv", encoding="utf-8"))))
                if not ms:
                    continue
                g = lambda f: mean_sd([f(m) for m in ms])
                rows.append({"task": task, "setting": plabel, "algorithm": al, "n_seeds": len(ms),
                             "macro_f1": g(lambda m: m["test"]["macro_f1"])[0],
                             "macro_f1_sd": g(lambda m: m["test"]["macro_f1"])[1],
                             "benign_fpr": g(lambda m: m["test"]["benign_fpr"])[0],
                             "attack_detection_rate": g(lambda m: m["test"]["attack_detection_rate"])[0],
                             "macro_f1_unseen": g(lambda m: m["test_unseen"]["macro_f1"])[0],
                             "wall_clock_s": g(lambda m: m["wall_clock_seconds"])[0],
                             "comm_MB": g(lambda m: m["communication"]["total_MB"])[0],
                             "mean_tv_label_skew": g(lambda m: m["partition"]["mean_tv_distance"])[0]})
                rounds = [int(r["round"]) for r in hs[0]]
                vals = np.array([[float(r["test_macro_f1"]) for r in h] for h in hs])
                curves[(plabel, al)] = (rounds, vals.mean(0), vals.min(0), vals.max(0))
        for mu in ("0.001", "0.1", "1.0"):
            mm = load(RUNS / f"fl_{task}_dir0.1_fedprox_mu{mu}_s0" / "metrics.json")
            if mm:
                rows.append({"task": task, "setting": "Dirichlet α=0.1", "algorithm": f"fedprox mu={mu}", "n_seeds": 1,
                             "macro_f1": mm["test"]["macro_f1"], "macro_f1_sd": None,
                             "benign_fpr": mm["test"]["benign_fpr"],
                             "attack_detection_rate": mm["test"]["attack_detection_rate"],
                             "macro_f1_unseen": mm["test_unseen"]["macro_f1"], "wall_clock_s": mm["wall_clock_seconds"],
                             "comm_MB": mm["communication"]["total_MB"],
                             "mean_tv_label_skew": mm["partition"]["mean_tv_distance"]})
        if curves:
            fig, axes = plt.subplots(1, 3, figsize=(10.5, 3.2), sharey=True)
            cline = np.mean([c["test"]["macro_f1"] for c in central]) if central else None
            for ax, (_, plabel) in zip(axes, FL_SETTINGS):
                last_r = None
                for i, al in enumerate(("fedavg", "fedprox")):
                    if (plabel, al) not in curves:
                        continue
                    r, m, lo, hi = curves[(plabel, al)]
                    last_r = r[-1]
                    ax.plot(r, m, color=SERIES[i], label={"fedavg": "FedAvg", "fedprox": "FedProx (μ=0.01)"}[al])
                    ax.fill_between(r, lo, hi, color=SERIES[i], alpha=0.15, linewidth=0)
                if cline is not None and last_r is not None:
                    ax.axhline(cline, color=INK2, linestyle="--", linewidth=1)
                    ax.text(last_r, cline + 0.005, "centralized", ha="right", va="bottom", fontsize=7, color=INK2)
                ax.set_title(plabel)
                ax.set_xlabel("Round")
            axes[0].set_ylabel(f"Test macro-F1, {tlab}\n(mean; band = min-max over seeds)")
            axes[0].legend(loc="lower right")
            fig.tight_layout()
            fig.savefig(FIG / f"m5_convergence_{task}.png", dpi=160)
            plt.close(fig)
    write_table("m5_federated", rows)


# ---------- M6 poisoning ----------
AGGS = [("fedavg", "FedAvg"), ("median", "Median"), ("trimmed_mean", "Trimmed mean"), ("norm_clip", "Norm clip")]
ATTS = [("clean", "No attack"), ("signflip", "Sign-flip x5 (20 %)"), ("targeted", "DDoS->Benign boost (20 %)")]


def poisoning():
    rows = []
    for task, tlab in TASKS:
        for p in ("iid", "dir1.0"):
            for att, alab in ATTS:
                for agg, glab in AGGS:
                    dirs = [RUNS / f"poison_{task}_{p}_{att}_{agg}_s{s}" for s in (0, 1, 2)]
                    ms = [(d, load(d / "metrics.json")) for d in dirs]
                    ms = [(d, m) for d, m in ms if m]
                    if not ms:
                        continue
                    fam = [family_benign_rates(d, task) for d, _ in ms]
                    g = lambda f: mean_sd([f(m) for _, m in ms])
                    rows.append({"task": task, "partition": p, "attack": alab, "aggregator": glab, "n_seeds": len(ms),
                                 "macro_f1": g(lambda m: m["test"]["macro_f1"])[0],
                                 "macro_f1_sd": g(lambda m: m["test"]["macro_f1"])[1],
                                 "benign_fpr": g(lambda m: m["test"]["benign_fpr"])[0],
                                 "attack_detection_rate": g(lambda m: m["test"]["attack_detection_rate"])[0],
                                 "ddos_pred_benign": mean_sd([f["DDoS"] if f else None for f in fam])[0],
                                 "wall_clock_s": g(lambda m: m["wall_clock_seconds"])[0]})
        for att in ("signflip", "targeted"):
            for frac in ("0.1", "0.3"):
                for agg in ("fedavg", "trimmed_mean", "median"):
                    d = RUNS / f"poison_{task}_iid_{att}_f{frac}_{agg}_s0"
                    m = load(d / "metrics.json")
                    if m:
                        f = family_benign_rates(d, task)
                        rows.append({"task": task, "partition": "iid", "attack": f"{att} ({float(frac):.0%})",
                                     "aggregator": agg, "n_seeds": 1, "macro_f1": m["test"]["macro_f1"],
                                     "macro_f1_sd": None, "benign_fpr": m["test"]["benign_fpr"],
                                     "attack_detection_rate": m["test"]["attack_detection_rate"],
                                     "ddos_pred_benign": f["DDoS"] if f else None,
                                     "wall_clock_s": m["wall_clock_seconds"]})
        for p in ("iid", "dir1.0"):
            sub = [r for r in rows if r["task"] == task and r["partition"] == p and r["attack"] in dict(ATTS).values()]
            if not sub:
                continue
            fig, axes = plt.subplots(1, 2, figsize=(10, 3.4))
            for k, (metric, ylab) in enumerate([("macro_f1", "Test macro-F1"),
                                                ("ddos_pred_benign", "Share of DDoS test windows predicted Benign")]):
                ax = axes[k]
                w = 0.2
                for i, (_, glab) in enumerate(AGGS):
                    xs, ys = [], []
                    for j, (_, alab) in enumerate(ATTS):
                        r = next((r for r in sub if r["attack"] == alab and r["aggregator"] == glab), None)
                        if r and r[metric] is not None:
                            xs.append(j + (i - 1.5) * w)
                            ys.append(r[metric])
                    ax.bar(xs, ys, width=w - 0.02, color=SERIES[i], label=glab)
                ax.set_xticks(range(len(ATTS)), ["No attack", "Sign-flip x5\n(20 % clients)",
                                                 "DDoS->Benign boost\n(20 % clients)"])
                ax.set_ylabel(ylab)
                ax.set_ylim(0, 1)
            axes[0].legend(ncol=2, loc="upper right")
            axes[1].text(0.02, 0.97, "bars near 0 (<= 0.003) are present but not visible", transform=axes[1].transAxes,
                         fontsize=7, color=INK2, va="top")
            fig.suptitle(f"Model-update poisoning, {tlab}, {'IID' if p == 'iid' else 'Dirichlet α=1.0'} partition, 10 clients")
            fig.tight_layout(rect=(0, 0, 1, 0.94))
            fig.savefig(FIG / f"m6_poisoning_{task}_{p}.png", dpi=160)
            plt.close(fig)
    write_table("m6_poisoning", rows)


# ---------- M7 evasion ----------
def evasion():
    rows, abl = [], []
    for task, tlab in TASKS:
        m = load(RUNS / f"evasion_centralized_{task}_window_invariant" / "metrics.json")
        if not m:
            continue
        for t, v in m["targets"].items():
            for b, bv in v["budgets"].items():
                for c, cv in bv["per_class"].items():
                    rows.append({"task": task, "target": t, "clean_benign_fpr": v["clean_benign_fpr"],
                                 "min_rate_factor": float(b), "family": c, "n": cv["n"],
                                 "clean_detection_rate": v["clean_detection_rate"][c], "evasion_rate": cv["evasion_rate"],
                                 "mean_queries": cv["mean_queries"]})
            for k, d in v["knob_ablation_at_loosest_budget"].items():
                abl.append({"task": task, "target": t, "knob": k, **d})
        classes = list(next(iter(m["targets"].values()))["clean_detection_rate"])
        fig, axes = plt.subplots(1, 2, figsize=(10, 3.4), sharey=True)
        for ax, (t, v) in zip(axes, m["targets"].items()):
            bud = sorted((float(b) for b in v["budgets"]), reverse=True)
            for i, c in enumerate(classes):
                ys = [v["budgets"][str(b)]["per_class"][c]["evasion_rate"] for b in bud]
                ax.plot(range(len(bud)), ys, marker="o", markersize=4, color=SERIES[i], label=c)
            ax.set_xticks(range(len(bud)), [f"r≥{b:g}" for b in bud])
            ax.set_xlabel("Slow-down budget (attacker may cut its packet rate to r×)")
            ax.set_title(f"{ {'mlp': 'MLP', 'random_forest': 'Random Forest'}[t] } (clean benign FPR {v['clean_benign_fpr']:.2f})")
        axes[0].set_ylabel(f"Evasion rate, {tlab} (detected -> Benign)")
        handles, labels = axes[0].get_legend_handles_labels()
        fig.legend(handles, labels, ncol=7, loc="upper center", fontsize=8, bbox_to_anchor=(0.5, 1.0))
        fig.tight_layout(rect=(0, 0, 1, 0.92))
        fig.savefig(FIG / f"m7_evasion_{task}.png", dpi=160)
        plt.close(fig)
    write_table("m7_evasion", rows)
    write_table("m7_evasion_knob_ablation", abl)


# ---------- M8 GridStratLLM ----------
def gridstrat():
    r = load(ROOT / "reports" / "gridstrat" / "results.json")
    inv = load(ROOT / "reports" / "gridstrat" / "inventory.json")
    if not r:
        return
    rows = []
    for g, folds in r["folds"].items():
        for mname, x in folds.items():
            rows.append({"features": g, "held_out_llm": mname, "test_windows": x["n_test"], "positive": x["positives"],
                         "roc_auc": x["roc_auc"], "pr_auc": x["pr_auc"], "precision": x["precision"],
                         "recall": x["recall"], "f1": x["f1"], "session_detection": x["session"]["detected_rate"],
                         "false_alarm_windows_per_h_normal": x["false_alarm_windows_per_hour_normal_test"]})
    for rule, folds in r["rules"].items():
        for mname, x in folds.items():
            rows.append({"features": f"rule: {rule}", "held_out_llm": mname, "recall": x["window_recall"],
                         "session_detection": x["session"]["detected_rate"],
                         "false_alarm_windows_per_h_normal": x["false_alarm_windows_per_hour_normal_test"]})
    write_table("m8_gridstrat", rows)
    if inv:
        write_table("m8_gridstrat_inventory", [{"dataset": k, "llm": v["model_name"], "hours": v["hours"],
                                               "packets": v["packets"], "sessions": v["sessions"],
                                               "coordinated": v["coordinated_sessions"],
                                               "positive_windows": v["windows_positive"],
                                               "excluded_windows": v["windows_excluded"]} for k, v in inv.items()])
    groups = [g for g in ("zeek_only", "binding", "volume", "volume+binding") if g in r["folds"]]
    llms = sorted(r["folds"][groups[0]])
    fig, ax = plt.subplots(figsize=(7.5, 3.8))
    w = 0.8 / len(groups)
    for i, g in enumerate(groups):
        ys = [r["folds"][g][m]["roc_auc"] for m in llms]
        ax.bar(np.arange(len(llms)) + (i - (len(groups) - 1) / 2) * w, ys, width=w - 0.02, color=SERIES[i], label=g)
    ax.set_xticks(range(len(llms)), [m.split("/")[-1] for m in llms])
    ax.set_ylim(0.5, 1.0)
    ax.set_ylabel("Window ROC-AUC on held-out LLM")
    ax.set_title("GridStratLLM leave-one-LLM-out detection (10-s windows, Random Forest)")
    ax.legend(ncol=4, loc="upper center", fontsize=8, bbox_to_anchor=(0.5, -0.12))
    fig.tight_layout()
    fig.savefig(FIG / "m8_gridstrat_auc.png", dpi=160)
    plt.close(fig)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-family-eval", action="store_true", help="skip recomputing per-family rates")
    FAMILY_EVAL = not ap.parse_args().no_family_eval
    centralized()
    federated()
    poisoning()
    evasion()
    gridstrat()
    print("tables:", sorted(p.name for p in TAB.glob("*.csv")))
    print("figures:", sorted(p.name for p in FIG.glob("*.png")))
    if missing:
        print(f"missing inputs ({len(set(missing))}), skipped")
