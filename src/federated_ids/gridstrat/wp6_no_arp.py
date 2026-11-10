"""WP6: GridStratLLM - are LLM-planned attacks still detectable WITHOUT the ARP signature?

Every attack session in GridStratLLM runs through `arp_mitm` + S7/Modbus data modification, and the M8
analysis (`analysis.py`) found that L2/L3 binding features ("IP seen with >1 MAC", ARP counts) and host
counts (distinct src MACs / IPs) carry most of the signal. This script removes them and asks what is left.

Feature sets (identity-free, per 10-s window, same windows/labels/guard band as M8):
  timing_volume_noid  - M8 `volume` minus n_src_mac / n_src_ip: packets, bytes, size stats, transport
                        shares, S7/Modbus packet counts, S7 inter-arrival mean/std. No ARP, no binding,
                        no host counts.
  process             - SCADA process data (`process_data.parquet`: scada/pv, scada/wind, scada/battery,
                        demand, power_flow). Per window and numeric field: std, range (max-min) and number of
                        value changes, plus records per source. Absolute levels are left out on purpose:
                        they follow weather / time of day, which differ between capture days, so a model
                        could separate days instead of attacks.
  timing_volume_noid+process
  volume_m8_reference - M8 `volume` recomputed; must equal reports/gridstrat/results.json (sanity check).

Evaluation is unchanged from M8: leave-one-LLM-out, normal operation split in time (first 60 % train,
last 40 % test only), RF(300, balanced) at the fixed 0.5 threshold, session detected if >= 1 window flagged,
broken down by target state and coordinated vs single-worker.

Inputs: reports/gridstrat/windows.csv (written by analysis.py) + the raw dataset for process data.
Outputs: reports/gridstrat/wp6_results.json, reports/tables/wp6_gridstrat_no_arp.{csv,md}.

Usage:
    python -m federated_ids.gridstrat.wp6_no_arp --root D:/.../data/dataset/unzipped
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np

from federated_ids.gridstrat.analysis import (NORMAL, VOLUME, WINDOW_S, dataset_dirs, evaluate_fold,
                                              session_detection, sessions)

NOID = [f for f in VOLUME if f not in ("n_src_mac", "n_src_ip")]


def _flatten(obj, prefix: str, out: dict) -> None:
    """Numeric leaves of a nested JSON object -> {"a.b.c": float}; booleans become 0/1."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            _flatten(v, f"{prefix}.{k}", out)
    elif isinstance(obj, bool):
        out[prefix] = float(obj)
    elif isinstance(obj, (int, float)):
        out[prefix] = float(obj)


def process_features(d: Path, t0_s: float):
    """Per-window change statistics of every numeric SCADA/process field (no absolute levels)."""
    import polars as pl

    df = pl.read_parquet(d / "process_data.parquet", columns=["ts", "source", "values"]).sort("ts")
    frames = []
    for src in sorted(df["source"].unique().to_list()):
        sub = df.filter(pl.col("source") == src)
        recs = []
        for v in sub["values"].to_list():
            r: dict = {}
            _flatten(json.loads(v), src, r)
            recs.append(r)
        vals = pl.DataFrame(recs, infer_schema_length=None)
        ts = sub["ts"].dt.epoch("us").to_numpy() / 1e6
        vals = vals.with_columns(pl.Series("w", ((ts - t0_s) // WINDOW_S).astype(np.int64)))
        fields = [c for c in vals.columns if c != "w"]
        aggs = [pl.len().alias(f"rate.{src}")]
        for f in fields:
            c = pl.col(f)
            aggs += [c.std().alias(f"std.{f}"), (c.max() - c.min()).alias(f"range.{f}"),
                     (c.diff() != 0).sum().alias(f"chg.{f}")]
        frames.append(vals.group_by("w").agg(aggs))
    out = frames[0]
    for f in frames[1:]:
        out = out.join(f, on="w", how="full", coalesce=True)
    return out.fill_null(0).fill_nan(0)


def main(argv: list[str] | None = None) -> int:
    import polars as pl

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", required=True, help=".../data/dataset/unzipped")
    ap.add_argument("--windows", default="reports/gridstrat/windows.csv")
    ap.add_argument("--m8-results", default="reports/gridstrat/results.json")
    ap.add_argument("--output-dir", default="reports/gridstrat")
    ap.add_argument("--table-dir", default="reports/tables")
    ap.add_argument("--normal-train-frac", type=float, default=0.6)
    a = ap.parse_args(argv)
    t_start = time.time()
    m8 = json.loads(Path(a.m8_results).read_text(encoding="utf-8"))
    if m8["window_s"] != WINDOW_S:
        raise SystemExit(f"window size mismatch: M8 {m8['window_s']} vs {WINDOW_S}")

    W_all = pl.read_csv(a.windows)
    dirs = dataset_dirs(Path(a.root))
    frames, sess_frames, proc_cols = [], [], None
    for name, d in dirs.items():
        w = W_all.filter(pl.col("dataset") == name)
        r0 = w.row(0, named=True)
        t0_s = r0["w_start_s"] - r0["w"] * WINDOW_S
        pf = process_features(d, t0_s)
        cols = set(pf.columns) - {"w"}
        proc_cols = cols if proc_cols is None else proc_cols & cols
        w = w.join(pf.with_columns(pl.col("w").cast(w["w"].dtype)), on="w", how="left")
        cover = float(w[sorted(c for c in cols if c.startswith("rate."))[0]].is_not_null().mean())
        frames.append(w)
        sess = sessions(d)
        if sess.height:
            sess_frames.append(sess.with_row_index("session_idx").with_columns(
                pl.col("session_idx").cast(pl.Int32), pl.lit(name).alias("dataset"))
                .select("dataset", "session_idx", "model_name", "coordinated", "target_state", "step_types"))
        print(f"{name}: {w.height} windows, {len(cols)} process features, process coverage {cover:.3f}", flush=True)
    PROC = sorted(proc_cols)
    W = pl.concat([f.select(W_all.columns + PROC) for f in frames]).fill_null(0).fill_nan(0)
    SESS = pl.concat(sess_frames)

    nw = W.filter(pl.col("dataset") == NORMAL).sort("w")
    cut = int(a.normal_train_frac * nw.height)
    normal_train, normal_test = nw[:cut], nw[cut:]
    normal_test_hours = normal_test.height * WINDOW_S / 3600
    attack = W.filter(pl.col("dataset") != NORMAL)
    models = sorted(attack["model_name"].unique().to_list())
    sets = {"volume_m8_reference": VOLUME, "timing_volume_noid": NOID, "process": PROC,
            "timing_volume_noid+process": NOID + PROC}

    results = {"window_s": WINDOW_S, "normal_test_hours": round(normal_test_hours, 3),
               "feature_sets": {k: len(v) for k, v in sets.items()}, "folds": {}}
    rows = []
    for group, feats in sets.items():
        results["folds"][group] = {}
        for m in models:
            tr = pl.concat([attack.filter((pl.col("model_name") != m) & (pl.col("label") >= 0)), normal_train])
            te_att = attack.filter((pl.col("model_name") == m) & (pl.col("label") >= 0))
            te = pl.concat([te_att, normal_test])
            r = evaluate_fold(tr, te, feats)
            n_att = te_att.height
            sess_det = session_detection(te_att, r["pred"][:n_att], SESS)
            fa_h = round(float(r["pred"][n_att:].sum()) / normal_test_hours, 2)
            res = {**r["window"], "session": sess_det, "false_alarm_windows_per_hour_normal_test": fa_h,
                   "importance_top5": dict(list(r["importance"].items())[:5])}
            results["folds"][group][m] = res
            rows.append({"feature_set": group, "held_out_llm": m, "n_features": len(feats),
                         "roc_auc": res["roc_auc"], "pr_auc": res["pr_auc"], "precision": res["precision"],
                         "recall": res["recall"], "f1": res["f1"], "session_detection": sess_det["detected_rate"],
                         "session_det_coordinated": sess_det["by_coordinated"].get("True"),
                         "session_det_single": sess_det["by_coordinated"].get("False"),
                         **{f"session_det[{k}]": v for k, v in sorted(sess_det["by_target_state"].items())},
                         "false_alarms_per_hour": fa_h,
                         "top_features": ", ".join(list(r["importance"])[:3])})
            print(f"[{group}] held-out {m}: AUC {res['roc_auc']:.3f} recall {res['recall']:.3f} "
                  f"session det {sess_det['detected_rate']:.2f} FA/h {fa_h}", flush=True)

    # sanity check: the recomputed M8 volume folds must match the stored M8 results
    for m in models:
        old, new = m8["folds"]["volume"][m]["roc_auc"], results["folds"]["volume_m8_reference"][m]["roc_auc"]
        if abs(old - new) > 1e-9:
            raise SystemExit(f"M8 reproduction failed for {m}: AUC {old} vs {new}")
    results["m8_reproduction"] = "volume AUCs identical to reports/gridstrat/results.json"
    results["seconds"] = round(time.time() - t_start, 1)

    out = Path(a.output_dir)
    (out / "wp6_results.json").write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    tab = pl.DataFrame(rows)
    tdir = Path(a.table_dir)
    tab.write_csv(tdir / "wp6_gridstrat_no_arp.csv")
    with open(tdir / "wp6_gridstrat_no_arp.md", "w", encoding="utf-8") as fh:
        cols = ["feature_set", "held_out_llm", "n_features", "roc_auc", "recall", "precision",
                "session_detection", "false_alarms_per_hour", "top_features"]
        fh.write("| " + " | ".join(cols) + " |\n|" + "---|" * len(cols) + "\n")
        for r in rows:
            fh.write("| " + " | ".join(f"{r[c]:.3f}" if isinstance(r[c], float) else str(r[c]) for c in cols) + " |\n")
    print(f"M8 reproduction OK; wrote {out / 'wp6_results.json'} and {tdir / 'wp6_gridstrat_no_arp.csv'} "
          f"({results['seconds']} s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
