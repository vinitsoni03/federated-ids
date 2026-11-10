"""Milestone 8: GridStratLLM - LLM-coordinated attacks on a smart-grid HIL testbed (separate
from CICIoT2023; no features or labels are shared between the two datasets).

Research question (answerable with the released data):
  RQ-G: Do network-observable signatures of LLM-planned coordinated attacks generalise across
        the LLM that planned them? I.e. does a detector trained on attack sessions planned by
        some LLMs detect sessions planned by a held-out LLM, at what false-alarm rate, and
        which feature groups carry the signal?

Ground truth (documented provenance, no guessing):
  * attack session activity intervals = [first, last] `exec_ts` of the session's steps in
    attack_exec_steps.parquet ("attack execution timeline per worker", dataset README);
  * session metadata (model_name, coordinated, target_state, plan step types) from
    attack_session_llm.parquet;
  * packet-level labels (packet id in attack_datamod_history.packet_id) are reported, but NOT
    used for training: most modification records have state pending/no_match and no linked
    packet, so packet labels are an incomplete lower bound (see reports/gridstrat_analysis.md).

Unit of analysis: fixed 10-s windows of packet metadata. A window is positive if it overlaps
an attack session's activity interval, negative if it is >= guard_s away from every session,
and excluded otherwise (ARP-cache and TCP effects can outlast a session).

Features contain NO host identities (no MAC/IP values), only counts and statistics, so a model
cannot memorise this testbed's attacker hosts. Feature groups:
  volume    - packets, bytes, size mean/std, transport shares, S7 (TCP/102) and Modbus (TCP/502)
              packet counts, S7 inter-arrival mean/std, distinct src MACs / src IPs;
  binding   - number of IPv4 addresses seen with >1 source MAC in the window, ARP packets
              (L2/L3 binding inconsistency, the classical ARP-spoofing indicator);
  zeek      - Zeek weird.log events in the window (timestamps come from the same capture).

Evaluation: leave-one-LLM-out over the attack datasets (both Claude Sonnet 4.6 datasets form
one fold); the normal-operation dataset is split in time: first 60 % used for training in every
fold, last 40 % only for testing (false alarms per hour of pure normal operation).

Usage:
    python -m federated_ids.gridstrat.analysis --root D:/.../unzipped --output-dir reports/gridstrat
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np

WINDOW_S = 10
GUARD_S = 20
NORMAL = "20260225_normal"
VOLUME = ["n_packets", "bytes", "size_mean", "size_std", "share_tcp", "share_udp", "share_icmp",
          "share_non_ip", "n_s7", "n_modbus", "s7_iat_mean", "s7_iat_std", "n_src_mac", "n_src_ip"]
BINDING = ["n_ip_multi_mac", "n_arp"]
ZEEK = ["n_zeek_weird"]
FEATURE_GROUPS = {"volume": VOLUME, "binding": BINDING, "volume+binding": VOLUME + BINDING,
                  "zeek_only": ZEEK}


def dataset_dirs(root: Path) -> dict[str, Path]:
    return {p.name: p / p.name for p in sorted(root.iterdir()) if p.is_dir()}


def sessions(d: Path):
    import polars as pl

    s = pl.read_parquet(d / "attack_session_llm.parquet")
    es = pl.read_parquet(d / "attack_exec_steps.parquet")
    if s.height == 0:
        return s
    iv = es.group_by("attack_session_id").agg(pl.col("exec_ts").min().alias("act_start"),
                                             pl.col("exec_ts").max().alias("act_end"))
    steps = s.select("id", "plan").with_columns(
        pl.col("plan").map_elements(lambda p: ",".join(sorted({st["step_type"] for st in json.loads(p)})),
                                    return_dtype=pl.String).alias("step_types"))
    return (s.select("id", "model_name", "coordinated", "target_state", "start_ts", "planned_end_ts")
            .join(steps.drop("plan"), on="id").join(iv, left_on="id", right_on="attack_session_id", how="left"))


def window_features(d: Path):
    """Per-10s-window identity-free features from packet_metadata (+ Zeek weird counts)."""
    import polars as pl

    lf = pl.scan_parquet(d / "packet_metadata.parquet").select(
        "ts", "size", "transport", "ethertype", "mac_src", "src_ip", "src_port", "dst_port")
    t0 = lf.select(pl.col("ts").min()).collect().item()
    lf = lf.with_columns(((pl.col("ts") - pl.lit(t0)).dt.total_microseconds() // (WINDOW_S * 1_000_000)).alias("w"),
                         pl.col("ts").dt.epoch("us").alias("t_us"))
    is_s7 = (pl.col("transport") == "tcp") & ((pl.col("dst_port") == 102) | (pl.col("src_port") == 102))
    is_mb = (pl.col("transport") == "tcp") & ((pl.col("dst_port") == 502) | (pl.col("src_port") == 502))
    base = lf.group_by("w").agg(
        pl.len().alias("n_packets"), pl.col("size").sum().alias("bytes"),
        pl.col("size").mean().alias("size_mean"), pl.col("size").std().alias("size_std"),
        (pl.col("transport") == "tcp").mean().alias("share_tcp"),
        (pl.col("transport") == "udp").mean().alias("share_udp"),
        pl.col("transport").is_in(["icmp_v4", "icmp_v6"]).mean().alias("share_icmp"),
        pl.col("transport").is_null().mean().alias("share_non_ip"),
        is_s7.sum().alias("n_s7"), is_mb.sum().alias("n_modbus"),
        (pl.col("ethertype") == 0x0806).sum().alias("n_arp"),
        pl.col("mac_src").n_unique().alias("n_src_mac"), pl.col("src_ip").n_unique().alias("n_src_ip"),
    ).collect(engine="streaming")
    s7 = (lf.filter(is_s7).sort("t_us").with_columns(pl.col("t_us").diff().alias("iat"))
          .group_by("w").agg((pl.col("iat").mean() / 1e6).alias("s7_iat_mean"),
                             (pl.col("iat").std() / 1e6).alias("s7_iat_std")).collect(engine="streaming"))
    multi = (lf.filter(pl.col("src_ip").is_not_null()).group_by("w", "src_ip").agg(pl.col("mac_src").n_unique().alias("k"))
             .filter(pl.col("k") > 1).group_by("w").agg(pl.len().alias("n_ip_multi_mac")).collect(engine="streaming"))
    feats = base.join(s7, on="w", how="left").join(multi, on="w", how="left")
    # Zeek weird.log (JSON lines, epoch seconds)
    wpath = d / "Zeek" / "weird.log"
    t0_s = t0.timestamp()
    zeek = []
    if wpath.exists():
        for line in open(wpath, encoding="utf-8", errors="replace"):
            if line.startswith("{"):
                zeek.append(int((json.loads(line)["ts"] - t0_s) // WINDOW_S))
    zw = pl.DataFrame({"w": np.array(zeek, dtype=np.int64)}).group_by("w").agg(pl.len().alias("n_zeek_weird")) \
        if zeek else pl.DataFrame({"w": [], "n_zeek_weird": []}, schema={"w": pl.Int64, "n_zeek_weird": pl.UInt32})
    feats = feats.join(zw.with_columns(pl.col("w").cast(feats["w"].dtype)), on="w", how="left")
    feats = feats.fill_null(0).fill_nan(0).sort("w")
    return feats.with_columns((pl.lit(t0_s) + pl.col("w") * WINDOW_S).alias("w_start_s")), t0_s


def label_windows(feats, sess, t0_s: float):
    """label 1 = overlaps an active session, 0 = >= GUARD_S from all sessions, -1 = excluded."""
    import polars as pl

    ws = feats["w_start_s"].to_numpy()
    we = ws + WINDOW_S
    lab = np.zeros(len(ws), dtype=np.int8)
    sid = np.full(len(ws), -1, dtype=np.int32)
    if sess.height:
        S = sess["act_start"].dt.epoch("us").to_numpy() / 1e6
        E = sess["act_end"].dt.epoch("us").to_numpy() / 1e6
        for i, (s, e) in enumerate(zip(S, E)):
            pos = (we > s) & (ws < e)
            near = (we > s - GUARD_S) & (ws < e + GUARD_S)
            lab[near & (lab == 0)] = -1
            lab[pos] = 1
            sid[pos] = i
    return feats.with_columns(pl.Series("label", lab), pl.Series("session_idx", sid))


def packet_label_summary(d: Path) -> dict:
    import polars as pl

    dm = pl.read_parquet(d / "attack_datamod_history.parquet", columns=["packet_id", "state", "label_source"])
    if dm.height == 0:
        return {"datamod_rows": 0}
    ids = dm.filter(pl.col("packet_id").is_not_null()).select(pl.col("packet_id").alias("id")).unique()
    linked = pl.scan_parquet(d / "packet_metadata.parquet").select("id").join(ids.lazy(), on="id", how="semi") \
        .select(pl.len()).collect().item()
    return {"datamod_rows": dm.height,
            "by_state": {r[0]: r[1] for r in dm.group_by("state").len().iter_rows()},
            "rows_with_packet_id": int(dm["packet_id"].is_not_null().sum()),
            "distinct_linked_packets_found_in_capture": int(linked)}


def evaluate_fold(train, test, feats: list[str], seed: int = 0) -> dict:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score, roc_auc_score

    Xtr, ytr = train.select(feats).to_numpy(), train["label"].to_numpy()
    Xte, yte = test.select(feats).to_numpy(), test["label"].to_numpy()
    clf = RandomForestClassifier(n_estimators=300, min_samples_leaf=2, class_weight="balanced",
                                 n_jobs=6, random_state=seed).fit(Xtr, ytr)
    sc = clf.predict_proba(Xte)[:, 1]
    # threshold chosen on TRAIN windows only: max F1 on out-of-bag-free train scores would be
    # optimistic, so we use the fixed 0.5 probability threshold
    pred = (sc >= 0.5).astype(int)
    return {"scores": sc, "pred": pred,
            "window": {"n_test": int(len(yte)), "positives": int(yte.sum()),
                       "roc_auc": float(roc_auc_score(yte, sc)) if 0 < yte.sum() < len(yte) else None,
                       "pr_auc": float(average_precision_score(yte, sc)) if yte.sum() else None,
                       "precision": float(precision_score(yte, pred, zero_division=0)),
                       "recall": float(recall_score(yte, pred, zero_division=0)),
                       "f1": float(f1_score(yte, pred, zero_division=0))},
            "importance": dict(sorted(zip(feats, clf.feature_importances_.round(4).tolist()), key=lambda kv: -kv[1]))}


def session_detection(test, pred: np.ndarray, sess) -> dict:
    """A session is detected if >= 1 of its windows is flagged. Broken down by metadata."""
    import polars as pl

    df = test.select("dataset", "session_idx", "label").with_columns(pl.Series("pred", pred))
    det = (df.filter(pl.col("label") == 1).group_by("dataset", "session_idx")
           .agg(pl.col("pred").max().alias("detected"), pl.len().alias("windows")))
    det = det.join(sess, on=["dataset", "session_idx"], how="left")
    out = {"sessions": det.height, "detected_rate": float(det["detected"].mean()) if det.height else None,
           "by_coordinated": {str(k): float(v) for k, v in det.group_by("coordinated").agg(pl.col("detected").mean()).iter_rows()},
           "by_target_state": {k: float(v) for k, v in det.group_by("target_state").agg(pl.col("detected").mean()).iter_rows()},
           "by_step_types": {k: float(v) for k, v in det.group_by("step_types").agg(pl.col("detected").mean()).iter_rows()}}
    return out


def main(argv: list[str] | None = None) -> int:
    import polars as pl

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", required=True, help=".../data/dataset/unzipped")
    ap.add_argument("--output-dir", default="reports/gridstrat")
    ap.add_argument("--normal-train-frac", type=float, default=0.6)
    a = ap.parse_args(argv)
    out = Path(a.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    t_start = time.time()
    dirs = dataset_dirs(Path(a.root))

    inventory, frames, sess_frames = {}, [], []
    for name, d in dirs.items():
        sess = sessions(d)
        feats, t0 = window_features(d)
        feats = label_windows(feats, sess, t0).with_columns(pl.lit(name).alias("dataset"))
        model = sess["model_name"][0] if sess.height else "none (normal operation)"
        feats = feats.with_columns(pl.lit(model).alias("model_name"))
        frames.append(feats)
        if sess.height:
            sess_frames.append(sess.with_row_index("session_idx").with_columns(
                pl.col("session_idx").cast(pl.Int32), pl.lit(name).alias("dataset"))
                .select("dataset", "session_idx", "model_name", "coordinated", "target_state", "step_types",
                        ((pl.col("act_end") - pl.col("act_start")).dt.total_seconds()).alias("active_s")))
        inventory[name] = {
            "model_name": model, "windows": feats.height, "hours": round(feats.height * WINDOW_S / 3600, 2),
            "packets": int(feats["n_packets"].sum()), "sessions": sess.height,
            "coordinated_sessions": int(sess["coordinated"].sum()) if sess.height else 0,
            "target_states": dict(sess.group_by("target_state").len().iter_rows()) if sess.height else {},
            "step_type_sets": dict(sess.group_by("step_types").len().iter_rows()) if sess.height else {},
            "windows_positive": int((feats["label"] == 1).sum()), "windows_excluded": int((feats["label"] == -1).sum()),
            "packet_labels": packet_label_summary(d),
        }
        print(f"{name}: {inventory[name]['windows']} windows, {inventory[name]['sessions']} sessions", flush=True)
    W = pl.concat(frames, how="diagonal_relaxed")
    SESS = pl.concat(sess_frames)
    W.write_csv(out / "windows.csv")
    (out / "inventory.json").write_text(json.dumps(inventory, indent=2, default=str), encoding="utf-8")

    # normal operation: time split
    nw = W.filter(pl.col("dataset") == NORMAL).sort("w")
    cut = int(a.normal_train_frac * nw.height)
    normal_train, normal_test = nw[:cut], nw[cut:]
    normal_test_hours = normal_test.height * WINDOW_S / 3600
    attack = W.filter(pl.col("dataset") != NORMAL)
    models = sorted(attack["model_name"].unique().to_list())

    results = {"window_s": WINDOW_S, "guard_s": GUARD_S, "normal_test_hours": round(normal_test_hours, 3),
               "folds": {}, "rules": {}}
    # simple rules (no training): binding inconsistency and Zeek weird events
    for rule, expr in {"ip_with_multiple_macs>0": pl.col("n_ip_multi_mac") > 0,
                       "arp_packets>0": pl.col("n_arp") > 0,
                       "zeek_weird>0": pl.col("n_zeek_weird") > 0}.items():
        r = {}
        for m in models:
            te = attack.filter((pl.col("model_name") == m) & (pl.col("label") >= 0))
            pred = te.select(expr).to_series().cast(pl.Int8).to_numpy()
            y = te["label"].to_numpy()
            fa = int(normal_test.select(expr).to_series().sum())
            r[m] = {"window_recall": float(pred[y == 1].mean()), "window_fpr_in_attack_capture": float(pred[y == 0].mean()),
                    "session": session_detection(te, pred, SESS),
                    "false_alarm_windows_per_hour_normal_test": round(fa / normal_test_hours, 2)}
        results["rules"][rule] = r

    for group, feats in FEATURE_GROUPS.items():
        results["folds"][group] = {}
        for m in models:
            tr = pl.concat([attack.filter((pl.col("model_name") != m) & (pl.col("label") >= 0)), normal_train])
            te_att = attack.filter((pl.col("model_name") == m) & (pl.col("label") >= 0))
            te = pl.concat([te_att, normal_test])
            r = evaluate_fold(tr, te, feats)
            n_att = te_att.height
            pred_normal = r["pred"][n_att:]
            results["folds"][group][m] = {
                "train_windows": tr.height, "train_positive": int(tr["label"].sum()),
                **r["window"],
                "session": session_detection(te_att, r["pred"][:n_att], SESS),
                "false_alarm_windows_per_hour_normal_test": round(float(pred_normal.sum()) / normal_test_hours, 2),
                "importance_top5": dict(list(r["importance"].items())[:5]),
            }
            print(f"[{group}] held-out {m}: AUC {results['folds'][group][m]['roc_auc']} "
                  f"session det {results['folds'][group][m]['session']['detected_rate']:.2f} "
                  f"FA/h {results['folds'][group][m]['false_alarm_windows_per_hour_normal_test']}", flush=True)
    results["seconds"] = round(time.time() - t_start, 1)
    (out / "results.json").write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
