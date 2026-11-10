"""CICIoT2023 data-quality checks on the converted Parquet + row-hash arrays.

Three reports (machine-readable JSON/CSV under OUTPUT_DIR):
  1. duplicates   - exact duplicate feature vectors within a file, across files of the same
                    class, and across classes (cross-label conflicts = identical inputs with
                    different labels; these bound achievable accuracy and leak across splits).
  2. semantics    - counts of semantically invalid or suspicious values (Max < Min, AVG outside
                    [Min, Max], Variance != Std^2, flag ratios outside [0, 1], negative IAT,
                    infinite Rate, missing values) and the per-class distribution of `Number`
                    (packets per window; the paper uses 100-packet windows for DDoS/DoS/Mirai
                    and 10-packet windows otherwise, so `Number` may encode the label).
  3. plausibility - per-class means of protocol/flag indicators, used to check that the
                    folder-derived label agrees with the traffic it labels.

Duplicate detection uses a 64-bit hash of the 39 feature values (see ciciot.hash_matrix);
with 46.8M rows the expected number of hash collisions is ~6e-5, i.e. negligible.

Usage:
    python -m federated_ids.data.ciciot_checks --work-dir D:/federated-ids-work --output-dir reports/data
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

from federated_ids.data.ciciot import CATEGORIES, CLASS34, FEATURES

FLAG_COLS = ["fin_flag_number", "syn_flag_number", "rst_flag_number", "psh_flag_number",
             "ack_flag_number", "ece_flag_number", "cwr_flag_number"]
INDICATOR_COLS = ["HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC", "TCP", "UDP", "DHCP",
                  "ARP", "ICMP", "IGMP", "IPv", "LLC"]
PLAUSIBILITY_COLS = ["TCP", "UDP", "ICMP", "ARP", "HTTP", "HTTPS", "DNS", "syn_flag_number",
                     "ack_flag_number", "rst_flag_number", "psh_flag_number", "fin_flag_number",
                     "Protocol Type", "Number", "Rate", "Tot size", "IAT"]


def load_manifest(work_dir: Path) -> dict:
    return json.loads((work_dir / "processed" / "ciciot2023" / "file_manifest.json").read_text(encoding="utf-8"))


def duplicate_report(hashes: np.ndarray, file_ids: np.ndarray, file_class: np.ndarray,
                     file_cat: np.ndarray, class_names: list[str]) -> dict:
    """Exact-duplicate structure. file_class/file_cat map file_id -> class index."""
    n = len(hashes)
    order = np.argsort(hashes, kind="stable")
    h = hashes[order]
    f = file_ids[order]
    c = file_class[f]
    k = file_cat[f]
    new_group = np.empty(n, dtype=bool)
    new_group[0] = True
    new_group[1:] = h[1:] != h[:-1]
    gid = np.cumsum(new_group) - 1
    n_groups = int(gid[-1] + 1)
    group_size = np.bincount(gid)

    def n_distinct_per_group(key: np.ndarray) -> np.ndarray:
        # distinct (group, key) pairs per group
        pair = gid.astype(np.int64) * 1_000_000 + key.astype(np.int64)
        up = np.unique(pair)
        return np.bincount(up // 1_000_000, minlength=n_groups)

    files_per_group = n_distinct_per_group(f)
    classes_per_group = n_distinct_per_group(c)
    cats_per_group = n_distinct_per_group(k)

    row_conflict34 = classes_per_group[gid] > 1
    row_conflict8 = cats_per_group[gid] > 1
    per_class = []
    for ci, name in enumerate(class_names):
        m = c == ci
        rows = int(m.sum())
        uniq = int(np.unique(gid[m]).size)
        per_class.append({
            "class34": name, "rows": rows, "unique_vectors": uniq,
            "duplicate_rows": rows - uniq,
            "duplicate_fraction": round((rows - uniq) / rows, 6) if rows else None,
            "rows_whose_vector_also_in_other_class34": int(row_conflict34[m].sum()),
            "rows_whose_vector_also_in_other_category": int(row_conflict8[m].sum()),
        })

    # conflicting class pairs (rows of class a whose vector also occurs in class b)
    conf_groups = np.flatnonzero(classes_per_group > 1)
    pair_counts: dict[str, int] = {}
    if conf_groups.size:
        sel = np.isin(gid, conf_groups)
        g_sel, c_sel = gid[sel], c[sel]
        # unique (group, class) pairs, then every pair of classes within a group
        pairs = np.unique(g_sel.astype(np.int64) * 1_000_000 + c_sel.astype(np.int64))
        pg, pc = pairs // 1_000_000, pairs % 1_000_000
        start = np.flatnonzero(np.r_[True, pg[1:] != pg[:-1]])
        end = np.r_[start[1:], len(pg)]
        for s, e in zip(start, end):
            cl = pc[s:e]
            for i in range(len(cl)):
                for j in range(i + 1, len(cl)):
                    key = f"{class_names[cl[i]]} <-> {class_names[cl[j]]}"
                    pair_counts[key] = pair_counts.get(key, 0) + 1
    top_pairs = sorted(pair_counts.items(), key=lambda kv: -kv[1])[:30]

    return {
        "rows": int(n),
        "unique_vectors": n_groups,
        "duplicate_rows_total": int(n - n_groups),
        "rows_in_groups_spanning_multiple_files": int((files_per_group[gid] > 1).sum()),
        "groups_spanning_multiple_files": int((files_per_group > 1).sum()),
        "rows_in_cross_class34_conflicts": int(row_conflict34.sum()),
        "groups_cross_class34_conflicts": int((classes_per_group > 1).sum()),
        "rows_in_cross_category_conflicts": int(row_conflict8.sum()),
        "groups_cross_category_conflicts": int((cats_per_group > 1).sum()),
        "largest_group_size": int(group_size.max()),
        "top_conflicting_class34_pairs_by_shared_vectors": [{"pair": p, "shared_vectors": v} for p, v in top_pairs],
        "per_class34": per_class,
    }


def semantic_report(parquet_dir: Path, manifest: dict) -> dict:
    import polars as pl

    lf = pl.scan_parquet(str(parquet_dir / "*.parquet"))
    fmap = pl.DataFrame({"file_id": [m["file_id"] for m in manifest["files"]],
                         "class34": [m["class34"] for m in manifest["files"]]},
                        schema={"file_id": pl.Int16, "class34": pl.String})
    lf = lf.join(fmap.lazy(), on="file_id", how="left")
    col = pl.col
    tol = 1e-6
    checks = {
        "max_lt_min": (col("Max") < col("Min")),
        "avg_lt_min": (col("AVG") < col("Min") - tol),
        "avg_gt_max": (col("AVG") > col("Max") + tol),
        "variance_ne_std_squared_rel_gt_1pct": (
            ((col("Variance") - col("Std") ** 2).abs() / (col("Std") ** 2).clip(lower_bound=1.0)) > 0.01),
        "tot_size_ne_avg": ((col("Tot size") - col("AVG")).abs() > 1e-6 * col("AVG").abs().clip(lower_bound=1.0)),
        "tot_sum_ne_avg_times_number_rel_gt_1pct": (
            ((col("Tot sum") - col("AVG") * col("Number")).abs() / col("Tot sum").clip(lower_bound=1.0)) > 0.01),
        "flag_ratio_outside_0_1": pl.any_horizontal([(col(c) < 0) | (col(c) > 1) for c in FLAG_COLS + INDICATOR_COLS]),
        "iat_negative": col("IAT") < 0,
        "rate_pos_inf": col("Rate") == float("inf"),
        "any_missing": pl.any_horizontal([col(c).is_null() | col(c).is_nan() for c in FEATURES]),
        "max_gt_1514_bytes": col("Max") > 1514,
    }
    agg = lf.select([e.fill_null(False).sum().alias(k) for k, e in checks.items()] + [pl.len().alias("rows")]).collect(engine="streaming")
    totals = {k: int(v) for k, v in agg.row(0, named=True).items()}
    by_class = (lf.group_by("class34").agg([e.fill_null(False).sum().alias(k) for k, e in checks.items()]
                                          + [pl.len().alias("rows")]).sort("class34").collect(engine="streaming"))
    number_dist = (lf.group_by("class34", "Number").len().collect(engine="streaming")
                   .sort(["class34", "len"], descending=[False, True]))
    number_summary = (lf.group_by("class34").agg(
        col("Number").min().alias("min"), col("Number").median().alias("median"),
        col("Number").max().alias("max"), (col("Number") == 100).mean().alias("share_eq_100"),
        (col("Number") == 10).mean().alias("share_eq_10")).sort("class34").collect(engine="streaming"))
    return {"totals": totals, "by_class34": by_class.to_dicts(), "number_by_class34": number_summary.to_dicts(),
            "number_top_values": number_dist.group_by("class34", maintain_order=True).head(5).to_dicts()}


def plausibility_report(parquet_dir: Path, manifest: dict):
    import polars as pl

    lf = pl.scan_parquet(str(parquet_dir / "*.parquet"))
    fmap = pl.DataFrame({"file_id": [m["file_id"] for m in manifest["files"]],
                         "class34": [m["class34"] for m in manifest["files"]],
                         "category": [m["category"] for m in manifest["files"]]},
                        schema={"file_id": pl.Int16, "class34": pl.String, "category": pl.String})
    lf = lf.join(fmap.lazy(), on="file_id", how="left").with_columns(
        pl.col("Rate").replace(float("inf"), None))
    exprs = [pl.col(c).mean().alias(c) for c in PLAUSIBILITY_COLS]
    return (lf.group_by("category", "class34").agg(exprs + [pl.len().alias("rows")])
            .sort("category", "class34").collect(engine="streaming"))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--work-dir", required=True)
    p.add_argument("--output-dir", default="reports/data")
    a = p.parse_args(argv)
    work = Path(a.work_dir)
    out = Path(a.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    hdir = work / "processed" / "ciciot2023"
    man = load_manifest(work)

    c34_index = {n: i for i, n in enumerate(CLASS34)}
    cat_index = {n: i for i, n in enumerate(CATEGORIES)}
    file_class = np.array([c34_index[m["class34"]] for m in man["files"]], dtype=np.int16)
    file_cat = np.array([cat_index[m["category"]] for m in man["files"]], dtype=np.int16)
    hashes = np.load(hdir / "row_hash.npy")
    fids = np.load(hdir / "row_file_id.npy")
    dup = duplicate_report(hashes, fids, file_class, file_cat, CLASS34)
    del hashes, fids
    (out / "ciciot_duplicates.json").write_text(json.dumps(dup, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in dup.items() if k not in ("per_class34",)}, indent=2))

    sem = semantic_report(hdir / "parquet", man)
    (out / "ciciot_semantic_checks.json").write_text(json.dumps(sem, indent=2), encoding="utf-8")
    print(json.dumps(sem["totals"], indent=2))

    pla = plausibility_report(hdir / "parquet", man)
    pla.write_csv(out / "ciciot_label_plausibility.csv", float_precision=4)
    print(pla)
    return 0


if __name__ == "__main__":
    sys.exit(main())
