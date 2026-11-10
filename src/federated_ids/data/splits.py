"""Leakage-aware, deterministic train/val/test split of CICIoT2023 (fixed holdout).

Unit of splitting, per class (class34):
  * >= `min_files_for_file_split` files -> whole files are assigned to one split
    (capture-level separation; no file contributes rows to two splits);
  * fewer files -> each file is cut into contiguous row blocks
    [0, 70%) train | [70%, 85%) val | [85%, 100%) test, with `purge_frac` of rows dropped at
    each boundary. Rows are time-ordered within a file (checked in the audit), so this is a
    time-aware split; it is still weaker than file-level separation (same capture session).

Then, inside each split: exact duplicate feature vectors are dropped (first occurrence kept),
each class is down-sampled to a cap with a seeded RNG, and the selected rows are written as
.npz arrays. Val/test rows whose exact feature vector also occurs anywhere in the train pool
are flagged (`seen_in_train`), and those whose vector occurs in the train pool under a
different category are flagged (`conflict_with_train`), so metrics can be reported on the
"unseen" subset as a leakage check.

Usage:
    python -m federated_ids.data.splits [--config configs/data.yaml] [--manifest-dir artifacts/splits]
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from federated_ids.config import REPO_ROOT, data_config
from federated_ids.data.ciciot import CATEGORIES, CLASS34, CLASS34_TO_CAT, FEATURES

SPLITS = ("train", "val", "test")


def assign_files(file_ids: list[int], rows: list[int], val_frac: float, test_frac: float,
                 rng: np.random.Generator) -> dict[int, str]:
    """Assign whole files to splits. Shuffled order; test filled first, then val, rest train.
    Guarantees >= 1 file in each split when len(file_ids) >= 3."""
    if len(file_ids) < 3:
        raise ValueError("file-level split needs at least 3 files")
    order = rng.permutation(len(file_ids))
    total = float(sum(rows))
    out: dict[int, str] = {}
    acc = {"test": 0, "val": 0}
    for i in order:
        fid = file_ids[i]
        if acc["test"] < test_frac * total or not any(v == "test" for v in out.values()):
            out[fid] = "test"
            acc["test"] += rows[i]
        elif acc["val"] < val_frac * total or not any(v == "val" for v in out.values()):
            out[fid] = "val"
            acc["val"] += rows[i]
        else:
            out[fid] = "train"
    if "train" not in out.values():  # tiny classes: move one val file to train
        moved = next(f for f in reversed([file_ids[i] for i in order]) if out[f] == "val")
        if sum(1 for v in out.values() if v == "val") > 1:
            out[moved] = "train"
        else:
            moved = next(f for f in reversed([file_ids[i] for i in order]) if out[f] == "test")
            out[moved] = "train"
    return out


def block_ranges(n: int, val_frac: float, test_frac: float, purge_frac: float,
                 purge_min: int) -> dict[str, tuple[int, int]]:
    """Contiguous [start, end) row ranges for train/val/test with purged gaps between them."""
    gap = max(purge_min, int(round(purge_frac * n)))
    a = int(round((1 - val_frac - test_frac) * n))
    b = int(round((1 - test_frac) * n))
    r = {"train": (0, max(0, a - gap)), "val": (min(n, a + gap), max(0, b - gap)), "test": (min(n, b + gap), n)}
    for k, (s, e) in r.items():
        if e <= s:
            raise ValueError(f"file with {n} rows too small for a block split ({k} empty)")
    return r


def plan_split(manifest_files: list[dict], cfg: dict) -> dict:
    """Return per-file plan: {file_id: {split: (start, end)}} plus the method per class."""
    s = cfg["split"]
    rng = np.random.default_rng(s["seed"])
    by_class: dict[str, list[dict]] = {}
    for f in manifest_files:
        by_class.setdefault(f["class34"], []).append(f)
    plan: dict[int, dict[str, tuple[int, int]]] = {}
    method: dict[str, str] = {}
    for c34 in sorted(by_class):
        files = sorted(by_class[c34], key=lambda f: f["file_id"])
        if len(files) >= s["min_files_for_file_split"]:
            method[c34] = "file"
            assign = assign_files([f["file_id"] for f in files], [f["rows"] for f in files],
                                  s["val_frac"], s["test_frac"], rng)
            for f in files:
                plan[f["file_id"]] = {assign[f["file_id"]]: (0, f["rows"])}
        else:
            method[c34] = "block"
            for f in files:
                plan[f["file_id"]] = block_ranges(f["rows"], s["val_frac"], s["test_frac"],
                                                  s["purge_frac"], s["purge_min_rows"])
    return {"plan": plan, "method": method}


def pool_indices(plan: dict, offsets: np.ndarray, split: str) -> np.ndarray:
    """Global row indices (into the concatenated row arrays) belonging to `split`."""
    parts = [np.arange(offsets[fid] + s, offsets[fid] + e, dtype=np.int64)
             for fid, rng in sorted(plan.items()) for k, (s, e) in rng.items() if k == split]
    return np.concatenate(parts) if parts else np.empty(0, dtype=np.int64)


def dedup_first(idx: np.ndarray, hashes: np.ndarray) -> np.ndarray:
    """Keep the first occurrence (in idx order) of each distinct feature vector."""
    _, first = np.unique(hashes[idx], return_index=True)
    return idx[np.sort(first)]


def pair_key(h: np.ndarray, label: np.ndarray) -> np.ndarray:
    """One 64-bit key per (row hash, label) pair."""
    from federated_ids.data.ciciot import _splitmix64

    with np.errstate(over="ignore"):
        return _splitmix64(h ^ _splitmix64(label.astype(np.uint64) + np.uint64(0xA5A5)))


def build(cfg: dict, manifest_dir: Path) -> dict:
    import polars as pl

    s = cfg["split"]
    work = Path(cfg["work_dir"])
    hdir = work / "processed" / "ciciot2023"
    man = json.loads((hdir / "file_manifest.json").read_text(encoding="utf-8"))
    files = man["files"]
    rows = np.array([f["rows"] for f in files], dtype=np.int64)
    offsets = np.concatenate([[0], np.cumsum(rows)[:-1]])
    hashes = np.load(hdir / "row_hash.npy")
    fids = np.load(hdir / "row_file_id.npy")
    c34_index = {n: i for i, n in enumerate(CLASS34)}
    cat_index = {n: i for i, n in enumerate(CATEGORIES)}
    file_c34 = np.array([c34_index[f["class34"]] for f in files], dtype=np.int16)
    file_cat = np.array([cat_index[f["category"]] for f in files], dtype=np.int16)

    p = plan_split(files, cfg)
    plan = p["plan"]
    rng = np.random.default_rng(s["seed"] + 1)
    caps = {"train": s["cap_train"], "val": s["cap_val"], "test": s["cap_test"]}
    out_dir = work / "splits" / s["name"]
    out_dir.mkdir(parents=True, exist_ok=True)

    pools = {k: pool_indices(plan, offsets, k) for k in SPLITS}
    # sanity: pools are disjoint
    for a in range(3):
        for b in range(a + 1, 3):
            assert np.intersect1d(pools[SPLITS[a]], pools[SPLITS[b]]).size == 0
    np.save(out_dir / "test_pool_idx.npy", pools["test"])

    train_hash_sorted = np.unique(hashes[pools["train"]])
    # (vector, category) keys present in the train pool, for cross-label conflict flags
    train_pair_keys = np.unique(pair_key(hashes[pools["train"]], file_cat[fids[pools["train"]]]))

    counts: dict[str, dict] = {}
    selected: dict[str, np.ndarray] = {}
    for split in SPLITS:
        idx = pools[split]
        sel_parts = []
        counts[split] = {}
        cls = file_c34[fids[idx]]
        for ci, name in enumerate(CLASS34):
            ci_idx = idx[cls == ci]
            n_pool = ci_idx.size
            if s["dedup_within_split"] and n_pool:
                ci_idx = dedup_first(ci_idx, hashes)
            n_dedup = ci_idx.size
            if n_dedup > caps[split]:
                ci_idx = np.sort(rng.choice(ci_idx, size=caps[split], replace=False))
            sel_parts.append(ci_idx)
            counts[split][name] = {"pool_rows": int(n_pool), "after_dedup": int(n_dedup),
                                   "sampled": int(ci_idx.size)}
        selected[split] = np.sort(np.concatenate(sel_parts))

    # read selected rows from parquet, file by file
    for split in SPLITS:
        idx = selected[split]
        f_of = fids[idx]
        r_of = idx - offsets[f_of]
        X = np.empty((idx.size, len(FEATURES)), dtype=np.float64)
        pos = 0
        for fid in np.unique(f_of):
            m = f_of == fid
            rows_needed = r_of[m]
            df = pl.read_parquet(hdir / "parquet" / f"{fid:03d}.parquet", columns=FEATURES)
            X[pos:pos + m.sum()] = df.to_numpy()[rows_needed]
            pos += m.sum()
        # order of X follows sorted (fid, row) == sorted idx since offsets are monotone
        h = hashes[idx]
        y34 = file_c34[f_of]
        y8 = file_cat[f_of]
        seen = np.isin(h, train_hash_sorted) if split != "train" else np.ones(idx.size, dtype=bool)
        if split != "train":
            # vector seen in train, but never with this category
            conflict = seen & ~np.isin(pair_key(h, y8), train_pair_keys)
        else:
            conflict = np.zeros(idx.size, dtype=bool)
        np.savez(out_dir / f"{split}.npz", X=X, y34=y34, y8=y8, file_id=f_of.astype(np.int16),
                 row=r_of.astype(np.int32), row_hash=h, seen_in_train=seen, conflict_with_train=conflict)
        counts[split]["_total"] = {"sampled": int(idx.size), "seen_in_train": int(seen.sum()) if split != "train" else None,
                                   "conflict_with_train": int(conflict.sum()) if split != "train" else None}

    file_plan = [{"file_id": f["file_id"], "rel_path": f["rel_path"], "class34": f["class34"],
                  "method": p["method"][f["class34"]],
                  "ranges": {k: list(v) for k, v in plan[f["file_id"]].items()}} for f in files]
    manifest = {
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "name": s["name"], "config": cfg, "class34": CLASS34, "categories": CATEGORIES,
        "class34_to_category": CLASS34_TO_CAT, "features": FEATURES,
        "split_method_by_class34": p["method"], "pool_rows": {k: int(v.size) for k, v in pools.items()},
        "counts": counts, "files": file_plan, "arrays_dir": str(out_dir),
    }
    md = manifest_dir / s["name"]
    md.mkdir(parents=True, exist_ok=True)
    (md / "split_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", default="configs/data.yaml")
    ap.add_argument("--manifest-dir", default=str(REPO_ROOT / "artifacts" / "splits"))
    a = ap.parse_args(argv)
    t0 = time.time()
    m = build(data_config(a.config), Path(a.manifest_dir))
    print(json.dumps(m["pool_rows"]), {k: m["counts"][k]["_total"] for k in SPLITS})
    print(f"done in {time.time() - t0:.0f}s; arrays in {m['arrays_dir']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
