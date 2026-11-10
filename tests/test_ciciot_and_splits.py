"""Label mapping, row hashing, split logic and leakage checks.

The last group of tests checks the REAL split artifacts and is skipped when they have not
been built (python -m federated_ids.data.splits)."""
from pathlib import Path

import numpy as np
import pytest

from federated_ids.data.ciciot import CATEGORIES, CLASS34, CLASS34_TO_CAT, FOLDER_MAP, hash_matrix, label_for_folder
from federated_ids.data.splits import assign_files, block_ranges, dedup_first, plan_split, pool_indices


def test_label_map_matches_paper_taxonomy():
    assert len(FOLDER_MAP) == 34 and len(CLASS34) == 34
    counts = {c: sum(1 for v in CLASS34_TO_CAT.values() if v == c) for c in CATEGORIES}
    # Neto et al. (2023): DDoS 12, DoS 4, Recon 5, Web 6, BruteForce 1, Spoofing 2, Mirai 3 (+ Benign)
    assert counts == {"Benign": 1, "DDoS": 12, "DoS": 4, "Recon": 5, "Web": 6, "BruteForce": 1,
                      "Spoofing": 2, "Mirai": 3}
    with pytest.raises(KeyError):
        label_for_folder("SomethingElse")


def test_hash_matrix_equalities():
    a = np.array([[0.0, np.nan, 1.5], [-0.0, float("nan"), 1.5], [1.5, np.nan, 0.0], [0.0, np.nan, 1.5000001]])
    h = hash_matrix(a)
    assert h[0] == h[1]          # -0.0 == 0.0, NaN == NaN
    assert h[0] != h[2]          # column order matters
    assert h[0] != h[3]
    assert np.array_equal(h, hash_matrix(a))  # deterministic


def test_assign_files_disjoint_and_deterministic():
    fids, rows = list(range(10)), [100] * 10
    a1 = assign_files(fids, rows, 0.15, 0.15, np.random.default_rng(1))
    a2 = assign_files(fids, rows, 0.15, 0.15, np.random.default_rng(1))
    assert a1 == a2 and set(a1) == set(fids)
    assert {"train", "val", "test"} == set(a1.values())
    a3 = assign_files([0, 1, 2], [5, 5, 5], 0.15, 0.15, np.random.default_rng(0))
    assert sorted(a3.values()) == ["test", "train", "val"]


def test_block_ranges_disjoint_with_gap():
    r = block_ranges(10_000, 0.15, 0.15, 0.005, 10)
    assert r["train"][0] == 0 and r["test"][1] == 10_000
    assert r["train"][1] < r["val"][0] and r["val"][1] < r["test"][0]
    assert r["val"][0] - r["train"][1] >= 2 * 50  # purge gap on both sides of the boundary
    with pytest.raises(ValueError):
        block_ranges(20, 0.15, 0.15, 0.005, 10)


def test_plan_and_pools_have_no_overlap():
    files = [{"file_id": i, "class34": "A", "rows": 1000} for i in range(5)] + \
            [{"file_id": 5, "class34": "B", "rows": 3000}]
    cfg = {"split": {"seed": 0, "min_files_for_file_split": 3, "val_frac": 0.15, "test_frac": 0.15,
                     "purge_frac": 0.005, "purge_min_rows": 10}}
    p = plan_split(files, cfg)
    assert p["method"] == {"A": "file", "B": "block"}
    for fid in range(5):
        assert len(p["plan"][fid]) == 1  # a whole file goes to exactly one split
    offsets = np.array([0, 1000, 2000, 3000, 4000, 5000])
    pools = {k: pool_indices(p["plan"], offsets, k) for k in ("train", "val", "test")}
    allp = np.concatenate(list(pools.values()))
    assert len(np.unique(allp)) == len(allp)


def test_dedup_first_keeps_first_occurrence():
    h = np.array([5, 7, 5, 9, 7], dtype=np.uint64)
    assert dedup_first(np.arange(5), h).tolist() == [0, 1, 3]


# ---- leakage checks on the real, built split ----
def _split_dir():
    from federated_ids.config import data_config

    cfg = data_config()
    d = Path(cfg["work_dir"]) / "splits" / cfg["split"]["name"]
    return d if (d / "train.npz").exists() else None


real = pytest.mark.skipif(_split_dir() is None, reason="split artifacts not built")


@real
def test_real_split_no_row_in_two_splits_and_no_file_leak():
    from federated_ids.data.dataset import split_manifest

    d = _split_dir()
    S = {k: np.load(d / f"{k}.npz") for k in ("train", "val", "test")}
    keys = {k: set(zip(S[k]["file_id"].tolist(), S[k]["row"].tolist())) for k in S}
    assert not keys["train"] & keys["test"] and not keys["train"] & keys["val"] and not keys["val"] & keys["test"]
    man = split_manifest()
    file_method = {f["file_id"]: f["method"] for f in man["files"]}
    files_in = {k: set(S[k]["file_id"].tolist()) for k in S}
    for fid, meth in file_method.items():
        if meth == "file":
            assert sum(fid in files_in[k] for k in S) <= 1, f"file {fid} leaks across splits"
    # block-split files: row ranges of different splits never overlap
    for f in man["files"]:
        if f["method"] == "block":
            r = f["ranges"]
            assert r["train"][1] <= r["val"][0] and r["val"][1] <= r["test"][0]


@real
def test_real_split_dedup_and_seen_flags():
    d = _split_dir()
    tr, te = np.load(d / "train.npz"), np.load(d / "test.npz")
    # no duplicate feature vector within a class inside a split
    for S in (tr, te):
        with np.errstate(over="ignore"):
            key = S["row_hash"] ^ (S["y34"].astype(np.uint64) * np.uint64(0x9E3779B97F4A7C15))
        assert len(np.unique(key)) == len(key)
    # every test vector that occurs in the train SAMPLE must be flagged as seen in the train POOL
    in_sample = np.isin(te["row_hash"], tr["row_hash"])
    assert te["seen_in_train"][in_sample].all()
