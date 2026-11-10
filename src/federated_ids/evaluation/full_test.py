"""Evaluate a fitted predictor on the ENTIRE held-out test pool (all rows of every test file /
test block, duplicates included, natural class prior), streaming one file at a time.

This complements the capped, de-duplicated test sample: the sample gives balanced per-class
estimates; the full pool shows behaviour under the dataset's real class imbalance
(e.g. benign FPR over all benign test windows).
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable

import numpy as np

from federated_ids.data.ciciot import CATEGORIES, CLASS34
from federated_ids.data.dataset import feature_indices, labels_for


def iter_test_pool(cfg: dict, manifest: dict, features: list[str]):
    import polars as pl

    hdir = Path(cfg["work_dir"]) / "processed" / "ciciot2023" / "parquet"
    cols = [manifest["features"][i] for i in feature_indices(features)]
    c34 = {n: i for i, n in enumerate(CLASS34)}
    cat = {n: i for i, n in enumerate(CATEGORIES)}
    for f in manifest["files"]:
        rng = f["ranges"].get("test")
        if not rng:
            continue
        s, e = rng
        df = pl.read_parquet(hdir / f"{f['file_id']:03d}.parquet", columns=cols)
        X = df.to_numpy()[s:e]
        n = X.shape[0]
        y34 = np.full(n, c34[f["class34"]], dtype=np.int16)
        y8 = np.full(n, cat[manifest["class34_to_category"][f["class34"]]], dtype=np.int16)
        yield X, y34, y8


def predict_full_test(cfg: dict, manifest: dict, features: list[str], task: str,
                      predict: Callable[[np.ndarray], np.ndarray]) -> tuple[np.ndarray, np.ndarray]:
    """predict: raw-feature matrix -> predicted label indices."""
    ys, ps = [], []
    for X, y34, y8 in iter_test_pool(cfg, manifest, features):
        ys.append(labels_for(task, y34, y8).astype(np.int8 if task != "class34" else np.int16))
        ps.append(predict(X).astype(ys[-1].dtype))
    return np.concatenate(ys), np.concatenate(ps)
