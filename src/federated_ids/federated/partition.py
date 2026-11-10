"""Client partitions of the (fixed) training set: IID and Dirichlet label skew.

Dirichlet(alpha) label skew (Hsu et al., 2019): for every class, the class's rows are split
among clients with proportions drawn from Dir(alpha * 1_K). Small alpha -> strong skew.
"""
from __future__ import annotations

import numpy as np


def iid_partition(n: int, n_clients: int, rng: np.random.Generator) -> list[np.ndarray]:
    return [np.sort(p) for p in np.array_split(rng.permutation(n), n_clients)]


def dirichlet_partition(y: np.ndarray, n_clients: int, alpha: float, rng: np.random.Generator,
                        min_size: int = 100, max_tries: int = 100) -> list[np.ndarray]:
    """Re-draws until every client has >= min_size rows (raises if impossible)."""
    classes = np.unique(y)
    for _ in range(max_tries):
        parts: list[list[np.ndarray]] = [[] for _ in range(n_clients)]
        for c in classes:
            idx = rng.permutation(np.flatnonzero(y == c))
            props = rng.dirichlet(alpha * np.ones(n_clients))
            cuts = (np.cumsum(props)[:-1] * len(idx)).astype(int)
            for k, chunk in enumerate(np.split(idx, cuts)):
                parts[k].append(chunk)
        out = [np.sort(np.concatenate(p)) for p in parts]
        if min(len(p) for p in out) >= min_size:
            return out
    raise ValueError(f"could not draw a Dirichlet({alpha}) partition with min_size={min_size}")


def make_partition(kind: str, y: np.ndarray, n_clients: int, seed: int, alpha: float | None = None,
                   min_size: int = 100) -> list[np.ndarray]:
    rng = np.random.default_rng(seed)
    if kind == "iid":
        return iid_partition(len(y), n_clients, rng)
    if kind == "dirichlet":
        return dirichlet_partition(y, n_clients, float(alpha), rng, min_size)
    raise ValueError(kind)


def partition_stats(parts: list[np.ndarray], y: np.ndarray, n_classes: int) -> dict:
    hist = np.stack([np.bincount(y[p], minlength=n_classes) for p in parts])
    frac = hist / hist.sum(1, keepdims=True)
    glob = np.bincount(y, minlength=n_classes) / len(y)
    # mean total-variation distance between each client's label distribution and the global one
    tv = 0.5 * np.abs(frac - glob).sum(1)
    return {"client_sizes": hist.sum(1).tolist(), "label_histogram": hist.tolist(),
            "classes_per_client": (hist > 0).sum(1).tolist(), "tv_distance_to_global": tv.round(4).tolist(),
            "mean_tv_distance": float(tv.mean())}
