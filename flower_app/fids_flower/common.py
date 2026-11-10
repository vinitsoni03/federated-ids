"""Shared pieces of the Flower ServerApp/ClientApp.

Data come from files written by `python -m federated_ids.federated.export_partitions`:
each client loads ONLY its own `client_<partition-id>.npz` (from the SuperNode's `data-dir`
node-config), the server loads `server_eval.npz` (from the `server-data-dir` run-config). The
model and local training are the research package's, so Flower runs are directly comparable
with `federated_ids.federated.simulation`.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

import numpy as np

MODEL = {"hidden": [128, 64], "dropout": 0.1}   # = configs/federated.yaml
CLASS_WEIGHTING = "sqrt_inverse"


@lru_cache(maxsize=2)
def manifest(data_dir: str) -> dict:
    return json.loads((Path(data_dir) / "manifest.json").read_text(encoding="utf-8"))


@lru_cache(maxsize=2)
def client_data(data_dir: str, pid: int) -> tuple[np.ndarray, np.ndarray]:
    d = np.load(Path(data_dir) / f"client_{pid}.npz")
    return d["X"], d["y"]


@lru_cache(maxsize=1)
def server_data(data_dir: str) -> dict:
    d = np.load(Path(data_dir) / "server_eval.npz")
    return {k: d[k] for k in d.files}
