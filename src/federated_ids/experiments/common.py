"""Shared experiment plumbing: run directories, environment capture, evaluation bundle."""
from __future__ import annotations

import json
import os
import platform
import time
from pathlib import Path

import numpy as np

from federated_ids.config import REPO_ROOT
from federated_ids.evaluation.metrics import classification_metrics


def run_dir(name: str) -> Path:
    d = REPO_ROOT / "artifacts" / "runs" / name
    d.mkdir(parents=True, exist_ok=True)
    return d


def environment() -> dict:
    import psutil
    import sklearn
    import torch

    return {"python": platform.python_version(), "platform": platform.platform(),
            "cpu": platform.processor(), "logical_cpus": os.cpu_count(),
            "ram_gb": round(psutil.virtual_memory().total / 2**30, 1),
            "torch": torch.__version__, "torch_threads": torch.get_num_threads(),
            "cuda_available": torch.cuda.is_available(),
            "gpu": torch.cuda.get_device_name(0) if torch.cuda.is_available() else None,
            "cuda_runtime": torch.version.cuda, "numpy": np.__version__, "sklearn": sklearn.__version__}


def peak_rss_mb() -> float:
    import psutil

    mi = psutil.Process().memory_info()
    return round(getattr(mi, "peak_wset", mi.rss) / 2**20, 1)


def write_json(path: Path, obj) -> None:
    path.write_text(json.dumps(obj, indent=2, default=float), encoding="utf-8")


def evaluate_bundle(predict_proba, data: dict, class_names: list[str], benign: int) -> dict:
    """data: {"val": SplitData, "test": SplitData}; predict_proba takes PREPROCESSED X."""
    out = {}
    for name, d in data.items():
        t = time.time()
        proba = predict_proba(d["Xp"])
        dt = time.time() - t
        pred = proba.argmax(1)
        out[name] = classification_metrics(d["y"], pred, class_names, benign, proba)
        out[name]["inference_seconds"] = round(dt, 3)
        out[name]["inference_us_per_row"] = round(1e6 * dt / max(len(pred), 1), 3)
        if name == "test":
            m = ~d["seen"]
            out["test_unseen"] = classification_metrics(d["y"][m], pred[m], class_names, benign, proba[m])
            out["test_unseen"]["note"] = "test rows whose exact feature vector never occurs in the train pool"
    return out
