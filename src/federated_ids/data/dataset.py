"""Load the fixed CICIoT2023 split arrays and the label task used by an experiment."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from federated_ids.config import REPO_ROOT, data_config
from federated_ids.data.ciciot import CATEGORIES, CLASS34, FEATURES

TASKS = ("category", "class34", "binary")


@dataclass
class SplitData:
    X: np.ndarray            # raw features restricted to the chosen feature set (float64)
    y: np.ndarray            # labels for the task (int64)
    y34: np.ndarray
    file_id: np.ndarray
    row: np.ndarray
    seen_in_train: np.ndarray
    conflict_with_train: np.ndarray


def task_labels(task: str) -> list[str]:
    return {"category": CATEGORIES, "class34": CLASS34, "binary": ["Benign", "Attack"]}[task]


def labels_for(task: str, y34: np.ndarray, y8: np.ndarray) -> np.ndarray:
    if task == "category":
        return y8.astype(np.int64)
    if task == "class34":
        return y34.astype(np.int64)
    if task == "binary":
        return (y8 != CATEGORIES.index("Benign")).astype(np.int64)
    raise ValueError(task)


def benign_index(task: str) -> int:
    return task_labels(task).index("Benign")


def feature_indices(features: list[str]) -> list[int]:
    return [FEATURES.index(f) for f in features]


def load_split(split: str, features: list[str], task: str, cfg: dict | None = None) -> SplitData:
    cfg = cfg or data_config()
    d = np.load(Path(cfg["work_dir"]) / "splits" / cfg["split"]["name"] / f"{split}.npz")
    return SplitData(X=d["X"][:, feature_indices(features)], y=labels_for(task, d["y34"], d["y8"]),
                     y34=d["y34"], file_id=d["file_id"], row=d["row"], seen_in_train=d["seen_in_train"],
                     conflict_with_train=d["conflict_with_train"])


def split_manifest(cfg: dict | None = None) -> dict:
    cfg = cfg or data_config()
    p = REPO_ROOT / "artifacts" / "splits" / cfg["split"]["name"] / "split_manifest.json"
    return json.loads(p.read_text(encoding="utf-8"))
