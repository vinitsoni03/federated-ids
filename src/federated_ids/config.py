"""Config loading and shared paths."""
from __future__ import annotations

import os
from pathlib import Path

import yaml

# two levels up from src/federated_ids/ = the repo folder
REPO_ROOT = Path(__file__).resolve().parents[2]


# relative paths are taken from the repo root, so scripts work from any folder
def load_yaml(path: str | Path) -> dict:
    p = Path(path)
    if not p.is_absolute():
        p = REPO_ROOT / p
    return yaml.safe_load(p.read_text(encoding="utf-8"))


def data_config(path: str | Path = "configs/data.yaml") -> dict:
    cfg = load_yaml(path)
    # the big data lives outside the repo (D: drive), env var lets the VM point somewhere else
    cfg["work_dir"] = os.environ.get("FIDS_WORK_DIR", cfg["work_dir"])
    return cfg


def work_dir(cfg: dict | None = None) -> Path:
    return Path((cfg or data_config())["work_dir"])
