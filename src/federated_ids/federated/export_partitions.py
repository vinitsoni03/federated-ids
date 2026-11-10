"""Export per-client federated datasets for real (multi-process / multi-machine) deployments.

Writes, for one (task, partition, alpha, seed, n_clients) setting:
  client_<i>.npz      - client i's PREPROCESSED training partition (float32 X, int64 y), exactly
                        the rows the in-process simulator gives client i (same make_partition call)
  server_eval.npz     - preprocessed validation and test sets (+ seen_in_train flags), for the server
  preprocessor.json   - the train-only fitted preprocessor (for the endpoint and for audit)
  manifest.json       - settings, row counts, label histograms and SHA-256 of every file

Each client then loads only its own small file instead of the whole dataset (the earlier
Flower run ran out of memory because every client process loaded all splits), and only these
derived files - never the raw CICIoT2023 CSVs - need to be copied to other machines.

Usage:
    python -m federated_ids.federated.export_partitions --task category --partition iid --n-clients 10
        --seed 0 --out D:/federated-ids-work/flower_data/category_iid_s0
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from federated_ids.config import data_config
from federated_ids.data.dataset import task_labels
from federated_ids.experiments.centralized import prepare
from federated_ids.federated.partition import make_partition

FEATURE_SET = "window_invariant"


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def export(task: str, partition: str, alpha: float | None, n_clients: int, seed: int, out: Path) -> dict:
    features, pre, data = prepare({"task": task, "feature_set": FEATURE_SET}, data_config())
    ytr = data["train"]["y"]
    parts = make_partition(partition, ytr, n_clients, seed, alpha if partition == "dirichlet" else None, 100)
    out.mkdir(parents=True, exist_ok=True)
    K = len(task_labels(task))
    files = {}
    for i, idx in enumerate(parts):
        p = out / f"client_{i}.npz"
        np.savez_compressed(p, X=data["train"]["Xp"][idx].astype(np.float32), y=ytr[idx].astype(np.int64))
        files[p.name] = {"rows": int(len(idx)), "label_histogram": np.bincount(ytr[idx], minlength=K).tolist()}
    p = out / "server_eval.npz"
    np.savez_compressed(p, Xval=data["val"]["Xp"].astype(np.float32), yval=data["val"]["y"],
                        Xtest=data["test"]["Xp"].astype(np.float32), ytest=data["test"]["y"],
                        seen_test=data["test"]["seen"], y34_test=data["test"]["y34"])
    files[p.name] = {"val_rows": int(len(data["val"]["y"])), "test_rows": int(len(data["test"]["y"]))}
    pre.to_json(out / "preprocessor.json")
    for name in list(files) + ["preprocessor.json"]:
        files.setdefault(name, {})["sha256"] = sha256(out / name)
    manifest = {"created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "task": task, "class_names": task_labels(task), "feature_set": FEATURE_SET, "features": features,
                "partition": partition, "alpha": alpha, "n_clients": n_clients, "seed": seed,
                "split": data_config()["split"]["name"], "files": files}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--task", default="category")
    ap.add_argument("--partition", default="iid")
    ap.add_argument("--alpha", type=float, default=None)
    ap.add_argument("--n-clients", type=int, default=10)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    m = export(a.task, a.partition, a.alpha, a.n_clients, a.seed, Path(a.out))
    sizes = {k: v["rows"] for k, v in m["files"].items() if "rows" in v}
    print(f"exported {len(sizes)} clients to {a.out}: rows {sizes}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
