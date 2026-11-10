"""Package a trained run (simulator or Flower) into a model bundle for `serving/app.py`.

    python scripts/package_model.py --run artifacts/runs/<run> --data-dir <export_partitions dir> --out <bundle dir>

The bundle holds model.pt, preprocessor.json (copied from the exported data, i.e. the one the
clients trained with) and model_meta.json (features, classes, architecture, provenance + SHA-256).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

MODEL = {"hidden": [128, 64], "dropout": 0.1}


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--run", required=True)
    ap.add_argument("--data-dir", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    run, data, out = Path(a.run), Path(a.data_dir), Path(a.out)
    man = json.loads((data / "manifest.json").read_text(encoding="utf-8"))
    out.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(run / "global_model.pt", out / "model.pt")
    shutil.copyfile(data / "preprocessor.json", out / "preprocessor.json")
    metrics = json.loads((run / "metrics.json").read_text(encoding="utf-8"))
    meta = {"task": man["task"], "class_names": man["class_names"], "features": man["features"], **MODEL,
            "source_run": run.name, "trained_with": metrics.get("framework", "federated_ids simulator"),
            "data_manifest": {k: man[k] for k in ("partition", "alpha", "n_clients", "seed", "split")},
            "test_macro_f1": metrics["test"]["macro_f1"], "test_benign_fpr": metrics["test"]["benign_fpr"],
            "sha256": {"model.pt": sha256(out / "model.pt"), "preprocessor.json": sha256(out / "preprocessor.json")}}
    (out / "model_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"bundle written to {out}: {meta['task']}, test macro-F1 {meta['test_macro_f1']:.4f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
