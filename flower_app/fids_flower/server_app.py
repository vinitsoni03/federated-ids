"""Flower ServerApp: FedAvg over all connected SuperNodes; evaluates the global model on the
fixed validation and test sets after every round and writes the same metrics files as the
in-process simulator.

Run-config keys: server-data-dir (folder from export_partitions), out-dir (where run results
go), run-name, num-server-rounds, n-clients, learning-rate, local-epochs, batch-size, device."""
from __future__ import annotations

import csv
import json
import platform
import time
from pathlib import Path

import torch
from flwr.app import ArrayRecord, ConfigRecord, Context, MetricRecord
from flwr.serverapp import Grid, ServerApp
from flwr.serverapp.strategy import FedAvg

from federated_ids.evaluation.metrics import classification_metrics
from federated_ids.models.mlp import MLP, predict_proba, set_seed

from fids_flower.common import MODEL, manifest, server_data

app = ServerApp()


@app.main()
def main(grid: Grid, context: Context) -> None:
    rc = context.run_config
    data_dir = str(rc["server-data-dir"])
    man, S = manifest(data_dir), server_data(data_dir)
    names = man["class_names"]
    benign = names.index("Benign")
    n_clients, n_feat = int(rc["n-clients"]), S["Xtest"].shape[1]
    set_seed(int(man["seed"]))
    model = MLP(n_feat, len(names), MODEL["hidden"], MODEL["dropout"])
    n_params = sum(p.numel() for p in model.parameters())
    out = Path(str(rc["out-dir"])) / str(rc["run-name"])
    out.mkdir(parents=True, exist_ok=True)
    hist: list[dict] = []
    t0 = time.time()

    def evaluate(server_round: int, arrays: ArrayRecord) -> MetricRecord:
        m = MLP(n_feat, len(names), MODEL["hidden"], MODEL["dropout"])
        m.load_state_dict(arrays.to_torch_state_dict())
        mv = classification_metrics(S["yval"], predict_proba(m, S["Xval"]).argmax(1), names, benign)
        mt = classification_metrics(S["ytest"], predict_proba(m, S["Xtest"]).argmax(1), names, benign)
        hist.append({"round": server_round, "val_macro_f1": mv["macro_f1"], "test_macro_f1": mt["macro_f1"],
                     "test_benign_fpr": mt["benign_fpr"], "elapsed_s": round(time.time() - t0, 1)})
        return MetricRecord({"val_macro_f1": mv["macro_f1"], "test_macro_f1": mt["macro_f1"]})

    # every connected SuperNode trains every round (= participation 1.0 in the simulator)
    strategy = FedAvg(fraction_train=1.0, fraction_evaluate=0.0, min_train_nodes=n_clients,
                      min_available_nodes=n_clients)
    result = strategy.start(grid=grid, initial_arrays=ArrayRecord(model.state_dict()),
                            train_config=ConfigRecord({"lr": float(rc["learning-rate"])}),
                            num_rounds=int(rc["num-server-rounds"]), evaluate_fn=evaluate)
    wall = time.time() - t0
    model.load_state_dict(result.arrays.to_torch_state_dict())
    torch.save(model.state_dict(), out / "global_model.pt")
    proba = predict_proba(model, S["Xtest"])
    pred = proba.argmax(1)
    seen = S["seen_test"]
    rounds = int(rc["num-server-rounds"])
    res = {"framework": "flower-1.42-deployment-engine",
           "test": classification_metrics(S["ytest"], pred, names, benign, proba),
           "test_unseen": classification_metrics(S["ytest"][~seen], pred[~seen], names, benign, proba[~seen]),
           "wall_clock_seconds": round(wall, 1),
           "communication": {"n_parameters": int(n_params), "bytes_per_model_float32": int(n_params * 4),
                             "total_MB_estimate": round(2 * n_clients * rounds * n_params * 4 / 2**20, 2),
                             "note": "payload estimate (broadcast + upload, float32); excludes transport overhead"},
           "server_host": platform.node()}
    (out / "metrics.json").write_text(json.dumps(res, indent=2, default=float), encoding="utf-8")
    (out / "config.json").write_text(json.dumps({"run_config": {k: rc[k] for k in rc}, "data_manifest": man},
                                                indent=2, default=str), encoding="utf-8")
    rows = [h for h in hist if h["round"] > 0]
    if rows:
        with open(out / "history.csv", "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
