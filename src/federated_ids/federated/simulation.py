"""In-process federated learning simulation (Milestone 5) with optional malicious clients (M6).

Deterministic given the seed: partition, client sampling, local shuffles and initialisation
are all seeded. Every client trains a copy of the same MLP as the centralized baseline on its
own partition of the fixed training split; the server aggregates parameter deltas.

Assumptions (stated in reports): preprocessing statistics (medians, means, stds) are fitted on
the pooled training split and shared with all clients, i.e. we assume they were agreed in
advance; this is a simplification - FL here gives no formal privacy guarantee, and no
differential privacy or secure aggregation is implemented.

Usage:
    python -m federated_ids.federated.simulation --config configs/federated.yaml
        [--partition iid|dirichlet] [--alpha A] [--algorithm fedavg|fedprox] [--mu MU]
        [--aggregator fedavg|median|trimmed_mean|norm_clip] [--attack none|sign_flip|label_flip_boost]
        [--malicious-fraction F] [--targets DDoS ...] [--seed S] [--rounds R] [--run-name NAME]
"""
from __future__ import annotations

import argparse
import copy
import csv
import sys
import time

import numpy as np
import torch

from federated_ids.attacks.poisoning import PoisonConfig, choose_malicious, poison_update, relabel_families
from federated_ids.config import data_config, load_yaml
from federated_ids.data.ciciot import family_of_class34
from federated_ids.data.dataset import benign_index, task_labels
from federated_ids.evaluation.metrics import classification_metrics, summary_row
from federated_ids.experiments.centralized import prepare
from federated_ids.experiments.common import environment, peak_rss_mb, run_dir, write_json
from federated_ids.federated.aggregators import aggregate
from federated_ids.federated.partition import make_partition, partition_stats
from federated_ids.models.mlp import (MLP, as_tensor, class_weights, flat_params, predict_proba, resolve_device,
                                     set_flat_params, set_seed, train_epochs)


def target_metrics(y: np.ndarray, y34: np.ndarray, pred: np.ndarray, benign: int, targets: list[str]) -> dict:
    """Per target attack FAMILY (works for every task): share of that family's test rows predicted
    Benign, and share predicted correctly (task label)."""
    fam = family_of_class34(y34)
    out = {}
    for t in targets:
        m = fam == t
        out[t] = {"rows": int(m.sum()), "predicted_benign_rate": float((pred[m] == benign).mean()) if m.any() else None,
                  "recall": float((pred[m] == y[m]).mean()) if m.any() else None}
    return out


def run(cfg: dict, name: str, log=print) -> dict:
    torch.set_num_threads(cfg.get("torch_threads", 6))
    device = resolve_device(cfg.get("device", "auto"))
    cfg["device_resolved"] = str(device)
    dcfg = data_config()
    class_names = task_labels(cfg["task"])
    benign = benign_index(cfg["task"])
    K = len(class_names)
    features, pre, data = prepare(cfg, dcfg)
    Xtr, ytr = data["train"]["Xp"], data["train"]["y"]
    seed = cfg["seed"]
    fl = cfg["federated"]
    parts = make_partition(fl["partition"], ytr, fl["n_clients"], seed, fl.get("alpha"), fl.get("min_client_size", 100))
    pstats = partition_stats(parts, ytr, K)
    pc = PoisonConfig(**{**cfg.get("poison", {}), "seed": seed})
    malicious = choose_malicious(fl["n_clients"], pc.malicious_fraction, seed) if pc.kind != "none" else []
    fam_tr = family_of_class34(data["train"]["y34"])

    set_seed(seed)
    model = MLP(Xtr.shape[1], K, cfg["model"]["hidden"], cfg["model"]["dropout"]).to(device)
    Xtr_dev = as_tensor(Xtr, device)  # whole training split on the device once
    parts_dev = [torch.as_tensor(p, device=device) for p in parts]
    n_params = sum(p.numel() for p in model.parameters())
    # loss weights from the GLOBAL label distribution would leak it; each client uses its own
    client_w = [class_weights(ytr[p], K, cfg["train"]["class_weighting"]) for p in parts]
    rng = np.random.default_rng(seed + 1)
    mu = fl["mu"] if fl["algorithm"] == "fedprox" else 0.0
    bytes_per_model = n_params * 4
    hist, comm_bytes = [], 0
    t0 = time.time()
    for rnd in range(1, fl["rounds"] + 1):
        n_part = max(1, int(round(fl["participation"] * fl["n_clients"])))
        chosen = sorted(rng.choice(fl["n_clients"], size=n_part, replace=False).tolist())
        chosen = sorted(set(chosen) | set(malicious))  # attacker clients always participate
        g = flat_params(model)
        ups, ws = [], []
        for k in chosen:
            local = copy.deepcopy(model)
            is_mal = k in malicious
            y_k = ytr[parts[k]]
            w_k = client_w[k]
            if is_mal and pc.kind == "label_flip_boost":
                # relabel the attacker's own rows of the target families as Benign; its loss
                # weights follow its relabelled data
                y_k = relabel_families(y_k, fam_tr[parts[k]], pc.targets, benign)
                w_k = class_weights(y_k, K, cfg["train"]["class_weighting"])
            train_epochs(local, Xtr_dev[parts_dev[k]], y_k, w_k, fl["local_epochs"], cfg["train"]["lr"],
                         cfg["train"]["batch_size"], seed * 100000 + rnd * 100 + k, prox_mu=mu,
                         global_params=g if mu > 0 else None)
            delta = flat_params(local) - g
            if is_mal:
                delta = poison_update(pc, delta, fl["n_clients"], len(malicious))
            ups.append(delta)
            ws.append(float(len(parts[k])))
        U = torch.stack(ups)
        agg = aggregate(fl["aggregator"], U, torch.tensor(ws, device=U.device), trim_beta=fl.get("trim_beta", 0.2),
                        clip_norm=fl.get("clip_norm"))
        set_flat_params(model, g + fl.get("server_lr", 1.0) * agg)
        comm_bytes += 2 * len(chosen) * bytes_per_model  # broadcast + upload, float32, uncompressed
        if rnd % fl["eval_every"] == 0 or rnd == fl["rounds"]:
            pv = predict_proba(model, data["val"]["Xp"]).argmax(1)
            mv = classification_metrics(data["val"]["y"], pv, class_names, benign)
            pt = predict_proba(model, data["test"]["Xp"]).argmax(1)
            mt = classification_metrics(data["test"]["y"], pt, class_names, benign)
            row = {"round": rnd, "val_macro_f1": mv["macro_f1"], "test_macro_f1": mt["macro_f1"],
                   "test_benign_fpr": mt["benign_fpr"], "test_attack_detection_rate": mt["attack_detection_rate"],
                   "elapsed_s": round(time.time() - t0, 1), "comm_MB": round(comm_bytes / 2**20, 2)}
            for t, v in target_metrics(data["test"]["y"], data["test"]["y34"], pt, benign, pc.targets).items():
                row[f"test_{t}_pred_benign"] = v["predicted_benign_rate"]
            hist.append(row)
            log(f"  [{name}] round {rnd}: val macroF1 {mv['macro_f1']:.4f} test macroF1 {mt['macro_f1']:.4f} "
                f"FPR {mt['benign_fpr']:.4f} ({row['elapsed_s']}s)")
    wall = time.time() - t0

    proba = predict_proba(model, data["test"]["Xp"])
    pred = proba.argmax(1)
    res = {"test": classification_metrics(data["test"]["y"], pred, class_names, benign, proba)}
    seen = data["test"]["seen"]
    res["test_unseen"] = classification_metrics(data["test"]["y"][~seen], pred[~seen], class_names, benign, proba[~seen])
    pv = predict_proba(model, data["val"]["Xp"])
    res["val"] = classification_metrics(data["val"]["y"], pv.argmax(1), class_names, benign, pv)
    res["targets"] = target_metrics(data["test"]["y"], data["test"]["y34"], pred, benign, pc.targets)
    res["malicious_clients"] = malicious
    res["partition"] = pstats
    res["wall_clock_seconds"] = round(wall, 1)
    res["communication"] = {"n_parameters": int(n_params), "bytes_per_model_float32": int(bytes_per_model),
                            "total_MB": round(comm_bytes / 2**20, 2), "rounds": fl["rounds"]}
    res["peak_rss_mb"] = peak_rss_mb()
    out = run_dir(name)
    torch.save(model.state_dict(), out / "global_model.pt")
    pre.to_json(out / "preprocessor.json")
    write_json(out / "config.json", {"experiment": cfg, "features": features})
    write_json(out / "environment.json", environment())
    write_json(out / "metrics.json", res)
    with open(out / "history.csv", "w", newline="", encoding="utf-8") as fh:
        wr = csv.DictWriter(fh, fieldnames=list(hist[0]))
        wr.writeheader()
        wr.writerows(hist)
    return res


def build_cfg(a) -> dict:
    cfg = load_yaml(a.config)
    fl = cfg["federated"]
    for k_arg, k_cfg in [("partition", "partition"), ("alpha", "alpha"), ("algorithm", "algorithm"),
                         ("mu", "mu"), ("aggregator", "aggregator"), ("rounds", "rounds"),
                         ("n_clients", "n_clients"), ("participation", "participation"),
                         ("local_epochs", "local_epochs")]:
        v = getattr(a, k_arg)
        if v is not None:
            fl[k_cfg] = v
    if a.seed is not None:
        cfg["seed"] = a.seed
    if a.hidden:
        cfg["model"]["hidden"] = a.hidden
    if a.dropout is not None:
        cfg["model"]["dropout"] = a.dropout
    if a.lr is not None:
        cfg["train"]["lr"] = a.lr
    if a.feature_set:
        cfg["feature_set"] = a.feature_set
    if a.task:
        cfg["task"] = a.task
    if a.device:
        cfg["device"] = a.device
    cfg.setdefault("poison", {})
    if a.attack:
        cfg["poison"]["kind"] = a.attack
    if a.malicious_fraction is not None:
        cfg["poison"]["malicious_fraction"] = a.malicious_fraction
    if a.targets:
        cfg["poison"]["targets"] = a.targets
    if a.scale is not None:
        cfg["poison"]["scale"] = a.scale
    if a.boost is not None:
        cfg["poison"]["boost"] = a.boost
    return cfg


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", default="configs/federated.yaml")
    ap.add_argument("--partition")
    ap.add_argument("--alpha", type=float)
    ap.add_argument("--algorithm")
    ap.add_argument("--mu", type=float)
    ap.add_argument("--aggregator")
    ap.add_argument("--rounds", type=int)
    ap.add_argument("--n-clients", type=int)
    ap.add_argument("--participation", type=float)
    ap.add_argument("--local-epochs", type=int)
    ap.add_argument("--seed", type=int)
    ap.add_argument("--hidden", nargs="*", type=int, help="MLP hidden sizes (default: config)")
    ap.add_argument("--dropout", type=float)
    ap.add_argument("--lr", type=float, help="client Adam learning rate")
    ap.add_argument("--feature-set")
    ap.add_argument("--attack")
    ap.add_argument("--malicious-fraction", type=float)
    ap.add_argument("--targets", nargs="*")
    ap.add_argument("--scale", type=float)
    ap.add_argument("--boost", type=float)
    ap.add_argument("--device", help="auto | cpu | cuda")
    ap.add_argument("--task", help="category | class34 | binary")
    ap.add_argument("--run-name", required=True)
    a = ap.parse_args(argv)
    cfg = build_cfg(a)
    res = run(cfg, a.run_name)
    print({k: v for k, v in summary_row(res["test"]).items()}, res["targets"], res["wall_clock_seconds"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
