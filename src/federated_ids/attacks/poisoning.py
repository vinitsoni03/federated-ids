"""Model-update poisoning by malicious federated clients (Milestone 6). Simulation only.

Threat model (documented in reports/threat_models.md):
  * The attacker controls a fixed set of m of the K clients (chosen at random once, seeded),
    which participate in every round. They receive the global model like any client
    (white-box access to the current model), know the training protocol and the aggregation
    rule, but do NOT see honest clients' data or updates (non-omniscient), and cannot tamper
    with the server or with other clients' messages.
  * They hold their own partition of real training data.

Attacks:
  sign_flip   (untargeted): train honestly, then submit  -scale * delta. Objective: degrade
              global utility (macro-F1) for everyone.
  label_flip_boost (targeted): relabel local rows of the `target` attack FAMILIES as Benign
              (defined per row from its class34 label, so the same attack applies to the
              8-class, 34-class and binary tasks), train on
              that, then submit  boost * delta  (boosting/model replacement idea from
              Bagdasaryan et al., 2020). Objective: make the global model classify the target
              attack family as Benign (a stealthy false-negative), while keeping other
              classes working. Success metric: fraction of target-class test rows predicted
              Benign (target "evasion rate"), compared with the clean run.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import torch


@dataclass
class PoisonConfig:
    kind: str = "none"                 # none | sign_flip | label_flip_boost
    malicious_fraction: float = 0.0
    scale: float = 5.0                 # sign_flip multiplier
    boost: float | None = None         # label_flip_boost multiplier; None -> K / m
    targets: list[str] = field(default_factory=list)   # category names relabelled as Benign
    seed: int = 0


def choose_malicious(n_clients: int, fraction: float, seed: int) -> list[int]:
    m = int(round(fraction * n_clients))
    if m == 0:
        return []
    return sorted(np.random.default_rng(seed + 7919).choice(n_clients, size=m, replace=False).tolist())


def relabel_families(y: np.ndarray, families: np.ndarray, targets: list[str], benign: int) -> np.ndarray:
    """Copy of y with every row whose attack family is in `targets` set to the Benign label."""
    out = np.array(y, copy=True)
    out[np.isin(families, targets)] = benign
    return out


def poison_update(cfg: PoisonConfig, delta: torch.Tensor, n_clients: int, n_malicious: int) -> torch.Tensor:
    """Transform the malicious client's locally trained delta into the submitted update."""
    if cfg.kind == "sign_flip":
        return -cfg.scale * delta
    if cfg.kind == "label_flip_boost":
        boost = cfg.boost if cfg.boost is not None else n_clients / max(n_malicious, 1)
        return boost * delta
    if cfg.kind == "none":
        return delta
    raise ValueError(cfg.kind)
