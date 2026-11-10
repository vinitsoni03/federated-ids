"""Server-side aggregation of client updates (flat parameter deltas, shape [n_clients, d]).

fedavg        - sample-size-weighted mean (McMahan et al., 2017).
median        - coordinate-wise median (Yin et al., 2018); tolerates < 50% Byzantine clients.
trimmed_mean  - coordinate-wise mean after dropping the `beta` fraction of largest and of
                smallest values (Yin et al., 2018); needs beta >= malicious fraction.
norm_clip     - clip every update to the median update L2 norm, then weighted mean (a simple
                norm-bounding defence in the spirit of Sun et al., 2019).
The robust rules are unweighted: weighting by self-reported sample counts would let a
malicious client inflate its influence.
"""
from __future__ import annotations

import torch


def fedavg(updates: torch.Tensor, weights: torch.Tensor) -> torch.Tensor:
    w = weights / weights.sum()
    return (updates * w[:, None]).sum(0)


def median(updates: torch.Tensor, weights: torch.Tensor | None = None) -> torch.Tensor:
    return updates.median(dim=0).values if updates.shape[0] % 2 else updates.quantile(0.5, dim=0)


def trimmed_mean(updates: torch.Tensor, weights: torch.Tensor | None = None, beta: float = 0.2) -> torch.Tensor:
    n = updates.shape[0]
    k = int(beta * n)
    if 2 * k >= n:
        raise ValueError(f"beta={beta} trims all {n} updates")
    s = updates.sort(dim=0).values
    return s[k:n - k].mean(0)


def norm_clip(updates: torch.Tensor, weights: torch.Tensor, max_norm: float | None = None) -> torch.Tensor:
    norms = updates.norm(dim=1)
    bound = norms.median() if max_norm is None else torch.tensor(max_norm, device=updates.device)
    scale = torch.clamp(bound / (norms + 1e-12), max=1.0)
    return fedavg(updates * scale[:, None], weights)


def aggregate(rule: str, updates: torch.Tensor, weights: torch.Tensor, **kw) -> torch.Tensor:
    if rule == "fedavg":
        return fedavg(updates, weights)
    if rule == "median":
        return median(updates)
    if rule == "trimmed_mean":
        return trimmed_mean(updates, beta=kw.get("trim_beta", 0.2))
    if rule == "norm_clip":
        return norm_clip(updates, weights, kw.get("clip_norm"))
    raise ValueError(f"unknown aggregation rule {rule!r}")
