"""Milestone 7: constrained inference-time evasion against the trained centralized IDS.
Offline simulation on held-out CICIoT2023 test windows only.

Threat model (see reports/threat_models.md):
  * Goal: an attack window that the IDS currently flags (predicted as any attack class) is
    classified as Benign. Being re-labelled as another attack class is NOT counted as evasion.
  * Knowledge/access: black-box, label-only queries to the deployed classifier (no gradients,
    no training data, cannot change the model or benign traffic). Query budget per window =
    size of the search grid below.
  * Capabilities: the attacker controls only how its OWN attack packets are generated:
      padding  p >= 0 bytes appended to every packet of the window
               -> Min, Max, AVG, Tot size (+ p);  Tot sum (+ p * Number);  Std, Variance unchanged;
               constraint: Max + p <= 1514 (Ethernet MTU; windows already above it get p = 0);
      slow-down r in (0, 1]: send at r x the original packet rate
               -> Rate * r;  IAT / r;
      TTL     the crafted packets' TTL is set to a value t taken from the benign TRAIN
               distribution (quantiles) -> Time_To_Live = t.
  * Not modifiable: protocol indicators, flag ratios/counts, Protocol Type, Header_Length.
    Changing them would change what the attack is (e.g. a SYN flood without SYN flags).
  * Cost: r < 1 directly reduces attack throughput; results are reported per minimum r.
Feature recomputation follows the feature definitions in Neto et al. (2023), Table 4. It is
a feature-space model of problem-space changes; it was not validated by replaying packets
(limitation).
"""
from __future__ import annotations

import itertools

import numpy as np

MTU = 1514.0
PADDING = [0, 50, 100, 200, 400, 800, 1450]
SLOWDOWN = [1.0, 0.5, 0.25, 0.1]


def apply_perturbation(X: np.ndarray, features: list[str], p: float, r: float, ttl: float | None) -> np.ndarray:
    """X: raw (unpreprocessed) feature rows. Returns a modified copy satisfying the constraints."""
    Z = np.array(X, dtype=np.float64, copy=True)
    col = {f: i for i, f in enumerate(features)}
    if p:
        mx = Z[:, col["Max"]]
        allowed = np.clip(MTU - mx, 0.0, None)
        pp = np.minimum(p, allowed)
        for f in ("Min", "Max", "AVG", "Tot size"):
            if f in col:
                Z[:, col[f]] += pp
        if "Tot sum" in col and "Number" in col:
            Z[:, col["Tot sum"]] += pp * Z[:, col["Number"]]
    if r != 1.0:
        Z[:, col["Rate"]] *= r
        Z[:, col["IAT"]] /= r
    if ttl is not None:
        Z[:, col["Time_To_Live"]] = ttl
    return Z


def check_constraints(X0: np.ndarray, Z: np.ndarray, features: list[str], r_min: float) -> dict:
    """Return violations (counts) of the threat-model constraints between original X0 and Z."""
    col = {f: i for i, f in enumerate(features)}
    frozen = [f for f in features if f not in ("Min", "Max", "AVG", "Tot size", "Tot sum", "Rate", "IAT",
                                               "Time_To_Live")]
    fi = [col[f] for f in frozen]
    both_nan = np.isnan(X0[:, fi]) & np.isnan(Z[:, fi])
    changed = ~((X0[:, fi] == Z[:, fi]) | both_nan)
    with np.errstate(invalid="ignore", divide="ignore"):
        pad = Z[:, col["Max"]] - X0[:, col["Max"]]
        rr = Z[:, col["Rate"]] / X0[:, col["Rate"]]
    return {"frozen_feature_changes": int(changed.sum()),
            "negative_padding": int((pad < -1e-9).sum()),
            "mtu_exceeded_by_padding": int(((pad > 1e-9) & (Z[:, col["Max"]] > MTU + 1e-9)).sum()),
            "std_changed": int((~np.isclose(Z[:, col["Std"]], X0[:, col["Std"]], equal_nan=True)).sum()),
            "rate_factor_below_budget": int(((rr < r_min - 1e-9) & np.isfinite(rr)).sum())}


def evade(predict, X: np.ndarray, features: list[str], benign: int, ttl_choices: list[float | None],
          r_min: float, padding=PADDING, slowdown=SLOWDOWN) -> dict:
    """Black-box grid search per window; stops at the first (cheapest-ordered) evading setting.
    Ordering: larger r (less slow-down) first, then smaller padding, original TTL first."""
    rs = sorted([r for r in slowdown if r >= r_min - 1e-12], reverse=True)
    grid = list(itertools.product(rs, padding, ttl_choices))
    n = len(X)
    evaded = np.zeros(n, dtype=bool)
    chosen = np.full((n, 3), np.nan)
    queries = np.zeros(n, dtype=np.int32)
    for r, p, t in grid:
        todo = ~evaded
        if not todo.any():
            break
        Z = apply_perturbation(X[todo], features, p, r, t)
        pred = predict(Z)
        queries[todo] += 1
        ok = pred == benign
        idx = np.flatnonzero(todo)[ok]
        evaded[idx] = True
        chosen[idx] = [r, p, np.nan if t is None else t]
    return {"evaded": evaded, "chosen": chosen, "queries": queries, "grid_size": len(grid)}
