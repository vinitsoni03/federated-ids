"""Tests for the WP5 helpers (expected values worked out by hand)."""
import numpy as np

from federated_ids.attacks.evasion import apply_perturbation
from federated_ids.experiments.wp5_advtrain import evasion_by_budget, rebuild

FEATURES = ["Min", "Max", "AVG", "Tot size", "Tot sum", "Number", "Rate", "IAT", "Time_To_Live", "Std"]


def test_evasion_by_budget():
    detected = np.array([True, True, True, True, False])
    evaded = np.array([True, True, False, True, False])
    chosen_r = np.array([1.0, 0.25, np.nan, 0.1, np.nan])
    out = evasion_by_budget(detected, evaded, chosen_r)
    assert out["1.0"]["evasion_rate"] == 0.25          # only the r=1 window
    assert out["0.25"]["evasion_rate"] == 0.5          # + the r=0.25 window
    assert out["0.1"]["evasion_rate"] == 0.75
    assert out["0.1"]["robust_detection"] == 0.2       # 1 of 5 detected and not evaded
    assert out["1.0"]["robust_detection"] == 0.6       # 3 of 5


def test_rebuild_matches_rowwise():
    rng = np.random.default_rng(0)
    X = rng.uniform(1, 500, size=(6, len(FEATURES)))
    chosen = np.array([[1.0, 0, np.nan], [0.5, 100, 64.0], [1.0, 0, np.nan],
                       [0.1, 1450, np.nan], [0.5, 100, 64.0], [0.25, 50, 128.0]])
    Z = rebuild(X, chosen, FEATURES)
    for i in range(len(X)):
        r, p, t = chosen[i]
        ref = apply_perturbation(X[i:i + 1], FEATURES, p, r, None if np.isnan(t) else t)
        np.testing.assert_allclose(Z[i:i + 1], ref)
