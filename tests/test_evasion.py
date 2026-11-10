import numpy as np

from federated_ids.attacks.evasion import MTU, apply_perturbation, check_constraints, evade

F = ["Rate", "Time_To_Live", "TCP", "syn_flag_number", "Min", "Max", "AVG", "Std", "Tot size", "IAT", "Variance"]


def _x():
    return np.array([[100.0, 64.0, 1.0, 0.9, 60.0, 100.0, 80.0, 10.0, 80.0, 0.01, 100.0],
                     [50.0, 128.0, 1.0, 0.0, 60.0, 1500.0, 700.0, 300.0, 700.0, 0.02, 90000.0]])


def test_perturbation_respects_feature_semantics_and_mtu():
    X = _x()
    Z = apply_perturbation(X, F, p=100, r=0.5, ttl=255)
    c = {f: i for i, f in enumerate(F)}
    assert np.allclose(Z[0, [c["Min"], c["Max"], c["AVG"], c["Tot size"]]], X[0, [4, 5, 6, 8]] + 100)
    assert Z[1, c["Max"]] == 1514 and Z[1, c["Min"]] == 74  # padding capped so Max <= MTU
    assert np.allclose(Z[:, c["Rate"]], X[:, c["Rate"]] * 0.5)
    assert np.allclose(Z[:, c["IAT"]], X[:, c["IAT"]] / 0.5)
    assert (Z[:, c["Time_To_Live"]] == 255).all()
    for f in ("TCP", "syn_flag_number", "Std", "Variance"):
        assert np.array_equal(Z[:, c[f]], X[:, c[f]])
    assert sum(check_constraints(X, Z, F, r_min=0.5).values()) == 0
    assert check_constraints(X, Z, F, r_min=0.9)["rate_factor_below_budget"] == 2
    assert (Z[:, c["Max"]] <= MTU).all()


def test_check_constraints_detects_illegal_changes():
    X = _x()
    Z = X.copy()
    Z[:, F.index("syn_flag_number")] = 0.0
    assert check_constraints(X, Z, F, 0.1)["frozen_feature_changes"] == 1


def test_evade_finds_cheapest_setting_with_toy_model():
    X = _x()[:1]
    benign = 0

    def predict(Z):  # "benign" iff Rate is low
        return np.where(Z[:, F.index("Rate")] < 30, 0, 1)

    e = evade(predict, X, F, benign, [None], r_min=0.25)
    assert e["evaded"].all() and e["chosen"][0, 0] == 0.25
    e2 = evade(predict, X, F, benign, [None], r_min=0.5)  # not allowed to slow down enough
    assert not e2["evaded"].any()
