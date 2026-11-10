import numpy as np

from federated_ids.data.ciciot import FEATURES
from federated_ids.data.preprocess import Preprocessor, select_features
from federated_ids.evaluation.metrics import classification_metrics


def test_window_invariant_drops_window_features():
    wd = ["Number", "Tot sum", "ack_count", "syn_count", "fin_count", "rst_count"]
    f = select_features(FEATURES, wd, "window_invariant")
    assert len(f) == 33 and not set(wd) & set(f)
    assert select_features(FEATURES, wd, "all39") == FEATURES


def test_preprocessor_fits_on_train_only_and_roundtrips(tmp_path):
    rng = np.random.default_rng(0)
    tr = rng.lognormal(size=(500, 3))
    tr[0, 0] = np.inf
    tr[1, 1] = np.nan
    te = rng.lognormal(mean=3, size=(200, 3))  # shifted distribution
    pre = Preprocessor(["Rate", "TCP", "IAT"]).fit(tr)
    Z = pre.transform(tr)
    assert np.isfinite(Z).all()
    assert np.allclose(Z.mean(0), 0, atol=1e-5) and np.allclose(Z.std(0), 1, atol=1e-3)
    # statistics must NOT move towards the test data
    assert pre.transform(te).mean() > 1.0
    pre.to_json(tmp_path / "p.json")
    pre2 = Preprocessor.from_json(tmp_path / "p.json")
    assert np.array_equal(pre2.transform(te), pre.transform(te))
    assert pre.log_mask == [True, False, True]


def test_metrics_known_values():
    names = ["Benign", "A", "B"]
    y = np.array([0, 0, 0, 0, 1, 1, 2, 2])
    p = np.array([0, 0, 0, 1, 1, 1, 2, 0])
    m = classification_metrics(y, p, names, 0)
    assert m["benign_fpr"] == 0.25             # 1 of 4 benign flagged as attack
    assert m["attack_detection_rate"] == 0.75  # 3 of 4 attacks flagged as some attack
    assert m["confusion_matrix"][2] == [1, 0, 1]
    assert abs(m["accuracy"] - 6 / 8) < 1e-12
