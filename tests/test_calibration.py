"""Tests for federated_ids.evaluation.calibration (expected values worked out by hand)."""
import numpy as np
import pytest

from federated_ids.evaluation.calibration import (operating_points, predict_with_threshold,
                                                  threshold_for_fpr)


def test_threshold_respects_target_fpr():
    rng = np.random.default_rng(0)
    score = rng.random(10_000)
    is_benign = rng.random(10_000) < 0.3
    for target in (0.05, 0.01, 0.2):
        t = threshold_for_fpr(score, is_benign, target)
        fpr = (score[is_benign] > t).mean()
        assert fpr <= target
        assert fpr > target - 2 / is_benign.sum()  # tight: at most one row below the target


def test_threshold_hand_example():
    # benign scores 0.1..1.0; 10 % target -> 1 row may exceed t -> t = 0.9
    score = np.array([0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0, 0.95])
    is_benign = np.array([True] * 10 + [False])
    assert threshold_for_fpr(score, is_benign, 0.10) == pytest.approx(0.9)
    assert threshold_for_fpr(score, is_benign, 0.0) == pytest.approx(1.0)  # nothing above the max


def test_ties_never_exceed_target():
    score = np.array([0.5] * 10)
    t = threshold_for_fpr(score, np.ones(10, bool), 0.3)
    assert (score > t).mean() == 0.0


def test_predict_with_threshold_benign_not_first():
    # classes: 0 = DDoS, 1 = Benign, 2 = Mirai
    proba = np.array([[0.30, 0.40, 0.30],    # score 0.60 -> attack, tie broken to class 0
                      [0.10, 0.80, 0.10],    # score 0.20 -> benign
                      [0.20, 0.35, 0.45]])   # score 0.65 -> Mirai (argmax would also say Mirai)
    pred = predict_with_threshold(proba, benign=1, t=0.5)
    assert pred.tolist() == [0, 1, 2]
    # row 0: argmax says Benign, but its attack score 0.6 exceeds t -> flagged as an attack
    assert proba[0].argmax() == 1


def test_operating_points_reuses_given_thresholds():
    proba = np.array([[0.9, 0.1], [0.4, 0.6], [0.2, 0.8], [0.7, 0.3]])
    y = np.array([0, 0, 1, 1])
    rows = operating_points(proba, y, ["Benign", "Attack"], 0, targets=(0.5,), thresholds={"fpr50": 0.65})
    op = {r["operating_point"]: r for r in rows}
    assert op["fpr50"]["threshold"] == 0.65
    assert op["fpr50"]["benign_fpr"] == 0.0           # 0.1, 0.6 <= 0.65
    assert op["fpr50"]["attack_detection_rate"] == 0.5  # 0.8 > 0.65, 0.3 not
    assert op["argmax"]["benign_fpr"] == 0.5
