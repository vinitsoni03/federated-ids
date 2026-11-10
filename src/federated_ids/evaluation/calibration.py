"""Operating-point calibration: choose a benign/attack threshold for a target benign FPR.

A multi-class detector's attack score is s = 1 - P(Benign). The threshold t is chosen on the
validation set so that at most `target` of the benign validation rows have s > t. At inference a
row is Benign if s <= t, otherwise the most probable *attack* class. With t = 0.5 on a binary
model this is the usual argmax; on a multi-class model argmax and thresholding can differ.
Thresholds are fitted on validation only and then applied unchanged to test.
"""
from __future__ import annotations

import numpy as np

from federated_ids.evaluation.metrics import classification_metrics


def attack_score(proba: np.ndarray, benign: int) -> np.ndarray:
    return 1.0 - proba[:, benign].astype(np.float64)


def threshold_for_fpr(score: np.ndarray, is_benign: np.ndarray, target: float) -> float:
    """Smallest threshold from the benign scores with FPR = mean(score[benign] > t) <= target.
    Ties can make the achieved FPR lower than the target, never higher."""
    sb = np.sort(score[is_benign])[::-1]  # descending
    if not len(sb):
        raise ValueError("no benign rows to calibrate on")
    k = int(np.floor(target * len(sb)))   # number of benign rows allowed above t
    return float(sb[min(k, len(sb) - 1)])


def predict_with_threshold(proba: np.ndarray, benign: int, t: float) -> np.ndarray:
    """Benign if attack score <= t, else argmax over the attack classes."""
    masked = proba.astype(np.float64).copy()
    masked[:, benign] = -np.inf
    pred = masked.argmax(1)
    pred[attack_score(proba, benign) <= t] = benign
    return pred


def operating_points(proba: np.ndarray, y: np.ndarray, class_names: list[str], benign: int,
                     targets=(0.05, 0.01), thresholds: dict | None = None) -> list[dict]:
    """Metrics at plain argmax and at each target FPR. `thresholds` ({"fpr5": t, ...}) reuses
    previously fitted thresholds (e.g. from validation on test); otherwise they are fitted on y."""
    rows = []
    m = classification_metrics(y, proba.argmax(1), class_names, benign)
    rows.append(_row("argmax", None, None, m))
    for tgt in targets:
        name = f"fpr{tgt * 100:g}"
        t = thresholds[name] if thresholds is not None else threshold_for_fpr(attack_score(proba, benign), y == benign, tgt)
        m = classification_metrics(y, predict_with_threshold(proba, benign, t), class_names, benign)
        rows.append(_row(name, tgt, t, m))
    return rows


def _row(name, target, t, m) -> dict:
    return {"operating_point": name, "target_fpr": target, "threshold": t, "macro_f1": m["macro_f1"],
            "benign_fpr": m["benign_fpr"], "attack_detection_rate": m["attack_detection_rate"],
            "binary_f1": m["binary_f1"], "per_class_f1": {k: v["f1"] for k, v in m["per_class"].items()}}
