"""Classification metrics for imbalanced multi-class IDS evaluation.

Reported: accuracy, balanced accuracy, macro/weighted F1, per-class precision/recall/F1/support,
confusion matrix, benign false-positive rate (benign rows flagged as any attack), attack
detection rate (attack rows flagged as any attack, i.e. binary recall), and one-vs-rest macro
ROC-AUC / PR-AUC (average precision) when class probabilities are given.
"""
from __future__ import annotations

import numpy as np
from sklearn.metrics import (accuracy_score, average_precision_score, balanced_accuracy_score,
                             confusion_matrix, f1_score, precision_recall_fscore_support,
                             roc_auc_score)


def classification_metrics(y_true: np.ndarray, y_pred: np.ndarray, class_names: list[str],
                           benign_index: int | None = 0, proba: np.ndarray | None = None) -> dict:
    labels = list(range(len(class_names)))
    p, r, f, s = precision_recall_fscore_support(y_true, y_pred, labels=labels, zero_division=0)
    present = s > 0
    out = {
        "n": int(len(y_true)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        # macro over classes present in y_true (absent classes would add spurious zeros)
        "macro_f1": float(f[present].mean()),
        "weighted_f1": float(f1_score(y_true, y_pred, labels=labels, average="weighted", zero_division=0)),
        "per_class": {class_names[i]: {"precision": float(p[i]), "recall": float(r[i]), "f1": float(f[i]),
                                       "support": int(s[i])} for i in labels},
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=labels).tolist(),
        "class_names": list(class_names),
    }
    if benign_index is not None:
        ben = y_true == benign_index
        att = ~ben
        out["benign_fpr"] = float((y_pred[ben] != benign_index).mean()) if ben.any() else None
        out["attack_detection_rate"] = float((y_pred[att] != benign_index).mean()) if att.any() else None
        out["binary_f1"] = float(f1_score(att, y_pred != benign_index, zero_division=0))
    if proba is not None:
        try:
            yk = np.eye(len(class_names))[y_true][:, present]
            pk = proba[:, present]
            out["macro_roc_auc_ovr"] = float(roc_auc_score(yk, pk, average="macro"))
            out["macro_pr_auc_ovr"] = float(average_precision_score(yk, pk, average="macro"))
            if benign_index is not None and ben.any() and att.any():
                score = 1.0 - proba[:, benign_index]
                out["binary_roc_auc"] = float(roc_auc_score(att, score))
                out["binary_pr_auc"] = float(average_precision_score(att, score))
        except ValueError as exc:  # e.g. a single class present
            out["auc_error"] = str(exc)
    return out


def summary_row(m: dict) -> dict:
    keys = ["n", "accuracy", "balanced_accuracy", "macro_f1", "weighted_f1", "benign_fpr",
            "attack_detection_rate", "binary_f1", "macro_roc_auc_ovr", "macro_pr_auc_ovr"]
    return {k: m.get(k) for k in keys}
