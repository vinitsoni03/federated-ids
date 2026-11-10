"""Train-only preprocessing: feature selection, +-inf -> NaN, median imputation, signed log,
standardisation. Fitted parameters are plain JSON (no pickles), so they can be inspected.

The same fitted Preprocessor is reused, unchanged, for validation, test, every federated
client and the attack experiments, so evaluation protocols stay identical.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

import numpy as np

# heavy-tailed, non-indicator columns get sign(x) * log1p(|x|) before scaling
LOG_COLUMNS = {"Header_Length", "Rate", "ack_count", "syn_count", "fin_count", "rst_count",
               "Tot sum", "Min", "Max", "AVG", "Std", "Tot size", "IAT", "Number", "Variance"}


def select_features(all_features: list[str], window_dependent: list[str], feature_set: str) -> list[str]:
    if feature_set == "all39":
        return list(all_features)
    if feature_set == "window_invariant":
        return [f for f in all_features if f not in set(window_dependent)]
    raise ValueError(f"unknown feature set {feature_set!r}")


def slog(x: np.ndarray) -> np.ndarray:
    return np.sign(x) * np.log1p(np.abs(x))


@dataclass
class Preprocessor:
    features: list[str]
    log_mask: list[bool] = field(default_factory=list)
    median: list[float] = field(default_factory=list)
    mean: list[float] = field(default_factory=list)
    std: list[float] = field(default_factory=list)
    fitted_on_rows: int = 0

    def _clean(self, X: np.ndarray) -> np.ndarray:
        X = np.array(X, dtype=np.float64, copy=True)
        X[~np.isfinite(X)] = np.nan
        return X

    def fit(self, X: np.ndarray) -> "Preprocessor":
        """X must be the TRAINING matrix restricted to self.features (column order)."""
        X = self._clean(X)
        self.median = np.nan_to_num(np.nanmedian(X, axis=0), nan=0.0).tolist()
        X = self._impute(X)
        self.log_mask = [f in LOG_COLUMNS for f in self.features]
        X = self._log(X)
        mean, std = X.mean(axis=0), X.std(axis=0)
        std[std < 1e-12] = 1.0  # constant columns stay constant (0) after scaling
        self.mean, self.std = mean.tolist(), std.tolist()
        self.fitted_on_rows = int(X.shape[0])
        return self

    def _impute(self, X: np.ndarray) -> np.ndarray:
        med = np.asarray(self.median)
        bad = np.isnan(X)
        X[bad] = np.take(med, np.nonzero(bad)[1])
        return X

    def _log(self, X: np.ndarray) -> np.ndarray:
        m = np.asarray(self.log_mask, dtype=bool)
        X[:, m] = slog(X[:, m])
        return X

    def transform(self, X: np.ndarray) -> np.ndarray:
        X = self._log(self._impute(self._clean(X)))
        return ((X - np.asarray(self.mean)) / np.asarray(self.std)).astype(np.float32)

    def to_json(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")

    @classmethod
    def from_json(cls, path: str | Path) -> "Preprocessor":
        return cls(**json.loads(Path(path).read_text(encoding="utf-8")))
