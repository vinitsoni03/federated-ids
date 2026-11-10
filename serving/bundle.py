"""Model bundle loading shared by the endpoint and the smoke test (no side effects on import)."""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import torch

from federated_ids.data.preprocess import Preprocessor
from federated_ids.models.mlp import MLP, predict_proba


class Bundle:
    def __init__(self, model_dir: Path):
        self.meta = json.loads((model_dir / "model_meta.json").read_text(encoding="utf-8"))
        self.pre = Preprocessor.from_json(model_dir / "preprocessor.json")
        self.features: list[str] = self.meta["features"]
        if self.pre.features != self.features:
            raise ValueError("preprocessor features do not match model_meta features")
        self.classes: list[str] = self.meta["class_names"]
        self.benign = self.classes.index("Benign")
        self.model = MLP(len(self.features), len(self.classes), self.meta["hidden"], self.meta["dropout"])
        self.model.load_state_dict(torch.load(model_dir / "model.pt", map_location="cpu"))
        self.model.eval()

    def predict(self, X: np.ndarray) -> np.ndarray:
        return predict_proba(self.model, self.pre.transform(X))
