"""Endpoint tests: auth, validation, and that served predictions equal offline predictions."""
import importlib
import json
import sys

import numpy as np
import pytest
import torch

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from federated_ids.data.preprocess import Preprocessor  # noqa: E402
from federated_ids.models.mlp import MLP, predict_proba  # noqa: E402

FEATS = ["Rate", "TCP", "IAT"]
CLASSES = ["Benign", "DDoS", "Web"]


@pytest.fixture()
def client(tmp_path, monkeypatch):
    rng = np.random.default_rng(0)
    pre = Preprocessor(FEATS).fit(rng.lognormal(size=(200, 3)))
    pre.to_json(tmp_path / "preprocessor.json")
    torch.manual_seed(0)
    m = MLP(3, 3, [8, 4], 0.1)
    torch.save(m.state_dict(), tmp_path / "model.pt")
    (tmp_path / "model_meta.json").write_text(json.dumps({
        "task": "toy", "class_names": CLASSES, "features": FEATS, "hidden": [8, 4], "dropout": 0.1,
        "source_run": "test", "trained_with": "test"}))
    monkeypatch.setenv("MODEL_DIR", str(tmp_path))
    monkeypatch.setenv("API_KEY", "k" * 20)
    monkeypatch.setenv("MAX_ROWS", "5")
    sys.modules.pop("serving.app", None)
    mod = importlib.import_module("serving.app")
    return TestClient(mod.app), m, pre


def test_auth_required(client):
    c, _, _ = client
    assert c.get("/health").status_code == 200
    assert c.post("/predict", json={"rows": [{"Rate": 1, "TCP": 1, "IAT": 0.1}]}).status_code == 401
    assert c.post("/predict", headers={"X-API-Key": "wrong"}, json={"rows": [{}]}).status_code == 401


def test_validation(client):
    c, _, _ = client
    h = {"X-API-Key": "k" * 20}
    assert c.post("/predict", headers=h, json={"rows": [{"Rate": 1, "TCP": 1}]}).status_code == 422  # missing IAT
    assert c.post("/predict", headers=h, json={"rows": []}).status_code == 422
    big = {"rows": [{"Rate": 1, "TCP": 1, "IAT": 0.1}] * 6}
    assert c.post("/predict", headers=h, json=big).status_code == 413


def test_served_predictions_match_offline(client):
    c, m, pre = client
    rows = [{"Rate": 3.0, "TCP": 1.0, "IAT": 0.01}, {"Rate": 900.0, "TCP": 0.0, "IAT": None}]
    r = c.post("/predict", headers={"X-API-Key": "k" * 20}, json={"rows": rows})
    assert r.status_code == 200
    X = np.array([[3.0, 1.0, 0.01], [900.0, 0.0, np.nan]])
    off = predict_proba(m, pre.transform(X)).argmax(1)
    assert [p["label"] for p in r.json()["predictions"]] == [CLASSES[k] for k in off]
