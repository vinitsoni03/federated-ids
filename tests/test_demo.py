"""Demo dashboard: endpoints work and the step-by-step attack agrees with attacks/evasion.evade."""
import numpy as np
import pytest
from fastapi.testclient import TestClient

A = pytest.importorskip("demo.app")
from federated_ids.attacks.evasion import evade  # noqa: E402

client = TestClient(A.app)


def test_meta_and_detect():
    m = client.get("/api/meta").json()
    assert len(m["windows"]) == 320 and m["classes"][0] == "Benign"
    r = client.post("/api/detect", json={"id": m["windows"][0]["id"], "model": "frozen", "rule": "fpr1"}).json()
    assert abs(sum(r["result"]["proba"].values()) - 1) < 1e-4
    assert client.post("/api/detect", json={"id": -5}).status_code == 404
    assert client.post("/api/detect", json={"id": m["windows"][0]["id"], "rule": "bogus"}).status_code == 422


@pytest.mark.parametrize("model", ["frozen", "hardened"])
def test_attack_trace_matches_evade(model):
    ids = [i for i, w in A.WINDOWS.items() if w["family"] in ("Spoofing", "Web")][:20]
    X = np.vstack([A.raw(i) for i in ids])
    dec = lambda Z: A.decide(model, "fpr1", A.proba(model, Z))  # noqa: E731
    det = dec(X) != A.BENIGN
    e = evade(dec, X[det], A.FEATURES, A.BENIGN, A.TTL_CHOICES, 0.1)
    ev = np.zeros(len(ids), bool)
    ev[det] = e["evaded"]
    for j, i in enumerate(ids):
        r = client.post("/api/attack", json={"id": i, "model": model, "rule": "fpr1"}).json()
        assert r["detected"] == bool(det[j]) and r["evaded"] == bool(ev[j])
        if r["evaded"]:
            assert sum(r["constraint_violations"].values()) == 0
            assert r["trace"][-1]["label"] == "Benign"
