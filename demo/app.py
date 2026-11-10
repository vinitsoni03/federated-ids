"""Local demo dashboard for the federated IDS project (Detect / Attack / Federated / Results).

Runs entirely on this machine from demo/bundle/ (built by scripts/build_demo_bundle.py) and the committed result
tables in reports/tables/. Uses the project's own code paths: the train-only Preprocessor, the MLP, the
val-calibrated thresholds (evaluation/calibration.py) and the constrained black-box attacker
(attacks/evasion.py, same search order as `evade`). No numbers are typed in by hand.

    python -m uvicorn demo.app:app --port 8000      (from the repo root; then open http://127.0.0.1:8000)

Binds to localhost only; this is a demonstration tool, not the secured endpoint (serving/app.py).
"""
from __future__ import annotations

import csv
import itertools
import json
import sys
from pathlib import Path

import numpy as np
import torch
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from federated_ids.attacks.evasion import PADDING, SLOWDOWN, apply_perturbation, check_constraints  # noqa: E402
from federated_ids.data.preprocess import Preprocessor  # noqa: E402
from federated_ids.evaluation.calibration import attack_score, predict_with_threshold  # noqa: E402
from federated_ids.models.mlp import MLP, predict_proba  # noqa: E402

BUNDLE = ROOT / "demo" / "bundle"
TABLES = ROOT / "reports" / "tables"
R_MIN = min(SLOWDOWN)
RULES = {"argmax": "argmax (most probable class)", "fpr5": "5 % benign-FPR threshold", "fpr1": "1 % benign-FPR threshold"}

META = json.loads((BUNDLE / "meta.json").read_text(encoding="utf-8"))
FEATURES, CLASSES, BENIGN = META["features"], META["class_names"], META["benign"]
PRE = Preprocessor.from_json(BUNDLE / "preprocessor.json")
WINDOWS = {w["id"]: w for w in json.loads((BUNDLE / "windows.json").read_text(encoding="utf-8"))}
TTL_CHOICES = META["ttl_choices"]
torch.set_num_threads(2)


def _load(name: str) -> MLP:
    m = MLP(len(FEATURES), len(CLASSES), META["hidden"], META["dropout"])
    m.load_state_dict(torch.load(BUNDLE / META["models"][name]["file"], map_location="cpu"))
    return m.eval()


MODELS = {k: _load(k) for k in META["models"]}


def proba(model: str, X: np.ndarray) -> np.ndarray:
    return predict_proba(MODELS[model], PRE.transform(X))


def decide(model: str, rule: str, P: np.ndarray) -> np.ndarray:
    if rule == "argmax":
        return P.argmax(1)
    return predict_with_threshold(P, BENIGN, META["models"][model]["thresholds"][rule])


def raw(wid: int) -> np.ndarray:
    if wid not in WINDOWS:
        raise HTTPException(404, f"unknown window {wid}")
    return np.array([[np.nan if v is None else v for v in WINDOWS[wid]["x"]]], dtype=np.float64)


def verdict(model: str, rule: str, X: np.ndarray) -> dict:
    P = proba(model, X)
    k = int(decide(model, rule, P)[0])
    return {"label": CLASSES[k], "is_attack": k != BENIGN, "attack_score": float(attack_score(P, BENIGN)[0]),
            "threshold": None if rule == "argmax" else META["models"][model]["thresholds"][rule],
            "proba": {c: float(p) for c, p in zip(CLASSES, P[0])}}


app = FastAPI(title="Federated IDS demo", docs_url=None, redoc_url=None)


class Req(BaseModel):
    id: int
    model: str = "frozen"
    rule: str = "fpr1"


def _check(r: Req) -> None:
    if r.model not in MODELS:
        raise HTTPException(422, f"model must be one of {list(MODELS)}")
    if r.rule not in RULES:
        raise HTTPException(422, f"rule must be one of {list(RULES)}")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(ROOT / "demo" / "static" / "index.html")


@app.get("/api/meta")
def meta() -> dict:
    return {"classes": CLASSES, "rules": RULES, "models": {k: v["source"] for k, v in META["models"].items()},
            "thresholds": {k: v["thresholds"] for k, v in META["models"].items()}, "ttl_choices": TTL_CHOICES,
            "windows": [{"id": w["id"], "family": w["family"], "attack": w["attack"]} for w in WINDOWS.values()]}


@app.post("/api/detect")
def detect(r: Req) -> dict:
    _check(r)
    w = WINDOWS.get(r.id) or {}
    X = raw(r.id)
    return {"window": {"id": r.id, "family": w["family"], "attack": w["attack"],
                       "features": dict(zip(FEATURES, w["x"]))},
            "result": verdict(r.model, r.rule, X)}


@app.post("/api/attack")
def attack(r: Req) -> dict:
    """Black-box, label-only search exactly as attacks/evasion.evade (larger r first, then smaller padding,
    original TTL first); every query is recorded so the dashboard can replay it."""
    _check(r)
    X0 = raw(r.id)
    start = verdict(r.model, r.rule, X0)
    if not start["is_attack"]:
        return {"start": start, "detected": False, "trace": [], "evaded": False}
    rs = sorted([s for s in SLOWDOWN if s >= R_MIN - 1e-12], reverse=True)
    trace, found = [], None
    for s, p, t in itertools.product(rs, PADDING, TTL_CHOICES):
        Z = apply_perturbation(X0, FEATURES, p, s, t)
        v = verdict(r.model, r.rule, Z)
        trace.append({"r": s, "padding": p, "ttl": t, "label": v["label"], "attack_score": v["attack_score"]})
        if not v["is_attack"]:
            found = (s, p, t, Z)
            break
    out = {"start": start, "detected": True, "trace": trace, "queries": len(trace),
           "grid_size": len(rs) * len(PADDING) * len(TTL_CHOICES), "evaded": found is not None}
    if found:
        s, p, t, Z = found
        out["perturbation"] = {"r": s, "padding": p, "ttl": t}
        out["constraint_violations"] = check_constraints(X0, Z, FEATURES, R_MIN)
        out["changed_features"] = [{"feature": f, "before": None if np.isnan(a) else float(a),
                                    "after": None if np.isnan(b) else float(b)}
                                   for f, a, b in zip(FEATURES, X0[0], Z[0]) if not (a == b or (np.isnan(a) and np.isnan(b)))]
        # the same disguised window against the other model (same rule)
        other = "hardened" if r.model == "frozen" else "frozen"
        out["other_model"] = {"model": other, "result": verdict(other, r.rule, Z)}
    return out


class BatchReq(BaseModel):
    model: str = "frozen"
    rule: str = "fpr1"


@app.post("/api/scan")
def scan(r: BatchReq) -> dict:
    """Classify all demo windows: benign false alarms and per-class detection."""
    _check(Req(id=0, model=r.model, rule=r.rule))
    ids = list(WINDOWS)
    X = np.vstack([raw(i) for i in ids])
    pred = decide(r.model, r.rule, proba(r.model, X))
    out: dict = {}
    for i, k in zip(ids, pred):
        f = WINDOWS[i]["family"]
        o = out.setdefault(f, {"n": 0, "flagged": 0, "correct_class": 0})
        o["n"] += 1
        o["flagged"] += int(k != BENIGN)
        o["correct_class"] += int(CLASSES[int(k)] == f)
    return {"per_class": out}


@app.post("/api/attack_all")
def attack_all(r: BatchReq) -> dict:
    """Run the attacker on every detected attack window (same search as /api/attack and evade())."""
    from federated_ids.attacks.evasion import evade
    _check(Req(id=0, model=r.model, rule=r.rule))
    ids = [i for i, w in WINDOWS.items() if w["family"] != "Benign"]
    X = np.vstack([raw(i) for i in ids])
    dec = lambda Z: decide(r.model, r.rule, proba(r.model, Z))  # noqa: E731
    det = dec(X) != BENIGN
    e = evade(dec, X[det], FEATURES, BENIGN, TTL_CHOICES, R_MIN)
    ev = np.zeros(len(ids), bool)
    ev[det] = e["evaded"]
    fam: dict = {}
    for i, d, v in zip(ids, det, ev):
        o = fam.setdefault(WINDOWS[i]["family"], {"n": 0, "detected": 0, "evaded": 0})
        o["n"] += 1
        o["detected"] += int(d)
        o["evaded"] += int(v)
    return {"n": len(ids), "detected": int(det.sum()), "evaded": int(ev.sum()), "per_family": fam,
            "mean_queries": float(e["queries"].mean()) if len(e["queries"]) else 0.0}


def _rows(name: str) -> list[dict]:
    p = TABLES / f"{name}.csv"
    if not p.exists():
        return []
    with open(p, encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


@app.get("/api/federated")
def federated() -> dict:
    fl = META["flower"]
    wp4 = [r for r in _rows("wp4_federated") if r["task"] == "category" and r["operating_point"] == "fpr1"
           and r["variant"] == "base" and r["arch"] == "v2"]
    by_part: dict = {}
    for r in wp4:
        by_part.setdefault(r["partition"], []).append(float(r["attack_detection_rate"]))
    return {"flower": fl, "wp4_detection_at_1pct": {k: float(np.mean(v)) for k, v in by_part.items()}}


@app.get("/api/results")
def results() -> dict:
    det: dict = {}
    for r in _rows("wp3_test_operating_points"):
        if r["split"] != "test" or r["operating_point"] not in ("argmax", "fpr1") or r["detector"] not in ("v2_mlp", "hgb"):
            continue
        det.setdefault((r["task"], r["detector"], r["operating_point"]), []).append(
            (float(r["attack_detection_rate"]), float(r["benign_fpr"])))
    detection = [{"task": t, "detector": d, "rule": o, "detection": float(np.mean([x[0] for x in v])),
                  "benign_fpr": float(np.mean([x[1] for x in v]))} for (t, d, o), v in sorted(det.items())]
    wp5 = [{"task": r["task"], "model": r["model"], "round": int(r["round"]),
            "evasion": float(r["evasion_r0.1"]), "robust_detection": float(r["robust_det_r0.1"])}
           for r in _rows("wp5_advtrain_summary") if r["operating_point"] == "fpr1"]
    wp6 = [{"features": r["feature_set"], "llm": r["held_out_llm"].split("/")[-1], "auc": float(r["roc_auc"]),
            "session_detection": float(r["session_detection"])} for r in _rows("wp6_gridstrat_no_arp")]
    return {"detection": detection, "advtrain": wp5, "gridstrat_no_arp": wp6}
