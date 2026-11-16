"""Inference endpoint for the trained federated IDS model (FastAPI).

Loads a model bundle (MODEL_DIR) made by `scripts/package_model.py`:
  model.pt           - MLP weights (state_dict)
  preprocessor.json  - the train-only fitted preprocessor used in training
  model_meta.json    - features (order), class names, architecture, provenance
Requests send RAW CICIoT2023 window features (the 33 window-invariant columns); the service
applies exactly the training preprocessing, so clients never preprocess themselves.

Security: every endpoint except /health requires the header `X-API-Key` equal to the API_KEY
environment variable (constant-time comparison; the service refuses to start without one).
Requests are limited to MAX_ROWS rows. Run behind TLS (uvicorn --ssl-certfile/--ssl-keyfile).

    API_KEY=... MODEL_DIR=... uvicorn serving.app:app --host 0.0.0.0 --port 8443 \
        --ssl-certfile cert.pem --ssl-keyfile key.pem
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path

import numpy as np
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from serving.bundle import Bundle

# cap on rows per request so one call can't eat all the memory
MAX_ROWS = int(os.environ.get("MAX_ROWS", "10000"))


def _load() -> Bundle:
    md = os.environ.get("MODEL_DIR")
    if not md:
        raise RuntimeError("MODEL_DIR is not set")
    return Bundle(Path(md))


# no key, no start. Better to crash at boot than run an open endpoint by mistake
API_KEY = os.environ.get("API_KEY", "").strip()  # a key file written on Windows ends in \r\n
if len(API_KEY) < 16:
    raise RuntimeError("API_KEY must be set (>= 16 characters)")
BUNDLE = _load()
app = FastAPI(title="Federated IDS inference", version="1.0",
              description="Classifies CICIoT2023-style 10/100-packet feature windows.")


# compare_digest takes the same time whether the key is close or not, so it can't be guessed char by char
def require_key(x_api_key: str = Header(default="")) -> None:
    if not secrets.compare_digest(x_api_key.encode(), API_KEY.encode()):
        raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")


# None is allowed for a value, pydantic turns missing/garbage types into a 422
class PredictRequest(BaseModel):
    rows: list[dict[str, float | None]] = Field(..., description="one dict per window: feature name -> raw value")


# no key needed here, the Azure health check and the smoke test hit this
@app.get("/health")
def health() -> dict:
    return {"status": "ok", "task": BUNDLE.meta["task"], "n_features": len(BUNDLE.features)}


@app.get("/model", dependencies=[Depends(require_key)])
def model_info() -> dict:
    return {k: BUNDLE.meta[k] for k in ("task", "class_names", "features", "source_run", "trained_with")}


@app.post("/predict", dependencies=[Depends(require_key)])
def predict(req: PredictRequest) -> dict:
    if not req.rows:
        raise HTTPException(status_code=422, detail="rows is empty")
    if len(req.rows) > MAX_ROWS:
        raise HTTPException(status_code=413, detail=f"at most {MAX_ROWS} rows per request")
    # every row needs all 33 features, in any order, extra keys are ignored
    missing = sorted({f for r in req.rows for f in BUNDLE.features if f not in r})
    if missing:
        raise HTTPException(status_code=422, detail=f"missing features: {missing[:10]}")
    # None / NaN / +-inf are allowed: the preprocessor imputes them with train medians
    X = np.array([[np.nan if (v := r[f]) is None else float(v) for f in BUNDLE.features] for r in req.rows],
                 dtype=np.float64)
    proba = BUNDLE.predict(X)
    # plain argmax here, the endpoint returns the class plus how sure the model is
    pred = proba.argmax(1)
    return {"predictions": [{"label": BUNDLE.classes[int(k)], "is_attack": bool(int(k) != BUNDLE.benign),
                             "probability": round(float(p[int(k)]), 6)} for k, p in zip(pred, proba)],
            "n": int(len(pred))}
