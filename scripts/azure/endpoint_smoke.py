"""Smoke-test the inference endpoint with real held-out test windows.

Sends N raw test windows (stratified across classes) over HTTPS (verified against the private
CA), and checks that (1) auth is enforced, (2) every served prediction equals the offline
prediction of the same bundle, and (3) reports served accuracy / benign FPR on the sample.

    python scripts/azure/endpoint_smoke.py --url https://127.0.0.1:18443 --ca .../ca.crt
        --api-key-file .../api_key [--bundle D:/federated-ids-work/azure/stage/model_bundle] [--n 400]
"""
from __future__ import annotations

import argparse
import json
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

import numpy as np


def call(url: str, ctx, key: str | None, payload: dict | None = None):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET",
                                 headers={"Content-Type": "application/json", **({"X-API-Key": key} if key else {})})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=60) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--ca", required=True)
    ap.add_argument("--api-key-file", required=True)
    ap.add_argument("--bundle", default="D:/federated-ids-work/azure/stage/model_bundle")
    ap.add_argument("--n", type=int, default=400)
    a = ap.parse_args()
    import sys as _s
    _s.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from federated_ids.data.dataset import load_split
    from serving.bundle import Bundle

    key = Path(a.api_key_file).read_text().strip()
    ctx = ssl.create_default_context(cafile=a.ca)
    st, h = call(a.url + "/health", ctx, None)
    print("health:", st, h)
    st_noauth, _ = call(a.url + "/predict", ctx, None, {"rows": [{}]})
    print("predict without key ->", st_noauth, "(expected 401)")

    b = Bundle(Path(a.bundle))
    te = load_split("test", b.features, b.meta["task"])
    rng = np.random.default_rng(0)
    per = max(1, a.n // len(b.classes))
    idx = np.concatenate([rng.choice(np.flatnonzero(te.y == k), min(per, int((te.y == k).sum())), replace=False)
                          for k in range(len(b.classes)) if (te.y == k).any()])
    X = te.X[idx]
    rows = [{f: (None if not np.isfinite(v) else float(v)) for f, v in zip(b.features, x)} for x in X]
    st, out = call(a.url + "/predict", ctx, key, {"rows": rows})
    print("predict with key ->", st)
    served = np.array([b.classes.index(p["label"]) for p in out["predictions"]])
    offline = b.predict(X).argmax(1)
    agree = float((served == offline).mean())
    y = te.y[idx]
    ben = b.benign
    print(f"rows {len(idx)}; served == offline: {agree:.4f}; served accuracy on sample {float((served == y).mean()):.4f}; "
          f"benign FPR on sample {float((served[y == ben] != ben).mean()):.4f}")
    ok = h is not None and st_noauth == 401 and st == 200 and agree == 1.0
    print("SMOKE TEST", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
