"""Real-traffic test: false alarms of the CICIoT2023 detectors on captures that are known to be benign,
and whether recalibrating the threshold on local traffic fixes them.

    python scripts/live_analysis.py [name=]<features.csv> [...]   (features.csv from federated_ids.live.score)

For every capture and model (demo bundle: frozen v2 MLP, WP5-hardened MLP):
* alarm rate at argmax and at the validation-calibrated 5 % / 1 % benign-FPR thresholds; every
  alarm is a false alarm because the captures contain no attacks;
* the same split by window type (TCP-majority vs UDP-majority windows) and with the two timing
  features (Rate, IAT) replaced by the training median, to see which features drive the alarms.
For the first capture: a local threshold for 1 % FPR fitted on its first half (chronological) and
tested on its second half, and what that threshold does to attack detection on the CICIoT2023 test
split (ciciot_v1, 8-class).

Writes reports/tables/live_capture.csv and live_recalibration.csv (aggregate numbers only: no
addresses, hostnames or timestamps).
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from federated_ids.config import data_config, work_dir  # noqa: E402
from federated_ids.evaluation.calibration import threshold_for_fpr  # noqa: E402
from federated_ids.live.features import ALL_FEATURES  # noqa: E402
from federated_ids.live.score import Detector  # noqa: E402

TABLES = ROOT / "reports" / "tables"
TIMING = [ALL_FEATURES.index("Rate"), ALL_FEATURES.index("IAT")]


def alarm(det: Detector, X: np.ndarray, model: str, rule: str) -> float:
    if not len(X):
        return float("nan")
    return float((det.verdicts(X)[model][rule] != det.benign).mean())


def capture_rows(det: Detector, name: str, df: pd.DataFrame) -> list[dict]:
    X = df[ALL_FEATURES].to_numpy(np.float64)
    tcp, udp = (df.TCP >= 0.5).to_numpy(), (df.UDP >= 0.5).to_numpy()
    Xt = X.copy()
    Xt[:, TIMING] = np.nan  # -> imputed with the training median by the preprocessor
    rows = []
    for model in det.models:
        V = det.verdicts(X)[model]
        rows.append({
            "capture": name, "model": model, "windows": len(X), "udp_majority_share": round(udp.mean(), 3),
            **{f"alarm_{r}": round(float((V[r] != det.benign).mean()), 4) for r in ("argmax", "fpr5", "fpr1")},
            "alarm_fpr1_tcp_windows": round(alarm(det, X[tcp], model, "fpr1"), 4),
            "alarm_fpr1_udp_windows": round(alarm(det, X[udp], model, "fpr1"), 4),
            "alarm_fpr1_timing_imputed": round(alarm(det, Xt, model, "fpr1"), 4),
            "top_predicted_fpr1": ", ".join(f"{det.classes[k]} {c}" for k, c in
                                            pd.Series(V["fpr1"][V["fpr1"] != det.benign]).value_counts().head(3).items()),
        })
    return rows


def recalibration(det: Detector, df: pd.DataFrame) -> list[dict]:
    X = df[ALL_FEATURES].to_numpy(np.float64)
    half = len(X) // 2
    test = np.load(work_dir(data_config(ROOT / "configs" / "data.yaml")) / "splits" / "ciciot_v1" / "test.npz")
    Xtest, y8 = test["X"], test["y8"]
    benign_test = y8 == det.benign
    rows = []
    for model in det.models:
        s_live = det.verdicts(X)[model]["score"]
        s_test = det.verdicts(Xtest)[model]["score"]
        t_val = det.meta["models"][model]["thresholds"]["fpr1"]
        t_loc = threshold_for_fpr(s_live[:half], np.ones(half, bool), 0.01)
        for label, t in (("validation 1 % FPR (CICIoT2023)", t_val), ("local 1 % FPR (first half of capture)", t_loc)):
            rows.append({"model": model, "threshold": label, "one_minus_t": f"{1 - t:.1e}",
                         "local_fpr_second_half": round(float((s_live[half:] > t).mean()), 4),
                         "ciciot_test_benign_fpr": round(float((s_test[benign_test] > t).mean()), 4),
                         "ciciot_test_attack_detection": round(float((s_test[~benign_test] > t).mean()), 4)})
    return rows


def main(paths: list[str]) -> int:
    det = Detector()
    named = [a.split("=", 1) if "=" in a else (Path(a).parent.name, a) for a in paths]
    frames = [(name, pd.read_csv(p)) for name, p in named]
    cap = pd.DataFrame([r for name, df in frames for r in capture_rows(det, name, df)])
    rec = pd.DataFrame(recalibration(det, frames[0][1]))
    cap.to_csv(TABLES / "live_capture.csv", index=False)
    rec.to_csv(TABLES / "live_recalibration.csv", index=False)
    pd.set_option("display.width", 250)
    print(cap.to_string(index=False), "\n")
    print(rec.to_string(index=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
