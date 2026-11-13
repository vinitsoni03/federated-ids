"""Score a real capture with the demo bundle's detectors (frozen v2 MLP and WP5-hardened MLP).

    python -m federated_ids.live.score capture.pcapng [more.pcap ...] [--window 10] [--out DIR]

For each capture: packets -> CICIoT2023 windows (features.py) -> the bundle's preprocessor and
models -> verdicts under argmax and the validation-calibrated 5 % / 1 % benign-FPR thresholds.
On traffic known to be benign every alarm is a false alarm, so the alarm rate is directly
comparable to the test-set benign FPR. Outputs go to <work_dir>/live/<capture name>/ (outside the
repository: features.csv, scores.csv, summary.json); no addresses are written.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import torch

from federated_ids.config import data_config, work_dir
from federated_ids.data.preprocess import Preprocessor
from federated_ids.evaluation.calibration import attack_score, predict_with_threshold
from federated_ids.live.features import ALL_FEATURES, PORTS, windows
from federated_ids.live.pcap import read_packets
from federated_ids.models.mlp import MLP, predict_proba

ROOT = Path(__file__).resolve().parents[3]
BUNDLE = ROOT / "demo" / "bundle"
RULES = ("argmax", "fpr5", "fpr1")


class Detector:
    def __init__(self, bundle: Path = BUNDLE):
        self.meta = json.loads((bundle / "meta.json").read_text(encoding="utf-8"))
        self.features, self.classes, self.benign = self.meta["features"], self.meta["class_names"], self.meta["benign"]
        self.pre = Preprocessor.from_json(bundle / "preprocessor.json")
        self.models = {}
        for name, m in self.meta["models"].items():
            net = MLP(len(self.features), len(self.classes), self.meta["hidden"], self.meta["dropout"])
            net.load_state_dict(torch.load(bundle / m["file"], map_location="cpu"))
            self.models[name] = net.eval()

    def columns(self, X_all: np.ndarray) -> np.ndarray:
        """Select the model's 33 features from a matrix in ALL_FEATURES order."""
        return X_all[:, [ALL_FEATURES.index(f) for f in self.features]]

    def verdicts(self, X_all: np.ndarray) -> dict[str, dict]:
        X = self.pre.transform(self.columns(X_all))
        out = {}
        for name, net in self.models.items():
            P = predict_proba(net, X)
            th = self.meta["models"][name]["thresholds"]
            out[name] = {"proba": P, "score": attack_score(P, self.benign), "argmax": P.argmax(1),
                         "fpr5": predict_with_threshold(P, self.benign, th["fpr5"]),
                         "fpr1": predict_with_threshold(P, self.benign, th["fpr1"])}
        return out


def service(row: dict[str, float]) -> str:
    """Name of the dominant traffic type of a window, from its own feature values."""
    apps = {k: row[k] for k in PORTS if row[k] > 0}
    if apps and max(apps.values()) >= 0.5:
        return max(apps, key=apps.get)
    kinds = {"TCP other": row["TCP"] - sum(row[k] for k in ("HTTP", "HTTPS", "Telnet", "SMTP", "SSH", "IRC")),
             "UDP other": row["UDP"] - row["DNS"] - row["DHCP"], "ARP": row["ARP"], "ICMP": row["ICMP"]}
    best = max(kinds, key=kinds.get)
    return best if kinds[best] >= 0.5 else "mixed"


def score_capture(path: Path, det: Detector, size: int, out_root: Path) -> dict:
    packets, counts = read_packets(path)
    X_all, starts = windows(packets, size)
    out = out_root / path.stem
    out.mkdir(parents=True, exist_ok=True)
    t0 = packets[0].ts if packets else 0.0
    summary = {"capture": path.name, **counts, "window": size, "windows": int(len(X_all)),
               "duration_s": round(packets[-1].ts - t0, 1) if packets else 0.0, "models": {}}
    with open(out / "features.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["t_start_s"] + ALL_FEATURES)
        for t, x in zip(starts, X_all):
            w.writerow([round(t - t0, 6)] + [float(v) for v in x])
    if not len(X_all):
        (out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        return summary

    rows = [dict(zip(ALL_FEATURES, x)) for x in X_all]
    services = [service(r) for r in rows]
    V = det.verdicts(X_all)
    for name, v in V.items():
        m = {"mean_attack_score": round(float(v["score"].mean()), 4)}
        for rule in RULES:
            alarm = v[rule] != det.benign
            m[rule] = {"alarms": int(alarm.sum()), "alarm_rate": round(float(alarm.mean()), 4),
                       "predicted": dict(Counter(det.classes[k] for k in v[rule][alarm]).most_common()),
                       "alarms_by_service": dict(Counter(s for s, a in zip(services, alarm) if a).most_common())}
        summary["models"][name] = m
    summary["windows_by_service"] = dict(Counter(services).most_common())
    with open(out / "scores.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["t_start_s", "service"] + [f"{n}_{c}" for n in V for c in ("score", *RULES)])
        for i, t in enumerate(starts):
            w.writerow([round(t - t0, 6), services[i]] + [x for n in V for x in
                        (round(float(V[n]["score"][i]), 6), *(det.classes[V[n][r][i]] for r in RULES))])
    (out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def print_summary(s: dict) -> None:
    print(f"\n{s['capture']}: {s['frames']} frames, {s['ip_or_arp']} IP/ARP packets "
          f"({s['skipped_non_ip']} other skipped), {s['duration_s']} s, {s['windows']} windows of {s['window']}")
    if not s["windows"]:
        print("  no full window - capture more traffic")
        return
    print(f"  traffic: {s['windows_by_service']}")
    for name, m in s["models"].items():
        rates = "  ".join(f"{r} {m[r]['alarm_rate']:.1%} ({m[r]['alarms']})" for r in RULES)
        print(f"  {name:9s} alarm rate: {rates}")
        if m["fpr1"]["alarms"]:
            print(f"            at 1 % FPR flagged as {m['fpr1']['predicted']}, by service {m['fpr1']['alarms_by_service']}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("captures", nargs="+", type=Path)
    ap.add_argument("--window", type=int, default=10, help="packets per window (10 = non-flood setting)")
    ap.add_argument("--out", type=Path, default=None, help="output root (default <work_dir>/live)")
    a = ap.parse_args(argv)
    out = a.out or work_dir(data_config(ROOT / "configs" / "data.yaml")) / "live"
    det = Detector()
    for c in a.captures:
        s = score_capture(c, det, a.window, out)
        print_summary(s)
    print(f"\noutputs: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
