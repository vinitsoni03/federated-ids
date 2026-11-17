"""Live monitor: score this laptop's own traffic while it happens (e.g. during a YouTube video).

    python scripts/live_monitor.py [--interface Wi-Fi] [--slice 2] [--seconds 0]

dumpcap (Wireshark/Npcap) writes the traffic in short slices (ring buffer); each finished slice is read,
cut into the dataset's 10-packet windows and scored by the demo bundle's frozen and hardened detectors
(same code path as federated_ids.live.score). One line is printed per slice; Ctrl+C (or --seconds)
stops it and prints the totals. Slices are deleted as soon as they are scored, nothing is kept.
All of this traffic is normal, so every alarm is a false alarm (report section 4.2).
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from federated_ids.live.features import ALL_FEATURES, window_row  # noqa: E402
from federated_ids.live.pcap import read_packets  # noqa: E402
from federated_ids.live.score import Detector, service  # noqa: E402

DUMPCAP = r"C:\Program Files\Wireshark\dumpcap.exe"
SIZE = 10  # packets per window, as in CICIoT2023


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--interface", default="Wi-Fi")
    ap.add_argument("--slice", type=int, default=2, help="seconds per capture slice")
    ap.add_argument("--seconds", type=int, default=0, help="stop after this many seconds (0 = until Ctrl+C)")
    ap.add_argument("--dir", type=Path, default=Path(r"D:\federated-ids-work\captures\live_stream"))
    a = ap.parse_args()

    det = Detector()
    shutil.rmtree(a.dir, ignore_errors=True)
    a.dir.mkdir(parents=True, exist_ok=True)
    # ring buffer: a new file every --slice seconds, at most 50 files on disk
    cap = subprocess.Popen([DUMPCAP, "-i", a.interface, "-q", "-b", f"duration:{a.slice}", "-b", "files:50",
                            "-w", str(a.dir / "slice.pcapng")], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    print(f"Live on '{a.interface}' - play the video now. Ctrl+C to stop.\n")
    print(f"{'time':>6} {'windows':>7}  {'frozen 1%':>9} {'hardened 1%':>11}  traffic")

    buf, prev_ts = [], None          # packets not yet in a full window, timestamp of the packet before them
    tot = {"windows": 0, "frozen": 0, "hardened": 0}
    svc_tot, t0 = Counter(), time.time()

    def score(files: list[Path]) -> None:
        nonlocal buf, prev_ts
        for f in files:
            pk, _ = read_packets(f)
            f.unlink(missing_ok=True)
            buf.extend(pk)
        n = len(buf) // SIZE * SIZE
        if not n:
            return
        ts = np.array([p.ts for p in buf[:n]])
        gap = np.diff(ts, prepend=prev_ts if prev_ts is not None else np.nan)
        rows = [window_row(buf[i:i + SIZE], gap[i:i + SIZE]) for i in range(0, n, SIZE)]
        prev_ts, buf = buf[n - 1].ts, buf[n:]
        X = np.array([list(r.values()) for r in rows], dtype=np.float64).reshape(-1, len(ALL_FEATURES))
        V = det.verdicts(X)
        fz = int((V["frozen"]["fpr1"] != det.benign).sum())
        hd = int((V["hardened"]["fpr1"] != det.benign).sum())
        svc = Counter(service(r) for r in rows)
        tot["windows"] += len(rows)
        tot["frozen"] += fz
        tot["hardened"] += hd
        svc_tot.update(svc)
        top = ", ".join(f"{k} {v}" for k, v in svc.most_common(3))
        print(f"{time.time() - t0:5.0f}s {len(rows):7d}  {fz:4d} ({fz / len(rows):4.0%}) {hd:5d} ({hd / len(rows):4.0%})  {top}",
              flush=True)

    try:
        while cap.poll() is None:
            if a.seconds and time.time() - t0 >= a.seconds:
                break
            files = sorted(a.dir.glob("slice_*.pcapng"))
            score(files[:-1])          # the newest file is still being written
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        if cap.poll() is None:
            cap.terminate()
            cap.wait(timeout=10)
    if cap.returncode not in (0, 1, None) and not tot["windows"]:
        print("dumpcap failed:", cap.stderr.read().decode(errors="replace").strip())
    score(sorted(a.dir.glob("slice_*.pcapng")))
    shutil.rmtree(a.dir, ignore_errors=True)

    w = tot["windows"]
    print(f"\nTotal: {w} windows in {time.time() - t0:.0f} s, traffic {dict(svc_tot.most_common(5))}")
    if w:
        print(f"False alarms at the 1 % rule: frozen {tot['frozen'] / w:.1%}, hardened {tot['hardened'] / w:.1%}")
        print("(all of this is normal traffic - every alarm is a false alarm; see report section 4.2)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
