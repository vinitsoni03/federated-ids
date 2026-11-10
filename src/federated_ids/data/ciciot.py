"""CICIoT2023 (local per-attack CSV layout): label mapping, Parquet conversion, row hashes.

Local layout (verified 2026-10-25): ROOT/<attack folder>/<name>.pcap.csv, 309 CSV files in
34 folders, 39 feature columns, NO label column. The class label is therefore taken from the
folder name. Evidence for that mapping (see reports/dataset_audit.md):
  * the 34 folder names are the 33 attack names + Benign listed in Neto et al. (2023), Table 3;
  * every file name inside a folder repeats the folder's attack name;
  * per-class protocol indicators are consistent with the attack (checked by
    `federated_ids.data.label_checks`).
The 7-category grouping (+ Benign) follows Neto et al. (2023), Sec. 3 / Table 3.

Conversion writes one Parquet file per source CSV (features as float64, unchanged values,
plus file_id and row index) and a 64-bit hash of every row's 39 feature values, so that
duplicate and cross-label-duplicate analysis does not need the CSVs again.
Raw CSVs are only read.

Usage:
    python -m federated_ids.data.ciciot convert RAW_ROOT --work-dir D:/federated-ids-work
        [--compare-root OTHER_COPY]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

FEATURES = [
    "Header_Length", "Protocol Type", "Time_To_Live", "Rate", "fin_flag_number",
    "syn_flag_number", "rst_flag_number", "psh_flag_number", "ack_flag_number",
    "ece_flag_number", "cwr_flag_number", "ack_count", "syn_count", "fin_count", "rst_count",
    "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC", "TCP", "UDP", "DHCP", "ARP",
    "ICMP", "IGMP", "IPv", "LLC", "Tot sum", "Min", "Max", "AVG", "Std", "Tot size", "IAT",
    "Number", "Variance",
]

# folder name -> (class34 canonical name, 7-category + Benign)
FOLDER_MAP: dict[str, tuple[str, str]] = {
    "Benign_Final": ("Benign", "Benign"),
    "DDoS-ACK_Fragmentation": ("DDoS-ACK_Fragmentation", "DDoS"),
    "DDoS-HTTP_Flood": ("DDoS-HTTP_Flood", "DDoS"),
    "DDoS-ICMP_Flood": ("DDoS-ICMP_Flood", "DDoS"),
    "DDoS-ICMP_Fragmentation": ("DDoS-ICMP_Fragmentation", "DDoS"),
    "DDoS-PSHACK_FLOOD": ("DDoS-PSHACK_Flood", "DDoS"),
    "DDoS-RSTFINFLOOD": ("DDoS-RSTFIN_Flood", "DDoS"),
    "DDoS-SlowLoris": ("DDoS-SlowLoris", "DDoS"),
    "DDoS-SynonymousIP_Flood": ("DDoS-SynonymousIP_Flood", "DDoS"),
    "DDoS-SYN_Flood": ("DDoS-SYN_Flood", "DDoS"),
    "DDoS-TCP_Flood": ("DDoS-TCP_Flood", "DDoS"),
    "DDoS-UDP_Flood": ("DDoS-UDP_Flood", "DDoS"),
    "DDoS-UDP_Fragmentation": ("DDoS-UDP_Fragmentation", "DDoS"),
    "DoS-HTTP_Flood": ("DoS-HTTP_Flood", "DoS"),
    "DoS-SYN_Flood": ("DoS-SYN_Flood", "DoS"),
    "DoS-TCP_Flood": ("DoS-TCP_Flood", "DoS"),
    "DoS-UDP_Flood": ("DoS-UDP_Flood", "DoS"),
    "Recon-HostDiscovery": ("Recon-HostDiscovery", "Recon"),
    "Recon-OSScan": ("Recon-OSScan", "Recon"),
    "Recon-PingSweep": ("Recon-PingSweep", "Recon"),
    "Recon-PortScan": ("Recon-PortScan", "Recon"),
    "VulnerabilityScan": ("Recon-VulnerabilityScan", "Recon"),
    "SqlInjection": ("Web-SqlInjection", "Web"),
    "CommandInjection": ("Web-CommandInjection", "Web"),
    "Backdoor_Malware": ("Web-Backdoor_Malware", "Web"),
    "Uploading_Attack": ("Web-Uploading_Attack", "Web"),
    "XSS": ("Web-XSS", "Web"),
    "BrowserHijacking": ("Web-BrowserHijacking", "Web"),
    "DictionaryBruteForce": ("BruteForce-Dictionary", "BruteForce"),
    "MITM-ArpSpoofing": ("Spoofing-ARP", "Spoofing"),
    "DNS_Spoofing": ("Spoofing-DNS", "Spoofing"),
    "Mirai-greeth_flood": ("Mirai-greeth_flood", "Mirai"),
    "Mirai-greip_flood": ("Mirai-greip_flood", "Mirai"),
    "Mirai-udpplain": ("Mirai-udpplain", "Mirai"),
}
CLASS34 = sorted(v[0] for v in FOLDER_MAP.values())
CATEGORIES = ["Benign", "BruteForce", "DDoS", "DoS", "Mirai", "Recon", "Spoofing", "Web"]
CLASS34_TO_CAT = {v[0]: v[1] for v in FOLDER_MAP.values()}
HASH_SEED = 20235941  # fixed seed of hash_matrix


def family_of_class34(y34: np.ndarray) -> np.ndarray:
    """Attack family (category name) of each class34 index."""
    lut = np.array([CLASS34_TO_CAT[c] for c in CLASS34])
    return lut[np.asarray(y34, dtype=np.int64)]


def label_for_folder(folder: str) -> tuple[str, str]:
    if folder not in FOLDER_MAP:
        raise KeyError(f"Unknown CICIoT2023 folder {folder!r}; refusing to guess its label")
    return FOLDER_MAP[folder]


def list_csv_files(root: Path) -> list[Path]:
    files = sorted(p for p in root.rglob("*.csv") if p.is_file())
    if not files:
        raise FileNotFoundError(f"No CSV files under {root}")
    return files


def sha256_of(path: Path, block: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(block):
            h.update(chunk)
    return h.hexdigest()


def read_csv_float(path: Path):
    """Read one CICIoT2023 CSV with every feature as Float64 (values unchanged; 'inf' -> inf)."""
    import polars as pl

    df = pl.read_csv(path, schema_overrides={c: pl.Float64 for c in FEATURES}, infer_schema_length=0)
    if df.columns != FEATURES:
        raise ValueError(f"{path}: unexpected header {df.columns}")
    return df


def _splitmix64(x: np.ndarray) -> np.ndarray:
    x = x + np.uint64(0x9E3779B97F4A7C15)
    x = (x ^ (x >> np.uint64(30))) * np.uint64(0xBF58476D1CE4E5B9)
    x = (x ^ (x >> np.uint64(27))) * np.uint64(0x94D049BB133111EB)
    return x ^ (x >> np.uint64(31))


def hash_matrix(x: np.ndarray, seed: int = HASH_SEED) -> np.ndarray:
    """Deterministic, library-version-independent 64-bit hash of each row of a float64 matrix.
    -0.0 is normalised to 0.0 and every NaN to one canonical NaN, so equal rows hash equally."""
    x = np.array(x, dtype=np.float64, copy=True)
    x[x == 0] = 0.0
    x[np.isnan(x)] = np.nan
    bits = x.view(np.uint64)
    h = np.full(len(x), np.uint64(seed), dtype=np.uint64)
    with np.errstate(over="ignore"):
        for j in range(bits.shape[1]):
            h = _splitmix64(h ^ _splitmix64(bits[:, j] + np.uint64(j)))
    return h


def row_hash(df) -> np.ndarray:
    return hash_matrix(df.select(FEATURES).to_numpy())


def convert(raw_root: Path, work_dir: Path, compare_root: Path | None = None) -> dict:
    import polars as pl

    out_pq = work_dir / "processed" / "ciciot2023" / "parquet"
    out_pq.mkdir(parents=True, exist_ok=True)
    files = list_csv_files(raw_root)
    manifest, hashes, file_ids, rows_idx = [], [], [], []
    t0 = time.time()
    for fid, path in enumerate(files):
        rel = path.relative_to(raw_root)
        folder = rel.parts[0]
        c34, cat = label_for_folder(folder)
        df = read_csv_float(path)
        n = df.height
        h = row_hash(df)
        hashes.append(h)
        file_ids.append(np.full(n, fid, dtype=np.int16))
        rows_idx.append(np.arange(n, dtype=np.int32))
        df.with_columns(pl.lit(fid, dtype=pl.Int16).alias("file_id"),
                        pl.int_range(0, n, dtype=pl.Int32).alias("row")).write_parquet(
            out_pq / f"{fid:03d}.parquet", compression="zstd")
        entry = {"file_id": fid, "rel_path": rel.as_posix(), "folder": folder, "class34": c34,
                 "category": cat, "rows": n, "bytes": path.stat().st_size, "sha256": sha256_of(path)}
        if compare_root is not None:
            other = compare_root / rel
            entry["copy_exists"] = other.is_file()
            entry["copy_sha256_equal"] = other.is_file() and sha256_of(other) == entry["sha256"]
        manifest.append(entry)
        print(f"[{fid + 1}/{len(files)}] {rel.as_posix()} rows={n:,} ({time.time() - t0:.0f}s)", flush=True)

    hdir = work_dir / "processed" / "ciciot2023"
    np.save(hdir / "row_hash.npy", np.concatenate(hashes))
    np.save(hdir / "row_file_id.npy", np.concatenate(file_ids))
    np.save(hdir / "row_index.npy", np.concatenate(rows_idx))
    meta = {
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "raw_root": str(raw_root), "compare_root": str(compare_root) if compare_root else None,
        "n_files": len(files), "total_rows": int(sum(m["rows"] for m in manifest)),
        "features": FEATURES, "hash": {"method": "federated_ids.data.ciciot.hash_matrix (splitmix64 over float64 bits)",
                 "seed": HASH_SEED},
        "seconds": round(time.time() - t0, 1), "files": manifest,
    }
    (hdir / "file_manifest.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("convert")
    c.add_argument("raw_root")
    c.add_argument("--work-dir", required=True)
    c.add_argument("--compare-root", default=None, help="second local copy to compare by SHA-256")
    a = p.parse_args(argv)
    meta = convert(Path(a.raw_root), Path(a.work_dir), Path(a.compare_root) if a.compare_root else None)
    print(f"files={meta['n_files']} rows={meta['total_rows']:,} seconds={meta['seconds']}")
    if a.compare_root:
        same = sum(f["copy_sha256_equal"] for f in meta["files"])
        print(f"identical files in second copy: {same}/{meta['n_files']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
