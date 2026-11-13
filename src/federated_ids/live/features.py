"""CICIoT2023 window features from parsed packets.

The dataset's rows are consecutive, non-overlapping windows of packets taken from each capture in
order (all flows mixed): 10 packets for non-flood traffic, 100 for DDoS/DoS/Mirai (Neto et al. 2023,
sec. 4; `Number` is 10 or 100). The definitions below were derived from the local CSV release and
checked against it (BenignTraffic.pcap.csv, 362,361 rows):

* fractions of packets in the window: flag columns, HTTP ... IRC, TCP ... IGMP, IPv, LLC
  (IPv + ARP = 1 and LLC = IPv in every benign row);
* Protocol Type = most common IP protocol in the window (ties -> lowest; ARP counts as 0):
  always an integer, and 6 whenever TCP >= 0.5;
* Header_Length = mean transport header length (TCP data offset, UDP 8, ARP 0): within +-2.4 of
  32*TCP + 8*UDP for 90 % of rows; all-UDP rows are exactly 8, all-ARP rows 0;
* Time_To_Live = mean TTL / hop limit (ARP 0);
* IAT = mean gap to the previous packet; Rate = mean of 1/gap (Rate * IAT >= 1, inf when a gap is 0);
* Min, Max, AVG = Tot size, Tot sum over frame lengths (>= 60 bytes); Std = sample std (ddof 1;
  80.7 % of two-size windows match it exactly, none match ddof 0); Variance = Std**2;
* *_count = number of packets with the flag; Number = packets in the window.

Application columns are decided by port (either direction), as the dataset does not inspect payloads.
"""
from __future__ import annotations

from collections import Counter

import numpy as np

from federated_ids.live.pcap import ACK, CWR, ECE, FIN, PSH, RST, SYN, Packet

ALL_FEATURES = ["Header_Length", "Protocol Type", "Time_To_Live", "Rate", "fin_flag_number", "syn_flag_number",
                "rst_flag_number", "psh_flag_number", "ack_flag_number", "ece_flag_number", "cwr_flag_number",
                "ack_count", "syn_count", "fin_count", "rst_count", "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH",
                "IRC", "TCP", "UDP", "DHCP", "ARP", "ICMP", "IGMP", "IPv", "LLC", "Tot sum", "Min", "Max", "AVG",
                "Std", "Tot size", "IAT", "Number", "Variance"]

PORTS = {"HTTP": {80}, "HTTPS": {443}, "DNS": {53}, "Telnet": {23}, "SMTP": {25}, "SSH": {22},
         "IRC": {194, 6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669}, "DHCP": {67, 68}}
FLAGS = {"fin": FIN, "syn": SYN, "rst": RST, "psh": PSH, "ack": ACK, "ece": ECE, "cwr": CWR}


def gaps(packets: list[Packet]) -> np.ndarray:
    """Gap of each packet to the one before it in the capture; the first packet has none (NaN)."""
    ts = np.array([p.ts for p in packets], dtype=np.float64)
    return np.concatenate([[np.nan], np.diff(ts)]) if len(ts) else ts


def window_row(packets: list[Packet], gap: np.ndarray) -> dict[str, float]:
    n = len(packets)
    tcp = [p for p in packets if p.is_ip and p.proto == 6]
    lengths = np.array([p.length for p in packets], dtype=np.float64)
    protos = Counter(0 if p.is_arp else p.proto for p in packets)
    top = max(protos.values())
    row: dict[str, float] = {
        "Header_Length": float(np.mean([p.header_len for p in packets])),
        "Protocol Type": float(min(k for k, v in protos.items() if v == top)),
        "Time_To_Live": float(np.mean([p.ttl for p in packets])),
    }
    g = gap[~np.isnan(gap)]
    with np.errstate(divide="ignore"):
        row["Rate"] = float(np.mean(1.0 / g)) if len(g) else float("nan")
    for name, bit in FLAGS.items():
        row[f"{name}_flag_number"] = sum(bool(p.tcp_flags & bit) for p in tcp) / n
    for name in ("ack", "syn", "fin", "rst"):
        row[f"{name}_count"] = float(sum(bool(p.tcp_flags & FLAGS[name]) for p in tcp))
    for name, ports in PORTS.items():
        row[name] = sum(p.is_ip and p.proto in (6, 17) and (p.sport in ports or p.dport in ports)
                        for p in packets) / n
    row["TCP"] = len(tcp) / n
    row["UDP"] = sum(p.is_ip and p.proto == 17 for p in packets) / n
    row["ARP"] = sum(p.is_arp for p in packets) / n
    row["ICMP"] = sum(p.is_ip and p.proto in (1, 58) for p in packets) / n
    row["IGMP"] = sum(p.is_ip and p.proto == 2 for p in packets) / n
    row["IPv"] = row["LLC"] = sum(p.is_ip for p in packets) / n
    std = float(np.std(lengths, ddof=1)) if n > 1 else 0.0
    row.update({"Tot sum": float(lengths.sum()), "Min": float(lengths.min()), "Max": float(lengths.max()),
                "AVG": float(lengths.mean()), "Std": std, "Tot size": float(lengths.mean()),
                "IAT": float(np.mean(g)) if len(g) else float("nan"), "Number": float(n), "Variance": std ** 2})
    return {k: row[k] for k in ALL_FEATURES}


def windows(packets: list[Packet], size: int = 10) -> tuple[np.ndarray, np.ndarray]:
    """Feature matrix (rows x ALL_FEATURES) of the full, non-overlapping windows, and each window's
    start time. A trailing partial window is dropped."""
    gap = gaps(packets)
    rows, starts = [], []
    for i in range(0, len(packets) - size + 1, size):
        rows.append(list(window_row(packets[i:i + size], gap[i:i + size]).values()))
        starts.append(packets[i].ts)
    X = np.array(rows, dtype=np.float64).reshape(-1, len(ALL_FEATURES))
    return X, np.array(starts, dtype=np.float64)
