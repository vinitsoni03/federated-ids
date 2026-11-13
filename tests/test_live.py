"""Real-capture scoring: pcap/pcapng reading, header parsing and CICIoT2023 window features."""
import struct

import numpy as np
import pytest

from federated_ids.live.features import ALL_FEATURES, window_row, windows
from federated_ids.live.pcap import ACK, PSH, SYN, read_packets


def eth(etype: int, payload: bytes) -> bytes:
    return b"\x02" * 6 + b"\x04" * 6 + struct.pack("!H", etype) + payload


def ipv4(proto: int, ttl: int, l4: bytes) -> bytes:
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0, ttl, proto, 0, b"\x0a\0\0\1", b"\x0a\0\0\2") + l4


def ipv6(nxt: int, hop: int, l4: bytes) -> bytes:
    return struct.pack("!IHBB16s16s", 6 << 28, len(l4), nxt, hop, b"\0" * 16, b"\0" * 16) + l4


def tcp(sport: int, dport: int, flags: int, hdr: int = 32, payload: int = 0) -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, (hdr // 4) << 4, flags, 0, 0, 0) + b"\0" * (hdr - 20 + payload)


def udp(sport: int, dport: int, payload: int = 0) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + payload, 0) + b"\0" * payload


ARP = eth(0x0806, b"\0" * 28)                                                 # 42 bytes -> padded to 60
FRAMES = [  # (time s, frame)
    (0.000, eth(0x0800, ipv4(6, 64, tcp(50000, 443, ACK | PSH, payload=1000)))),   # 1066 B
    (0.010, eth(0x0800, ipv4(6, 128, tcp(443, 50000, ACK)))),                      # 66 B
    (0.020, eth(0x0800, ipv4(17, 64, udp(53000, 53, 40)))),                        # 82 B
    (0.040, ARP),
    (0.040, eth(0x86DD, ipv6(6, 255, tcp(80, 50001, SYN | ACK, hdr=40)))),         # 94 B
    (0.050, eth(0x888E, b"\0" * 50)),                                              # EAPOL: skipped
    (0.060, eth(0x0800, ipv4(1, 64, b"\x08\0" + b"\0" * 6))),                      # ICMP, 42 -> 60 B
    (0.080, eth(0x0800, ipv4(6, 64, tcp(50000, 443, ACK)))),
    (0.090, eth(0x0800, ipv4(6, 64, tcp(50000, 22, ACK, hdr=20)))),                # 54 -> 60 B
    (0.100, eth(0x0800, ipv4(17, 64, udp(68, 67, 300)))),                          # 342 B
    (0.150, eth(0x0800, ipv4(6, 64, tcp(50000, 443, ACK)))),
]


def write_pcap(path, frames):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for t, d in frames:
            sec = 1_700_000_000 + int(t)
            f.write(struct.pack("<IIII", sec, round((t % 1) * 1e6), len(d), len(d)) + d)


def write_pcapng(path, frames, tsresol_ns=True):
    def block(btype, body):
        body += b"\0" * (-len(body) % 4)
        n = len(body) + 12
        return struct.pack("<II", btype, n) + body + struct.pack("<I", n)
    opts = (struct.pack("<HHB3x", 9, 1, 9) if tsresol_ns else b"") + struct.pack("<HH", 0, 0)
    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack("<HHI", 1, 0, 0) + opts)
    unit = 1e9 if tsresol_ns else 1e6
    for t, d in frames:
        ts = round((1_700_000_000 + t) * unit)
        out += block(6, struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(d), len(d)) + d)
    path.write_bytes(out)


@pytest.mark.parametrize("fmt", ["pcap", "pcapng_ns", "pcapng_us"])
def test_reader_and_parser(tmp_path, fmt):
    p = tmp_path / f"c.{fmt}"
    if fmt == "pcap":
        write_pcap(p, FRAMES)
    else:
        write_pcapng(p, FRAMES, tsresol_ns=fmt == "pcapng_ns")
    pk, counts = read_packets(p)
    assert counts == {"frames": 11, "ip_or_arp": 10, "skipped_non_ip": 1}
    assert [x.length for x in pk] == [1066, 66, 82, 60, 94, 60, 66, 60, 342, 66]
    assert [x.proto for x in pk] == [6, 6, 17, 0, 6, 1, 6, 6, 17, 6]
    assert [x.ttl for x in pk] == [64, 128, 64, 0, 255, 64, 64, 64, 64, 64]
    assert [x.header_len for x in pk] == [32, 32, 8, 0, 40, 0, 32, 20, 8, 32]
    assert pk[4].tcp_flags == SYN | ACK and pk[4].sport == 80
    assert abs(pk[9].ts - pk[0].ts - 0.150) < 1e-6


def test_window_features_match_definitions(tmp_path):
    p = tmp_path / "c.pcap"
    write_pcap(p, FRAMES)
    pk, _ = read_packets(p)
    X, starts = windows(pk, 10)
    assert X.shape == (1, len(ALL_FEATURES)) and starts[0] == pk[0].ts
    r = dict(zip(ALL_FEATURES, X[0]))
    lengths = np.array([1066, 66, 82, 60, 94, 60, 66, 60, 342, 66], float)
    gaps = np.array([0.010, 0.010, 0.020, 0.000, 0.020, 0.020, 0.010, 0.010, 0.050])  # EAPOL frame removed
    expect = {
        "Header_Length": 20.4, "Protocol Type": 6, "Time_To_Live": (64 * 7 + 128 + 255) / 10,
        "fin_flag_number": 0, "syn_flag_number": 0.1, "rst_flag_number": 0, "psh_flag_number": 0.1,
        "ack_flag_number": 0.6, "ece_flag_number": 0, "cwr_flag_number": 0,
        "ack_count": 6, "syn_count": 1, "fin_count": 0, "rst_count": 0,
        "HTTP": 0.1, "HTTPS": 0.4, "DNS": 0.1, "Telnet": 0, "SMTP": 0, "SSH": 0.1, "IRC": 0, "DHCP": 0.1,
        "TCP": 0.6, "UDP": 0.2, "ARP": 0.1, "ICMP": 0.1, "IGMP": 0, "IPv": 0.9, "LLC": 0.9,
        "Tot sum": lengths.sum(), "Min": 60, "Max": 1066, "AVG": lengths.mean(), "Tot size": lengths.mean(),
        "Std": lengths.std(ddof=1), "Variance": lengths.var(ddof=1), "IAT": gaps.mean(), "Number": 10,
    }
    for k, v in expect.items():
        assert r[k] == pytest.approx(v, abs=1e-6), k
    assert np.isinf(r["Rate"])  # one gap is 0 (ARP and IPv6 packet at the same time), as in the dataset


def test_rate_is_mean_inverse_gap_and_partial_window_dropped(tmp_path):
    p = tmp_path / "c.pcap"
    frames = [(i * 0.01 + (0.01 if i >= 5 else 0), eth(0x0800, ipv4(6, 64, tcp(1, 443, ACK)))) for i in range(23)]
    write_pcap(p, frames)
    pk, _ = read_packets(p)
    X, _ = windows(pk, 10)
    assert X.shape[0] == 2
    r = dict(zip(ALL_FEATURES, X[1]))
    gaps = np.diff([t for t, _ in frames])[9:19]
    assert r["Rate"] == pytest.approx(np.mean(1 / gaps), rel=1e-4)  # pcap stores microseconds
    assert r["Rate"] * r["IAT"] >= 1


def test_protocol_type_is_mode_with_low_tie_break():
    from federated_ids.live.pcap import Packet
    mk = lambda proto, arp=False: Packet(0.0, 60, arp, not arp, 0 if arp else proto, 64, 0, 0, 0, 0)  # noqa: E731
    gap = np.full(10, 0.01)
    assert window_row([mk(6)] * 5 + [mk(17)] * 5, gap)["Protocol Type"] == 6
    assert window_row([mk(6)] * 4 + [mk(17)] * 6, gap)["Protocol Type"] == 17
    assert window_row([mk(0, arp=True)] * 4 + [mk(6)] * 3 + [mk(17)] * 3, gap)["Protocol Type"] == 0


def test_score_cli_writes_outputs(tmp_path):
    pytest.importorskip("torch")
    from federated_ids.live.score import main
    p = tmp_path / "c.pcap"
    write_pcap(p, [(i * 0.01, d) for i, (_, d) in enumerate(FRAMES * 3)])
    assert main([str(p), "--out", str(tmp_path / "out")]) == 0
    import json
    s = json.loads((tmp_path / "out" / "c" / "summary.json").read_text())
    assert s["windows"] == 3 and set(s["models"]) == {"frozen", "hardened"}
    for m in s["models"].values():
        assert 0 <= m["fpr1"]["alarm_rate"] <= m["fpr5"]["alarm_rate"] + 1e-9
    assert (tmp_path / "out" / "c" / "scores.csv").read_text().count("\n") == 4
