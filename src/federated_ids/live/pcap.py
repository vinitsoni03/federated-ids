"""Pure-Python pcap / pcapng reader and per-packet header parser (no extra packages).

Only what the CICIoT2023 window features need is parsed: timestamp, frame length, ARP or IP,
IP protocol and TTL / hop limit, transport header length, TCP flags and ports. Payloads are never
inspected and no addresses are kept.

Supported link types: Ethernet (1, what Npcap/Wireshark write for Ethernet and Wi-Fi adapters) and
raw IP (101, 228, 229). Frames of other link types are counted and skipped.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator

ETHERNET, RAW_IP, RAW_IPV4, RAW_IPV6 = 1, 101, 228, 229
MIN_FRAME = 60  # Ethernet frames are padded to 60 bytes (without FCS) on the wire

# TCP flag bits
FIN, SYN, RST, PSH, ACK, ECE, CWR = 0x01, 0x02, 0x04, 0x08, 0x10, 0x40, 0x80


@dataclass(frozen=True)
class Frame:
    ts: float          # seconds since the epoch
    wire_len: int      # original length on the wire
    linktype: int
    data: bytes        # captured bytes (may be truncated by the snap length)


@dataclass(frozen=True)
class Packet:
    ts: float
    length: int               # frame length, padded to MIN_FRAME
    is_arp: bool
    is_ip: bool               # IPv4 or IPv6
    proto: int                # IP protocol / IPv6 next header; 0 for ARP
    ttl: int                  # TTL / hop limit; 0 for ARP
    header_len: int           # TCP data offset * 4, 8 for UDP, else 0
    tcp_flags: int            # 0 unless TCP
    sport: int                # 0 unless TCP/UDP
    dport: int


# ------------------------------------------------------------------------------------- readers
def _read_pcap(f: BinaryIO, head: bytes) -> Iterator[Frame]:
    magic = head[:4]
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">", b"\x4d\x3c\xb2\xa1": "<",
              b"\xa1\xb2\x3c\x4d": ">"}[magic]
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    rest = f.read(20)
    linktype = struct.unpack(endian + "I", rest[16:20])[0] & 0x0FFFFFFF
    div = 1e9 if nano else 1e6
    while True:
        rec = f.read(16)
        if len(rec) < 16:
            return
        sec, frac, incl, orig = struct.unpack(endian + "IIII", rec)
        data = f.read(incl)
        if len(data) < incl:
            return
        yield Frame(sec + frac / div, orig, linktype, data)


def _read_pcapng(f: BinaryIO, head: bytes) -> Iterator[Frame]:
    endian = "<"
    interfaces: list[tuple[int, float]] = []  # (linktype, seconds per timestamp unit)
    block = head
    while True:
        if len(block) < 8:
            return
        btype = struct.unpack(endian + "I", block[:4])[0]
        if block[:4] == b"\x0a\x0d\x0d\x0a":  # section header: byte order and a fresh interface list
            bom = f.read(4)
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            btype, blen = 0x0A0D0D0A, struct.unpack(endian + "I", block[4:8])[0]
            body = bom + f.read(blen - 12)
            interfaces = []
        else:
            blen = struct.unpack(endian + "I", block[4:8])[0]
            body = f.read(blen - 8)
        if len(body) < blen - 8 or blen < 12:
            return
        if btype == 0x00000001:  # interface description
            linktype = struct.unpack(endian + "H", body[:2])[0]
            interfaces.append((linktype, _tsresol(body[8:-4], endian)))
        elif btype == 0x00000006:  # enhanced packet
            iface, hi, lo, cap, orig = struct.unpack(endian + "IIIII", body[:20])
            linktype, unit = interfaces[iface]
            yield Frame(((hi << 32) | lo) * unit, orig, linktype, body[20:20 + cap])
        elif btype == 0x00000003:  # simple packet (interface 0, no timestamp)
            orig = struct.unpack(endian + "I", body[:4])[0]
            linktype, _ = interfaces[0]
            yield Frame(float("nan"), orig, linktype, body[4:4 + orig])
        block = f.read(8)


def _tsresol(options: bytes, endian: str) -> float:
    """if_tsresol option (code 9); default is microseconds."""
    i = 0
    while i + 4 <= len(options):
        code, length = struct.unpack(endian + "HH", options[i:i + 4])
        if code == 0:
            break
        if code == 9 and length >= 1:
            v = options[i + 4]
            return 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
        i += 4 + ((length + 3) & ~3)
    return 1e-6


def read_frames(path: str | Path) -> Iterator[Frame]:
    """Yield every captured frame of a pcap or pcapng file, in file order."""
    with open(path, "rb") as f:
        head = f.read(4)
        if head == b"\x0a\x0d\x0d\x0a":
            yield from _read_pcapng(f, head + f.read(4))
        elif head in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
            yield from _read_pcap(f, head)
        else:
            raise ValueError(f"{path}: not a pcap or pcapng file")


# ------------------------------------------------------------------------------------- parser
_IPV6_EXT = {0, 43, 60, 51}  # hop-by-hop, routing, destination options, AH (fragment 44 handled apart)


def parse(frame: Frame) -> Packet | None:
    """Header fields of one frame, or None for frames that are neither IP nor ARP (e.g. EAPOL, LLDP)."""
    d, length = frame.data, max(frame.wire_len, MIN_FRAME)
    if frame.linktype == ETHERNET:
        if len(d) < 14:
            return None
        etype, off = struct.unpack("!H", d[12:14])[0], 14
        while etype in (0x8100, 0x88A8) and len(d) >= off + 4:  # VLAN tags
            etype, off = struct.unpack("!H", d[off + 2:off + 4])[0], off + 4
    elif frame.linktype in (RAW_IP, RAW_IPV4, RAW_IPV6):
        if not d:
            return None
        etype, off = (0x0800 if d[0] >> 4 == 4 else 0x86DD), 0
        length = max(frame.wire_len + 14, MIN_FRAME)  # as if it had an Ethernet header
    else:
        return None

    if etype == 0x0806:
        return Packet(frame.ts, length, True, False, 0, 0, 0, 0, 0, 0)
    if etype == 0x0800 and len(d) >= off + 20:
        ihl = (d[off] & 0x0F) * 4
        ttl, proto = d[off + 8], d[off + 9]
        frag_offset = struct.unpack("!H", d[off + 6:off + 8])[0] & 0x1FFF
        l4 = off + ihl if frag_offset == 0 else None
    elif etype == 0x86DD and len(d) >= off + 40:
        proto, ttl, l4 = d[off + 6], d[off + 7], off + 40
        while proto in _IPV6_EXT | {44} and l4 is not None and len(d) >= l4 + 8:
            if proto == 44:  # fragment header: only the first fragment carries the transport header
                first = struct.unpack("!H", d[l4 + 2:l4 + 4])[0] >> 3 == 0
                proto, l4 = d[l4], (l4 + 8 if first else None)
            else:
                ext_len = (d[l4 + 1] + 2) * 4 if proto == 51 else (d[l4 + 1] + 1) * 8
                proto, l4 = d[l4], l4 + ext_len
    else:
        return None

    header_len = flags = sport = dport = 0
    if l4 is not None:
        if proto == 6 and len(d) >= l4 + 14:
            sport, dport = struct.unpack("!HH", d[l4:l4 + 4])
            header_len, flags = (d[l4 + 12] >> 4) * 4, d[l4 + 13]
        elif proto == 17 and len(d) >= l4 + 4:
            sport, dport = struct.unpack("!HH", d[l4:l4 + 4])
            header_len = 8
    return Packet(frame.ts, length, False, True, proto, ttl, header_len, flags, sport, dport)


def read_packets(path: str | Path) -> tuple[list[Packet], dict]:
    """Parsed IP/ARP packets of a capture (time-ordered as written) and counts of what was skipped."""
    packets, frames, skipped = [], 0, 0
    for fr in read_frames(path):
        frames += 1
        p = parse(fr)
        if p is None:
            skipped += 1
        else:
            packets.append(p)
    return packets, {"frames": frames, "ip_or_arp": len(packets), "skipped_non_ip": skipped}
