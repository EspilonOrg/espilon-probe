"""Standard pcap writer/reader. probe never dissects; it captures into a standard pcap so
the operator analyses with their own tools (tshark, wireshark, zbdsniff, crackle).

Classic pcap format (not pcapng): a 24-byte global header then per-packet records. The
linktype (DLT) is set per protocol, e.g. 256 = LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR for BLE,
215 = LINKTYPE_IEEE802_15_4_WITHFCS for Zigbee. Frames whose raw bytes are properly
layered for that DLT dissect cleanly; the pcap container itself is protocol-agnostic.
"""

from __future__ import annotations

import struct

from .wire import Frame   # re-export the single Frame type

__all__ = ["Frame", "PcapWriter", "read_pcap"]

_MAGIC_LE = 0xA1B2C3D4
# classic pcap magics -> byte order ("<" LE, ">" BE), microsecond and nanosecond variants
_MAGICS = {0xA1B2C3D4: "<", 0xD4C3B2A1: ">", 0xA1B23C4D: "<", 0x4D3CB2A1: ">"}
_GLOBAL = struct.Struct("<IHHiIII")   # magic, vmaj, vmin, thiszone, sigfigs, snaplen, dlt
_REC = struct.Struct("<IIII")         # ts_sec, ts_usec, caplen, origlen


class PcapWriter:
    def __init__(self, path: str, linktype: int):
        self.linktype = linktype
        self._f = open(path, "wb")
        self._f.write(_GLOBAL.pack(_MAGIC_LE, 2, 4, 0, 0, 65535, linktype))

    def write(self, frame: Frame) -> None:
        raw = frame.raw
        ts = frame.ts or 0.0
        sec = int(ts)
        usec = int(round((ts - sec) * 1_000_000))
        self._f.write(_REC.pack(sec, usec, len(raw), len(raw)))
        self._f.write(raw)

    def close(self) -> None:
        if self._f:
            self._f.close()
            self._f = None

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def read_pcap(path: str) -> tuple[int, list[bytes]]:
    """Return (linktype, [raw frame bytes]). Accepts little- or big-endian classic pcap."""
    with open(path, "rb") as f:
        hdr = f.read(_GLOBAL.size)
        if len(hdr) < _GLOBAL.size:
            return 0, []
        (magic,) = struct.unpack("<I", hdr[:4])
        endian = _MAGICS.get(magic)
        if endian is None:
            raise ValueError(f"not a pcap file (bad magic 0x{magic:08x})")
        g = struct.Struct(endian + "IHHiIII")
        rec = struct.Struct(endian + "IIII")
        (_, _, _, _, _, _, linktype) = g.unpack(hdr)
        frames: list[bytes] = []
        while True:
            ph = f.read(rec.size)
            if len(ph) < rec.size:
                break
            _sec, _usec, caplen, _orig = rec.unpack(ph)
            data = f.read(caplen)
            if len(data) < caplen:
                break
            frames.append(data)
    return linktype, frames
