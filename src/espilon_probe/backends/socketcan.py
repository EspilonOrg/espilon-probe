"""socketcan backend: real CAN over a Linux SocketCAN interface (vcan0, can0, slcan0...).

Raw PF_CAN, no third-party dependency. The same protocol codec (protocols/can.py) drives this
and the virtual backend, so `probe --backend socketcan --target vcan0 can dump` is the
exact workflow the player learned in the lab, now against a real bus. This is the
dual-purpose payoff for CAN.
"""

from __future__ import annotations

import socket
import time

from ..core.backend import Backend, Capabilities
from ..core.frame import Frame, PcapWriter, read_pcap

FRAME_SIZE = 16


class SocketCanBackend(Backend):
    def __init__(self, target: str | None = None):
        self.iface = target or "vcan0"
        self._sock: socket.socket | None = None

    def open(self) -> None:
        s = socket.socket(socket.PF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
        try:
            s.bind((self.iface,))
        except OSError as e:
            s.close()
            raise RuntimeError(f"cannot bind CAN interface {self.iface!r}: {e}")
        self._sock = s

    def close(self) -> None:
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass
        self._sock = None

    def capabilities(self) -> Capabilities:
        from ..protocols import can
        return Capabilities(protocol="can", transport="socketcan", channels=[],
                            verbs=["scan", "sniff", "inject", "replay"],
                            meta={"iface": self.iface, "pcap_dlt": can.PCAP_DLT})

    def scan(self) -> list[dict]:
        from ..protocols import can
        frames = self._read(count=None, seconds=2.0)
        return [{"id": hex(i)} for i in can.ids_seen(frames)]

    def sniff(self, out_pcap: str, count=None, seconds=None, channel=None) -> int:
        from ..protocols import can
        frames = self._read(count=count, seconds=(seconds or 2.0))
        with PcapWriter(out_pcap, can.PCAP_DLT) as pw:
            for raw in frames:
                pw.write(Frame(ts=0.0, channel=0, raw=raw, direction="rx", protocol="can"))
        return len(frames)

    def inject(self, frame: bytes, channel=None) -> None:
        self._require_open().send(frame[:FRAME_SIZE].ljust(FRAME_SIZE, b"\x00"))

    def replay(self, in_pcap: str, frame_filter: str | None = None) -> int:
        _dlt, frames = read_pcap(in_pcap)
        for raw in frames:
            self.inject(raw)
        return len(frames)

    def op(self, verb: str, **kwargs) -> dict:
        raise NotImplementedError(verb)

    def _require_open(self) -> socket.socket:
        if self._sock is None:
            raise RuntimeError("socketcan backend not open (call open() first)")
        return self._sock

    def _read(self, count, seconds) -> list[bytes]:
        self._require_open()
        out: list[bytes] = []
        deadline = time.monotonic() + seconds if seconds else None
        self._sock.settimeout(0.2)
        while True:
            if count and len(out) >= count:
                break
            if deadline and time.monotonic() >= deadline:
                break
            try:
                out.append(self._sock.recv(FRAME_SIZE))
            except socket.timeout:
                if deadline is None:
                    break
        return out
