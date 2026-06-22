"""Virtual backend: talks the probe wire protocol over TCP to an Espilon lab bridge.

The default backend. The lab panel gives the player one dynamic endpoint per spawn:
    export ESP_PROBE=tcp://host:port
Verbs map straight onto the wire protocol. No analysis here; capture is standard pcap.
"""

from __future__ import annotations

import os
import socket

from ..core import wire
from ..core.backend import Backend, Capabilities


class VirtualBackend(Backend):
    def __init__(self, target: str | None = None, baud: int = 115200):
        self.target = target or os.environ.get("ESP_PROBE")
        self.baud = baud
        self._sock: socket.socket | None = None
        self._r = None
        self._w = None
        self._caps: dict = {}

    def _endpoint(self) -> tuple[str, int]:
        t = self.target
        if not t:
            raise RuntimeError(
                "no lab endpoint: set ESP_PROBE=tcp://host:port (see your lab panel) "
                "or pass --target")
        if t.startswith("tcp://"):
            t = t[len("tcp://"):]
        host, _, port = t.partition(":")
        if not port:
            raise RuntimeError(f"bad endpoint {self.target!r}, expected tcp://host:port")
        return host, int(port)

    def open(self) -> None:
        host, port = self._endpoint()
        sock = socket.create_connection((host, port), timeout=10)
        try:
            sock.settimeout(None)            # connect-only timeout; reads/sniff must not inherit it
            r = sock.makefile("rb")
            w = sock.makefile("wb")
            wire.send(w, wire.hello(config={"baud": self.baud}))
            msg = wire.recv(r)
            if not msg or msg.get("t") != wire.WELCOME:
                raise RuntimeError("handshake failed (no welcome from bridge)")
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            raise                            # leave _sock None so the backend is not half-open
        self._sock, self._r, self._w = sock, r, w
        self._caps = msg.get("capabilities", {}) or {}

    def close(self) -> None:
        for f in (self._r, self._w):
            try:
                if f:
                    f.close()
            except Exception:
                pass
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass
        self._sock = self._r = self._w = None

    def capabilities(self) -> Capabilities:
        c = self._caps
        return Capabilities(protocol=c.get("protocol", ""), transport="virtual",
                            channels=c.get("channels", []), verbs=c.get("verbs", []),
                            meta=c.get("meta", {}))

    def _txn(self, msg: dict) -> dict:
        wire.send(self._w, msg)
        r = wire.recv(self._r)
        if r is None:
            raise RuntimeError("connection closed by lab")
        if r.get("t") == wire.ERROR:
            raise RuntimeError(r.get("msg", "error"))
        return r

    def scan(self) -> list[dict]:
        return self._txn({"t": wire.SCAN}).get("items", [])

    def op(self, verb: str, **kwargs) -> dict:
        return self._txn({"t": wire.OP, "verb": verb, "args": kwargs}).get("result", {})

    def inject(self, frame: bytes, channel: int | None = None) -> None:
        self._txn({"t": wire.INJECT, "frame": frame.hex(), "channel": channel})

    def replay(self, in_pcap: str, frame_filter: str | None = None) -> int:
        """Re-transmit every frame in a pcap. Filter with stock tools (tshark -w) BEFORE
        replay and pass the filtered pcap; we deliberately do not reimplement a filter."""
        from ..core.frame import read_pcap
        _dlt, frames = read_pcap(in_pcap)
        r = self._txn({"t": wire.REPLAY, "frames": [f.hex() for f in frames]})
        return r.get("count", 0)

    def sniff(self, out_pcap: str, count=None, seconds=None, channel=None) -> int:
        from ..core.frame import PcapWriter
        dlt = self._caps.get("pcap_dlt", 147)   # 147 = LINKTYPE_USER0 fallback
        wire.send(self._w, {"t": wire.SNIFF, "count": count, "seconds": seconds,
                            "channel": channel})
        n = 0
        with PcapWriter(out_pcap, dlt) as pw:
            while True:
                m = wire.recv(self._r)
                if m is None:
                    break
                t = m.get("t")
                if t == wire.FRAME:
                    pw.write(wire.Frame.from_msg(m))
                    n += 1
                elif t == wire.SNIFF_END:
                    break
                elif t == wire.ERROR:
                    raise RuntimeError(m.get("msg", "error"))
        return n
