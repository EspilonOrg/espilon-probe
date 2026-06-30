"""Virtual backend: talks the probe wire protocol over TCP to an Espilon lab bridge.

The default backend. The lab panel gives the player one dynamic endpoint per spawn:
    export ESP_PROBE=tcp://host:port
Verbs map straight onto the wire protocol. No analysis here; capture is standard pcap.
"""

from __future__ import annotations

import os
import socket
import time

from ..core import wire
from ..core.backend import Backend, Capabilities

# Hard client-side ceiling for a sniff when the operator gives neither count nor seconds.
# The tool always stops on its own; it never trusts the bridge to end a capture.
SNIFF_DEFAULT_SECONDS = 30.0
# Wall-clock guard so a wedged/never-ending bridge can never hang the client. It is the
# requested duration plus a small margin, or a fixed ceiling when only `count` was given.
SNIFF_COUNT_ONLY_TIMEOUT = 60.0
SNIFF_TIMEOUT_MARGIN = 5.0


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
                            shape=c.get("shape", "packet"), meta=c.get("meta", {}))

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
        replay and pass the filtered pcap; we deliberately do not reimplement a filter.

        The pcap's DLT is validated against the active protocol's DLT (convention C4): a
        cross-protocol capture is refused, not blasted onto the wire."""
        from ..core.frame import read_pcap_for_replay
        frames = read_pcap_for_replay(in_pcap, self._caps.get("pcap_dlt"))
        r = self._txn({"t": wire.REPLAY, "frames": [f.hex() for f in frames]})
        return r.get("count", 0)

    def sniff(self, out_pcap: str, count=None, seconds=None, channel=None) -> int:
        """Capture frames to a pcap, BOUNDED entirely client-side.

        The tool stops on its own and never trusts the bridge to end the capture:
          - if neither `count` nor `seconds` is given, a default ceiling applies
            (`SNIFF_DEFAULT_SECONDS`) instead of capturing unbounded;
          - the read loop stops at `frames_read >= count` OR elapsed >= `seconds` OR
            elapsed >= a hard wall-clock `timeout`, whichever fires first;
          - each recv carries a socket timeout derived from the remaining budget, so a
            bridge that simply stops sending frames cannot wedge the client.
        After the bound is reached the client stops reading regardless of further frames.
        """
        from ..core.frame import PcapWriter

        if count is None and seconds is None:
            seconds = SNIFF_DEFAULT_SECONDS
        # Hard wall-clock guard, always finite, even in the count-only case.
        if seconds is not None:
            timeout = seconds + SNIFF_TIMEOUT_MARGIN
        else:
            timeout = SNIFF_COUNT_ONLY_TIMEOUT

        dlt = self._caps.get("pcap_dlt", 147)   # 147 = LINKTYPE_USER0 fallback
        wire.send(self._w, {"t": wire.SNIFF, "count": count, "seconds": seconds,
                            "channel": channel})
        start = time.monotonic()
        n = 0
        with PcapWriter(out_pcap, dlt) as pw:
            while True:
                elapsed = time.monotonic() - start
                if count is not None and n >= count:
                    break
                if seconds is not None and elapsed >= seconds:
                    break
                if elapsed >= timeout:
                    break
                # Bound this single recv so the client never blocks past the budget.
                remaining = timeout - elapsed
                if seconds is not None:
                    remaining = min(remaining, seconds - elapsed)
                self._sock.settimeout(max(0.0, remaining))
                try:
                    m = wire.recv(self._r)
                except (socket.timeout, OSError):
                    break
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
        # Best-effort: tell the bridge to stop, then clear the read timeout.
        try:
            wire.send(self._w, {"t": wire.SNIFF_END, "count": n})
        except OSError:
            pass
        try:
            self._sock.settimeout(None)
        except OSError:
            pass
        return n
