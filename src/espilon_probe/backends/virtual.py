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
# Grace window to consume the single trailing SNIFF_END a conformant bridge sends to terminate a
# capture, once our own bound has tripped. The bridge sends it in the same burst as the frames, so
# it is already buffered and the wait is effectively zero; this only caps how long we wait for a
# bridge that omits it, so the client can never wedge here.
SNIFF_END_DRAIN_GRACE = 0.5


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
        # `items` is backend-supplied; a missing key defaults to [], but an explicit non-list
        # (e.g. JSON null or an object) must not flow to the display loop as if it were rows.
        # We hand the raw list to the caller, which normalizes per-row (cli._scan_rows); a
        # non-list is refused loud here rather than guessed at.
        items = self._txn({"t": wire.SCAN}).get("items", [])
        if items is None:
            return []
        if not isinstance(items, list):
            raise RuntimeError(f"bridge returned non-list scan items {items!r}")
        return items

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

        # The capture's DLT must come from the bridge's advertised `pcap_dlt`. A silent
        # fallback here would write a capture under a guessed link type that `replay` (which
        # refuses loud when `pcap_dlt` is absent) would then reject, so a misconfigured bridge
        # produced a capture it could not replay. Refuse loud instead, agreeing with replay.
        dlt = self._caps.get("pcap_dlt")
        if dlt is None:
            from ..core.errors import ProbeError
            raise ProbeError(
                "bridge did not advertise a pcap link type (pcap_dlt); refusing to write a "
                "capture under a guessed DLT that replay would reject")
        wire.send(self._w, {"t": wire.SNIFF, "count": count, "seconds": seconds,
                            "channel": channel})
        start = time.monotonic()
        n = 0
        bound_reached = False    # our own count/seconds/timeout tripped (vs a quiet/closed bridge)
        saw_end = False          # the bridge's terminating SNIFF_END was already consumed in-loop
        with PcapWriter(out_pcap, dlt) as pw:
            while True:
                elapsed = time.monotonic() - start
                if count is not None and n >= count:
                    bound_reached = True
                    break
                if seconds is not None and elapsed >= seconds:
                    bound_reached = True
                    break
                if elapsed >= timeout:
                    bound_reached = True
                    break
                # Bound this single recv so the client never blocks past the budget.
                remaining = timeout - elapsed
                if seconds is not None:
                    remaining = min(remaining, seconds - elapsed)
                self._sock.settimeout(max(0.0, remaining))
                try:
                    m = wire.recv(self._r)
                except (socket.timeout, OSError):
                    break            # bridge went quiet; nothing left to realign
                if m is None:
                    break            # bridge closed the connection
                t = m.get("t")
                if t == wire.FRAME:
                    pw.write(wire.Frame.from_msg(m))
                    n += 1
                elif t == wire.SNIFF_END:
                    saw_end = True
                    break
                elif t == wire.ERROR:
                    raise RuntimeError(m.get("msg", "error"))
        # A conformant bridge terminates every capture with exactly one inbound SNIFF_END. When our
        # own bound (count/seconds/timeout) tripped first, that marker is still queued on the wire;
        # consume it so the NEXT command on a PERSISTENT connection reads its own reply and not the
        # stale marker. We deliberately do NOT send a SNIFF_END of our own: the bridge does not read
        # while it streams a capture (an outbound stop cannot end one early), and older bridges
        # reject the unknown inbound `sniff_end` type, which desyncs the session. It is inbound-only.
        if bound_reached and not saw_end:
            self._drain_sniff_end(start, timeout)
        try:
            self._sock.settimeout(None)
        except OSError:
            pass
        return n

    def _drain_sniff_end(self, start: float, timeout: float) -> None:
        """Consume the single trailing SNIFF_END that terminates a capture, realigning the stream
        for the next command on a persistent connection.

        A conformant bridge sends the marker in the same burst as the frames (both queued before it
        loops back to read), so it is already buffered and this returns at once. The wait is bounded
        (`SNIFF_END_DRAIN_GRACE`, itself clamped by the capture's remaining wall-clock budget) so a
        bridge that omits the marker cannot wedge the client - it gives up and leaves the stream as
        is. Exactly one message is consumed: the marker for a count-bounded capture, or a stray
        frame from a non-conformant bridge (which we do not chase, so we can never hang here).
        """
        remaining = timeout - (time.monotonic() - start)
        budget = min(SNIFF_END_DRAIN_GRACE, max(0.0, remaining))
        try:
            self._sock.settimeout(budget)
            wire.recv(self._r)
        except (socket.timeout, OSError):
            return
