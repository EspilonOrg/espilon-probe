"""socketcan medium: real CAN over a Linux SocketCAN interface (vcan0, can0, slcan0...).

The packet-shape sibling of SerialMedium (docs/design/can-framed.md section 2). A raw PF_CAN
socket with a background reader thread that recv()s frames into a FIFO CONTINUOUSLY, independent of
any client connection - the exact role SerialMedium._read_loop plays for a stream. That is what lets
a device response injected BETWEEN a `probe can send` and a later `probe can dump` (two discrete
per-verb connections) survive to the next dump: the persistent bound socket + FIFO holds it across
the connections, the same hazard the serial daemon solves. Connectionless removes the "open a session
to a peer" step, NOT the "hold RX across the discrete per-verb connections" need.

Stdlib only (socket.AF_CAN/CAN_RAW); no third-party, no can-utils.

RECV_OWN_MSGS is left OFF (the SocketCAN default): a CAN_RAW socket does not receive its own injected
frames, so a `dump` after a `send` sees only the peer's reply, never the echo of the request. The
virtual CanFrameMedium matches this exactly (it queues responses only), which is what keeps virtual
and real frame-for-frame identical.
"""

from __future__ import annotations

import socket
import sys
import threading
import time
from collections import deque

from ...protocols import can

FRAME_SIZE = can.FRAME_SIZE

# Cap on the un-drained RX FIFO. The background reader appends frames CONTINUOUSLY, independent of
# any client, so a persistent daemon on a busy bus that is never drained would grow the FIFO without
# bound (each SocketCAN frame is 16 bytes; 100k frames ~= 1.6 MiB). At the cap the OLDEST frame is
# dropped to admit the newest (drop-oldest: a sniff wants the most recent traffic, not stale frames)
# and a dropped-frame counter is bumped so the loss is observable, never silent.
_FIFO_MAXLEN = 100_000

# Default `scan` listen window when the client requests none. A CAN scan collects the distinct
# arbitration ids seen on the bus over this window; the operator can override it with `scan -t <secs>`
# (the same seconds plumbing as the BLE medium), e.g. a longer window to catch a slow-cycling ECU.
_SCAN_WINDOW = 2.0


class CanMedium:
    shape = "packet"

    def __init__(self, endpoint: str = "vcan0", bitrate: int | None = None):
        self.endpoint = endpoint
        self.bitrate = bitrate
        self._sock: socket.socket | None = None
        self._fifo: deque[bytes] = deque(maxlen=_FIFO_MAXLEN)
        self._dropped = 0            # frames dropped-oldest at the FIFO cap (observable in caps/meta)
        self._lock = threading.Lock()
        self._reader: threading.Thread | None = None
        self._closed = threading.Event()

    def open(self) -> None:
        s = socket.socket(socket.PF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
        try:
            s.bind((self.endpoint,))
        except OSError as e:
            s.close()
            raise RuntimeError(f"cannot bind CAN interface {self.endpoint!r}: {e}")
        s.settimeout(0.1)
        self._sock = s
        self._reader = threading.Thread(target=self._read_loop, name="can-rx", daemon=True)
        self._reader.start()

    def apply_config(self, config: dict) -> None:
        """A link setting {"can_bitrate": N} is applied to a real controller by `ip link` before the
        socket is bound; on vcan (and once bound) it is a no-op here, recorded only for `info`. Never
        guessed at."""
        if isinstance(config, dict):
            br = config.get("can_bitrate")
            if isinstance(br, int) and br > 0:
                self.bitrate = br

    def _read_loop(self) -> None:
        while not self._closed.is_set():
            try:
                raw = self._sock.recv(FRAME_SIZE)
            except socket.timeout:
                continue
            except OSError:
                break               # socket closed / hard error: the line is gone
            if not raw:
                break
            self._push(raw)

    def _push(self, raw: bytes) -> None:
        """Append one frame to the RX FIFO, dropping the OLDEST at the cap and counting the loss.
        Split out from the reader so the drop-oldest bound is unit-testable without a live socket."""
        with self._lock:
            if len(self._fifo) == self._fifo.maxlen:
                # deque(maxlen) would silently evict the oldest on append; count it first so the
                # drop is observable, then log a coarse-rate heartbeat to stderr.
                self._dropped += 1
                if self._dropped == 1 or self._dropped % 10_000 == 0:
                    print(f"can-rx: FIFO full ({self._fifo.maxlen}), dropping oldest frames "
                          f"(dropped={self._dropped})", file=sys.stderr)
            self._fifo.append(raw)

    def inject(self, frame: bytes) -> None:
        """Transmit one 16-byte SocketCAN struct verbatim (padded/truncated defensively)."""
        self._require_open().send(bytes(frame)[:FRAME_SIZE].ljust(FRAME_SIZE, b"\x00"))

    def take_frames(self, count: int | None, deadline: float) -> list[bytes]:
        """Drain buffered frames + any that arrive before `deadline` (an absolute monotonic time),
        bounded by `count`. Returns as soon as `count` frames are collected, so a `dump -c 1` after a
        `send` returns the moment its response is buffered."""
        if self._sock is None:
            return []
        out: list[bytes] = []
        while True:
            with self._lock:
                while self._fifo and (count is None or len(out) < count):
                    out.append(self._fifo.popleft())
            if count is not None and len(out) >= count:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(0.005, remaining))
        return out

    def scan(self, seconds: float | None = None, count: int | None = None) -> list[dict]:
        """Collect the distinct arbitration ids seen over a listen window. `seconds` overrides the
        default window (already coerced/clamped by the server); `count` is accepted for interface
        parity but not applied here - a CAN id-scan dedups ids, so an early-stop on a raw frame count
        would end on the wrong quantity, and we do not guess a distinct-id early-stop the medium
        cannot bound cheaply. It is ignored rather than mis-honoured."""
        self._require_open()
        window = _SCAN_WINDOW if seconds is None else float(seconds)
        deadline = time.monotonic() + window
        frames = self.take_frames(None, deadline)
        return [{"id": hex(i)} for i in can.ids_seen(frames)]

    def caps(self) -> dict:
        # pcap_dlt is a TOP-LEVEL capability (the tunnel client reads it there to pick the capture
        # link type and to gate replay); it is also echoed into meta for `info`.
        with self._lock:
            dropped = self._dropped
        return {"protocol": "can", "channels": [],
                "verbs": ["scan", "sniff", "inject", "replay"], "shape": "packet",
                "pcap_dlt": can.PCAP_DLT,
                "meta": {"iface": self.endpoint, "pcap_dlt": can.PCAP_DLT,
                         "rx_dropped": dropped, "rx_fifo_max": _FIFO_MAXLEN}}

    def alive(self) -> bool:
        """False once the RX reader stopped because the socket died. The daemon uses this to retire
        when the medium goes away, mirroring SerialMedium.alive()."""
        return self._reader is not None and self._reader.is_alive()

    def close(self) -> None:
        self._closed.set()
        if self._reader is not None:
            self._reader.join(timeout=0.5)
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        self._sock = None

    def _require_open(self) -> socket.socket:
        if self._sock is None:
            raise RuntimeError("socketcan medium not open (call open() first)")
        return self._sock
