"""The VIRTUAL CAN bridge: serve the UdsEcu over the generic packet FRAMED path of BridgeServer.

Reuses the EXACT SAME BridgeServer the real socketcan bridge uses; only the medium differs - here a
CanFrameMedium that adapts the UdsEcu to the packet-medium surface (inject/take_frames/caps/scan).
So virtual vs real is a medium substitution and even the FRAMED serve path is shared - the corpus's
"same tunnel, two terminations" made literal (docs/design/can-framed.md section 4).

Persistence mirrors the real bridge's FIFO: a `can send`'s response goes into this medium's deque and
is delivered to the NEXT `can dump` connection, exactly as the real bridge's background reader holds a
0x7E8 emitted after the send connection closed until the dump connection opens (section 2).

Fidelity-critical (section 4.2, surprise #3): inject() must NOT echo the injected REQUEST frame into
its own RX. A real CAN_RAW socket does not receive its own sent frames (RECV_OWN_MSGS off), so a real
`can dump` sees only the 0x7E8 response; queueing the 0x7E0 request here would be an instant spurious
diff. We queue responses only.
"""

from __future__ import annotations

import threading
import time
from collections import deque

from espilon_probe.bridges.server import BridgeServer
from espilon_probe.protocols import can

from . import can_isotp
from .uds_ecu import UdsEcu


class CanFrameMedium:
    """Adapt a UdsEcu to the packet-medium surface (inject/take_frames/scan/caps/apply_config)."""

    shape = "packet"

    def __init__(self, ecu: UdsEcu | None = None):
        self.ecu = ecu or UdsEcu()
        self._fifo: deque[bytes] = deque()
        self._lock = threading.Lock()

    def apply_config(self, config: dict) -> None:
        # No bit clock / bitrate physics in the model transport; a link setting is a no-op here.
        pass

    def inject(self, frame: bytes) -> None:
        # Decode the injected request, drive the model, queue ONLY the response frame. Never echo the
        # request into RX (RECV_OWN_MSGS off on a real socket) - see the module docstring.
        try:
            can_id, pdu = can_isotp.decode(bytes(frame))
        except ValueError:
            return                          # not a well-formed SF request: a real ECU ignores it
        if can_id != can_isotp.REQ_ID:
            return                          # not addressed to this ECU's request id
        resp = self.ecu.request(pdu)
        if resp is None:
            return
        with self._lock:
            self._fifo.append(can_isotp.encode_response(resp))

    def take_frames(self, count: int | None, deadline: float) -> list[bytes]:
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
        # The virtual CAN scan is a non-destructive peek of the already-buffered FIFO, so it is
        # instantaneous and the listen-window/count hints do not change its result (which keeps the
        # virtual == vcan0 scan comparison stable).
        with self._lock:
            frames = list(self._fifo)       # non-destructive peek: scan must not steal a dump's frame
        return [{"id": hex(i)} for i in can.ids_seen(frames)]

    def caps(self) -> dict:
        return {"protocol": "can", "channels": [],
                "verbs": ["scan", "sniff", "inject", "replay"], "shape": "packet",
                "pcap_dlt": can.PCAP_DLT,
                "meta": {"iface": "virtual-can", "pcap_dlt": can.PCAP_DLT}}

    def alive(self) -> bool:
        return True

    def close(self) -> None:
        pass


class VirtualCanBridge:
    """A running virtual CAN bridge: bind a loopback port, serve the UdsEcu over the wire in a thread.
    Reached by the shipped `probe --backend virtual --target tcp://...` client, exactly like the real
    socketcan bridge - the client cannot tell them apart."""

    backend = "virtual"

    def __init__(self, ecu: UdsEcu | None = None, host: str = "127.0.0.1"):
        self.medium = CanFrameMedium(ecu)
        self.server = BridgeServer(self.medium, host=host, port=0)
        self.port: int | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> int:
        self.port = self.server.bind()
        self._thread = threading.Thread(target=self.server.serve_forever,
                                        name="virtual-can-bridge", daemon=True)
        self._thread.start()
        return self.port

    @property
    def target(self) -> str:
        return f"tcp://127.0.0.1:{self.port}"

    @property
    def env(self) -> dict:
        import os
        return dict(os.environ)

    def stop(self) -> None:
        self.server.close()
        if self._thread is not None:
            self._thread.join(timeout=1.0)

    def __enter__(self) -> "VirtualCanBridge":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()
