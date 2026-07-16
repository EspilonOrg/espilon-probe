"""socketcan backend: a loopback launcher for real CAN over a Linux SocketCAN interface.

`probe --backend socketcan --target vcan0` stays simple for the user, but internally probe reaches a
PERSISTENT `probe-bridge` daemon for the socketcan medium and connects to it over the ordinary wire
tunnel (docs/design/00 decision 5, docs/design/02, docs/design/can-framed.md section 2). The client holds ZERO
medium knowledge: the PF_CAN socket + the background frame FIFO live in the bridge's CAN medium
(bridges/media/socketcan.py); here the client only does process orchestration + rendezvous.

Why PERSISTENT although CAN is connectionless (docs/design/can-framed.md section 2): each `probe`
invocation is one short-lived connection running one verb. A `probe can send 7E0 1003` (inject) then
a separate `probe can dump` (sniff) are two connections; the ECU's `7E8` response, injected onto the
bus in between, is lost if no socket is bound when it arrives. A persistent bound PF_CAN socket
(whose reader keeps a FIFO) captures it and hands it to the next dump. So the FIRST invocation for a
target spawns a detached daemon; later ones DISCOVER and connect to it. The rendezvous machinery is
shared verbatim with the serial launcher (it takes the medium name as a parameter).

This is a subclass of the tunnel client (VirtualBackend), the twin of SerialBackend: once connected
it IS the tunnel client, so `inject`/`sniff`/`replay`/`scan` are inherited unchanged. `close()` only
closes the tunnel connection; it does NOT kill the daemon (that is the whole point of persistence).
"""

from __future__ import annotations

from .serial import _ensure_bridge
from .virtual import VirtualBackend


class CanBackend(VirtualBackend):
    _transport_label = "socketcan"

    def __init__(self, target: str | None = None, baud: int = 115200):
        # The tunnel target is not known until we discover/spawn the daemon (set in open()).
        super().__init__(target=None, baud=baud)
        self.endpoint = target or "vcan0"

    def open(self) -> None:
        port = _ensure_bridge("socketcan", self.endpoint, self.baud)   # reuse serial.py's rendezvous
        self.target = f"tcp://127.0.0.1:{port}"
        super().open()

    # close() is inherited from VirtualBackend: it closes ONLY the tunnel connection. The daemon is
    # persistent and retires on its own idle timeout / medium EOF; we deliberately do not kill it.
