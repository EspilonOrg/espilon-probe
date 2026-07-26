"""hci backend: a loopback launcher for real BLE GATT over BlueZ (bleak, behind the [hci] extra).

`probe --backend hci --target my-lock gatt read 0x0011` stays simple for the user, but internally
probe reaches a PERSISTENT `probe-bridge` daemon for the hci medium and connects to it over the
ordinary wire tunnel (docs/design/00 decision 5, docs/design/ble-gatt.md sections 2, 4.3). The client
holds ZERO medium knowledge: the asyncio loop + the held BleakClient + the ATT-error map live in the
bridge's hci medium (bridges/media/hci.py); here the client only does process orchestration +
rendezvous.

Why PERSISTENT, and MORE load-bearing than serial/CAN (docs/design/ble-gatt.md section 4.3): each
`probe gatt` invocation is one short-lived connection running one verb. The peripheral's unlock state
lives in the PERIPHERAL and many peripherals reset per-connection app state on BLE disconnect, so
read-STATUS -> write-RX -> read-FLAG MUST ride ONE held BLE link across the discrete probe processes
or the target relocks between the write and the read (and reconnecting costs seconds). So the FIRST
invocation for a target spawns a detached daemon that OPENS AND HOLDS the BLE connection; SUBSEQUENT
invocations for the same target DISCOVER and connect to the running daemon, reusing its held link. The
rendezvous machinery is shared verbatim with the serial/CAN launchers (it takes the medium name as a
parameter); the daemon key is the TARGET, so the held connection is per peripheral.

`scan` needs no target (a central discovers advertisers), so `probe --backend hci scan` runs against a
target-less daemon (endpoint NO_TARGET) that never connects; only `gatt` requires `--target`.

This is a subclass of the tunnel client (VirtualBackend), the twin of SerialBackend/CanBackend: once
connected it IS the tunnel client, so `scan`/`op` are inherited unchanged. `close()` only closes the
tunnel connection; it does NOT kill the daemon (that is the whole point of persistence).
"""

from __future__ import annotations

from .serial import _ensure_bridge
from .virtual import VirtualBackend

# The endpoint a scan-only spawn carries (mirrors bridges.media.hci.NO_TARGET, matched by string so
# the client core imports no bridge/medium module). `scan` needs no target; only `gatt` requires one.
_NO_TARGET = "any"


class HciBackend(VirtualBackend):
    _transport_label = "hci"

    def __init__(self, target: str | None = None, baud: int = 115200):
        # The tunnel target is not known until we discover/spawn the daemon (set in open()).
        super().__init__(target=None, baud=baud)
        # The peripheral to connect to for gatt; _NO_TARGET means scan-only (no connection).
        self.endpoint = target or _NO_TARGET

    def open(self) -> None:
        port = _ensure_bridge("hci", self.endpoint, self.baud)   # reuse serial.py's rendezvous
        self.target = f"tcp://127.0.0.1:{port}"
        super().open()

    # close() is inherited from VirtualBackend: it closes ONLY the tunnel connection. The daemon is
    # persistent and retires on its own idle timeout / medium close; we deliberately do not kill it.
