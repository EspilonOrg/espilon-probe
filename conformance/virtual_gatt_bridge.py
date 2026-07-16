"""The VIRTUAL GATT bridge: serve the GattServer over the generic transaction serve path.

Reuses the EXACT SAME BridgeServer the real hci bridge will use; only the medium differs - here a
GattOpMedium that adapts the GattServer model to the transaction-medium surface (op/scan/caps/
apply_config). So virtual vs real is a medium substitution (GattOpMedium vs the future HciMedium) and
even the FRAMED op serve path (_serve_op) is shared - the corpus's "same tunnel, two terminations"
made literal (docs/design/ble-gatt.md sections 1, 4.2).

Persistence: the medium HOLDS ONE GattServer instance across the per-verb `probe gatt` connections,
so the `unlocked` state a `gatt write` sets survives to the next `gatt read` - the virtual analogue of
the real bridge holding ONE persistent BLE connection across the discrete probe processes
(docs/design/ble-gatt.md section 4.3). No pcap, no FIFO: a GATT op is request/response.
"""

from __future__ import annotations

import threading

from espilon_probe.bridges.server import BridgeServer
from espilon_probe.core.fields import as_int, hex_bytes
from espilon_probe.protocols import ble

from .gatt_server import AttError, GattServer


class GattOpMedium:
    """Adapt a GattServer to the transaction-medium surface (op/scan/caps/apply_config/alive/close).

    `op(verb, args)` is the one method BridgeServer._serve_op drives. The untrusted `args` (handle,
    value) are coerced AUTHORITATIVELY through the guarded fields helpers: a value we cannot interpret
    raises (surfaced by _serve_op as a clean wire ERROR the client renders as a nonzero-exit error),
    never a guessed byte. A protocol-level ATT error is NOT an exception - it is returned inside the
    result as `{error: <code>}` and travels as an ordinary OP_RESULT."""

    shape = "transaction"

    def __init__(self, server: GattServer | None = None):
        self.server = server or GattServer()

    def apply_config(self, config: dict) -> None:
        # No link params in the model transport (the real hci medium would carry connection params).
        pass

    def op(self, verb: str, args: dict) -> dict:
        if verb == "gatt.enum":
            return {"characteristics": [
                {"handle": a.handle, "uuid": a.uuid, "props": a.props}
                for a in self.server.enumerate()]}
        if verb == "gatt.read":
            handle = as_int(args.get("handle"), "gatt handle")
            res = self.server.read(handle)
            if isinstance(res, AttError):
                return {"error": res.code}
            return {"value": bytes(res).hex()}
        if verb == "gatt.write":
            handle = as_int(args.get("handle"), "gatt handle")
            value = hex_bytes(args.get("value", ""), "gatt.write value")
            res = self.server.write(handle, value)
            if isinstance(res, AttError):
                return {"error": res.code}
            return {"ok": True}
        # An unknown op verb on a GATT medium: fail loud (a wire ERROR via _serve_op), never a silent
        # empty result the client might misread as a benign answer.
        raise ValueError(f"unsupported gatt op {verb!r}")

    def scan(self, seconds: float | None = None, count: int | None = None) -> list[dict]:
        # Advertise the (single) peripheral. The address/RSSI are normalized out by the comparator
        # (docs/design/ble-gatt.md section 4.4); the fidelity-bearing surface is the gatt ops. The
        # listen-window/count hints do not change this single-peripheral model result.
        return [{"name": "pilot-peripheral", "addr": "00:11:22:33:44:55", "rssi": -50}]

    def caps(self) -> dict:
        # verbs = ["scan", "gatt"] ONLY: a central is not a sniffer, so NO sniff/inject/replay
        # (docs/design/ble-gatt.md section 6). No pcap_dlt: a GATT op produces no capture.
        return {"protocol": ble.PROTOCOL, "channels": [],
                "verbs": ["scan", "gatt"], "shape": "transaction",
                "meta": {"peripheral": "pilot-peripheral"}}

    def alive(self) -> bool:
        return True

    def close(self) -> None:
        pass


class VirtualGattBridge:
    """A running virtual GATT bridge: bind a loopback port, serve the GattServer over the wire in a
    thread. Reached by the shipped `probe --backend virtual --target tcp://...` client, exactly like
    the future real hci bridge - the client cannot tell them apart."""

    backend = "virtual"

    def __init__(self, server: GattServer | None = None, host: str = "127.0.0.1"):
        self.medium = GattOpMedium(server)
        self.server = BridgeServer(self.medium, host=host, port=0)
        self.port: int | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> int:
        self.port = self.server.bind()
        self._thread = threading.Thread(target=self.server.serve_forever,
                                        name="virtual-gatt-bridge", daemon=True)
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

    def __enter__(self) -> "VirtualGattBridge":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()
