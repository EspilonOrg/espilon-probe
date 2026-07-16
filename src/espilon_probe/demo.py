"""`probe demo` - a zero-setup tour against a bundled toy target.

`pip install espilon-probe && probe demo` must produce output with no endpoint to configure and
no hardware to plug in. So this module ships a tiny, flag-free, obviously-a-demo virtual target
(a mock "demo-door-lock" BLE peripheral) and runs a short scripted example against it through the
ordinary shipped client path: it binds the real `BridgeServer` on loopback and drives it with a
real `VirtualBackend`, exactly the way `conformance/` stands up a virtual bridge. Nothing here is
target/challenge/lab content - it is a demonstration of the verbs only.

Stdlib only, like the rest of the client core.
"""

from __future__ import annotations

import threading

from .backends.virtual import VirtualBackend
from .bridges.server import BridgeServer
from .core.fields import as_int, hex_bytes
from .protocols import ble


class _DemoLockMedium:
    """A trivial transaction medium: a toy BLE door lock with three characteristics.

    read the door -> "locked"; write the key -> unlocks; read the door -> "open". No secret, no
    flag, no persistence beyond this one process. It implements the same transaction-medium surface
    (`shape`/`op`/`scan`/`caps`) the real `hci` medium implements, so the shipped client cannot tell
    it apart from real hardware.
    """

    shape = "transaction"

    # (handle, uuid, props, value-bytes). The `door` value is computed from `self._open`.
    _MODEL = 0x0001
    _KEY = 0x0002
    _DOOR = 0x0003

    def __init__(self) -> None:
        self._open = False

    def apply_config(self, config: dict) -> None:  # no link params in the toy transport
        pass

    def op(self, verb: str, args: dict) -> dict:
        if verb == "gatt.enum":
            return {"characteristics": [
                {"handle": self._MODEL, "uuid": "demo-0001-model", "props": "R"},
                {"handle": self._KEY, "uuid": "demo-0002-key", "props": "W"},
                {"handle": self._DOOR, "uuid": "demo-0003-door", "props": "R"},
            ]}
        if verb == "gatt.read":
            handle = as_int(args.get("handle"), "gatt handle")
            if handle == self._MODEL:
                return {"value": b"demo-door-lock".hex()}
            if handle == self._DOOR:
                return {"value": (b"open" if self._open else b"locked").hex()}
            # A read of the write-only key is Read Not Permitted (0x02), like a real lock.
            if handle == self._KEY:
                return {"error": 0x02}
            return {"error": 0x0a}  # Attribute Not Found
        if verb == "gatt.write":
            handle = as_int(args.get("handle"), "gatt handle")
            value = hex_bytes(args.get("value", ""), "gatt.write value")
            if handle == self._KEY:
                self._open = value == b"\x01"
                return {"ok": True}
            return {"error": 0x03}  # Write Not Permitted
        raise ValueError(f"unsupported demo op {verb!r}")

    def scan(self, seconds: float | None = None, count: int | None = None) -> list[dict]:
        return [{"name": "demo-door-lock", "addr": "00:DE:M0:00:00:01", "rssi": -40}]

    def caps(self) -> dict:
        return {"protocol": ble.PROTOCOL, "channels": [],
                "verbs": ["scan", "gatt"], "shape": "transaction",
                "meta": {"peripheral": "demo-door-lock"}}

    def alive(self) -> bool:
        return True

    def close(self) -> None:
        pass


def _text(result: dict) -> str:
    """Render a gatt.read result as readable text (the toy values are all ASCII)."""
    return bytes.fromhex(result["value"]).decode(errors="replace")


def run() -> int:
    """Spin the toy target, run a scripted example, and print the equivalent real commands."""
    medium = _DemoLockMedium()
    server = BridgeServer(medium, host="127.0.0.1", port=0)
    port = server.bind()
    thread = threading.Thread(target=server.serve_forever, name="probe-demo-bridge", daemon=True)
    thread.start()

    backend = VirtualBackend(f"tcp://127.0.0.1:{port}")
    try:
        backend.open()
        print("probe demo - a zero-setup tour against a bundled toy target (no hardware needed).")
        print(f"Spun up the toy 'demo-door-lock' BLE peripheral on 127.0.0.1:{port}.")
        print()

        c = backend.capabilities()
        print("$ probe info")
        print(f"backend: {c.transport}   protocol: {c.protocol}   shape: {c.shape}   "
              f"verbs: {','.join(c.verbs)}")
        print()

        print("$ probe scan")
        for row in backend.scan():
            print(f"{row['name']}  {row['addr']}  {row['rssi']}")
        print()

        print("$ probe gatt enum")
        for ch in ble.gatt_enum(backend).get("characteristics", []):
            print(f"0x{as_int(ch['handle'], 'handle'):04x}  {ch['uuid']}  {ch['props']}")
        print()

        print("$ probe gatt read 0x0003          # the door")
        print(_text(ble.gatt_read(backend, _DemoLockMedium._DOOR)))
        print("$ probe gatt write 0x0002 01      # turn the key")
        ble.gatt_write(backend, _DemoLockMedium._KEY, "01")
        print("ok")
        print("$ probe gatt read 0x0003          # the door again")
        print(_text(ble.gatt_read(backend, _DemoLockMedium._DOOR)))
        print()

        print("That was the shipped client driving a simulated target. The SAME commands drive real")
        print("hardware - only the backend changes:")
        print()
        print("  probe --backend hci --target <address> gatt read 0x0003")
        print("  probe --backend hci --target <address> gatt write 0x0002 01")
        print()
        print("Next: `probe --help`, or point ESP_PROBE at a virtual target and go.")
    finally:
        backend.close()
        server.close()
        thread.join(timeout=1.0)
    return 0
