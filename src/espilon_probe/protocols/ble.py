"""BLE protocol: GATT semantics + the `gatt` verb group.

Adds connection-oriented verbs on top of the core ones, routed through Backend.op(...)
so they work identically against the virtual lab backend and the real `hci` backend.
Sniff uses DLT_BLUETOOTH_LE_LL_WITH_PHDR so captures open cleanly in wireshark/tshark.
"""

from __future__ import annotations

from ..core.backend import Backend

PROTOCOL = "ble"
PCAP_DLT = 256          # LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR
VERBS = ["gatt"]

ATT_WRITE_REQ = 0x12    # ATT opcode for a Write Request


# gatt verbs (used by the CLI dispatch and by tests/scripts)
def gatt_enum(backend: Backend) -> dict:
    return backend.op("gatt.enum")


def gatt_read(backend: Backend, handle: int) -> dict:
    return backend.op("gatt.read", handle=handle)


def gatt_write(backend: Backend, handle: int, value_hex: str) -> dict:
    return backend.op("gatt.write", handle=handle, value=value_hex)


def unlock_write_frame(handle: int = 0x0014, value: int = 0x01) -> bytes:
    """A raw ATT Write Request PDU: opcode 0x12, handle (LE u16), value.

    This is exactly what tshark dissects as btatt.opcode==0x12, and what a sniff captures
    then a replay re-sends.
    """
    return bytes([ATT_WRITE_REQ, handle & 0xFF, (handle >> 8) & 0xFF, value])
