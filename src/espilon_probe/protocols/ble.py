"""BLE protocol: GATT semantics + the `gatt` verb group.

Adds connection-oriented verbs on top of the core ones, routed through Backend.op(...)
so they work identically against the virtual lab backend and the real `hci` backend.
Sniff uses DLT_BLUETOOTH_LE_LL_WITH_PHDR (256) so captures open cleanly in wireshark/tshark.

`unlock_write_frame` emits the FULL layering DLT 256 requires (LE pseudo-header + Link Layer
data PDU + L2CAP + ATT), not a bare ATT PDU, so a sniff/replay capture actually dissects as
`btatt.opcode == 0x12` in stock tools. A bare ATT PDU under DLT 256 does NOT dissect; that
was the prior bug. See convention C-rule 5 (pcap DLT is first-class).
"""

from __future__ import annotations

import struct

from ..core.backend import Backend
from ..core.errors import ProbeError

PROTOCOL = "ble"
PCAP_DLT = 256          # LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR
VERBS = ["gatt"]

ATT_WRITE_REQ = 0x12    # ATT opcode for a Write Request
L2CAP_CID_ATT = 0x0004  # the fixed L2CAP channel for ATT
# A connection (data-channel) access address. It must NOT be the advertising AA (0x8E89BED6),
# or the dissector treats the LL PDU as an advertising PDU and never reaches L2CAP/ATT.
_LL_ACCESS_ADDRESS = 0x12345678
_LL_DATA_PDU_START = 0x02   # LL header byte 0: LLID = 0b10 (start of an L2CAP message)
_LL_CRC = b"\x00\x00\x00"   # 3-byte LL CRC trailer (synthetic; phdr clears crc-checked)


# gatt verbs (used by the CLI dispatch and by tests/scripts)
def gatt_enum(backend: Backend) -> dict:
    return backend.op("gatt.enum")


def gatt_read(backend: Backend, handle: int) -> dict:
    return backend.op("gatt.read", handle=handle)


def gatt_write(backend: Backend, handle: int, value_hex: str) -> dict:
    return backend.op("gatt.write", handle=handle, value=value_hex)


def att_write_pdu(handle: int, value: int) -> bytes:
    """The bare ATT Write Request PDU: opcode 0x12, handle (LE u16), 1-byte value.

    Validates field widths so a too-large handle/value is a clean error, not a silent wrap.
    """
    if not 0 <= handle <= 0xFFFF:
        raise ProbeError(f"ATT handle out of range: 0x{handle:x} (must fit 16 bits, 0..0xFFFF)")
    if not 0 <= value <= 0xFF:
        raise ProbeError(f"ATT value out of range: 0x{value:x} (must fit 8 bits, 0..0xFF)")
    return bytes([ATT_WRITE_REQ, handle & 0xFF, (handle >> 8) & 0xFF, value])


def unlock_write_frame(handle: int = 0x0014, value: int = 0x01) -> bytes:
    """A complete LE_LL_WITH_PHDR (DLT 256) frame carrying an ATT Write Request.

    Layering, outer to inner, so stock tshark dissects `btatt.opcode == 0x12`:
      - 10-byte BLE LE pseudo-header (rf channel, signal/noise dBm, AA offenses, ref AA, flags)
      - Link Layer data PDU: Access Address (4) + LL header (2: LLID/flags + length) + payload
        + 3-byte CRC trailer
      - L2CAP: payload length (2) + CID (2, = ATT 0x0004)
      - ATT Write Request PDU

    The access address is a connection (data-channel) address, not the advertising address,
    so the dissector treats this as a data PDU and walks into L2CAP/ATT. The 3-byte CRC
    trailer is required by the LL framing (without it the dissector consumes the tail of the
    ATT payload as the CRC); it is synthetic and the phdr `flags` leaves crc-checked clear, so
    no CRC error is reported. Field widths are validated by `att_write_pdu`.
    """
    att = att_write_pdu(handle, value)

    # L2CAP B-frame: 2-byte payload length, 2-byte CID, then the ATT PDU.
    l2cap = struct.pack("<HH", len(att), L2CAP_CID_ATT) + att

    # LL data PDU: header byte 0 = LLID 0b10 (start of an L2CAP message), header byte 1 =
    # payload length (the L2CAP bytes only, not the CRC). Access Address precedes the LL
    # header; a 3-byte CRC trailer closes the PDU.
    ll_header = bytes([_LL_DATA_PDU_START, len(l2cap)])
    ll = struct.pack("<I", _LL_ACCESS_ADDRESS) + ll_header + l2cap + _LL_CRC

    # LE pseudo-header (10 bytes). flags = 0: crc-checked clear, so the synthetic CRC trailer
    # is not validated and the dissector reports no CRC error.
    rf_channel = 0
    signal_dbm = 0
    noise_dbm = 0
    aa_offenses = 0
    flags = 0x0000
    phdr = struct.pack("<BbbBIH", rf_channel, signal_dbm, noise_dbm,
                       aa_offenses, _LL_ACCESS_ADDRESS, flags)
    return phdr + ll
