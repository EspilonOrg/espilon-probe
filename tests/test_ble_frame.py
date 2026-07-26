"""BLE `unlock_write_frame` must emit bytes that actually layer for its declared DLT.

The frame is declared as DLT 256 (LE_LL_WITH_PHDR). The prior implementation emitted a bare
ATT PDU, which does NOT dissect under DLT 256. This sprint emits the full layering
(LE phdr + LL data PDU + L2CAP + ATT). These tests prove the bytes are structured for DLT 256
two ways: a stdlib structural walk (always runs) and an optional scapy dissection
(skipped where scapy is absent, e.g. CI), plus field-width validation.
"""

import struct

import pytest

from espilon_probe.protocols import ble
from espilon_probe.core.errors import ProbeError


def _walk_le_ll_with_phdr(frame: bytes):
    """Reverse the DLT-256 layering with stdlib only; return the inner ATT PDU bytes."""
    assert len(frame) >= 10, "missing 10-byte LE pseudo-header"
    rf_chan, sig, noise, offenses, ref_aa, flags = struct.unpack("<BbbBIH", frame[:10])
    ll = frame[10:]
    assert len(ll) >= 4 + 2 + 3, "LL PDU too short (AA + header + CRC)"
    (aa,) = struct.unpack("<I", ll[:4])
    # The access address must NOT be the advertising AA, or this dissects as an ADV PDU.
    assert aa != 0x8E89BED6, "data PDU must not use the advertising access address"
    llid_flags, ll_len = ll[4], ll[5]
    assert (llid_flags & 0x03) in (0x01, 0x02), "LLID must mark an L2CAP data PDU"
    body = ll[6:]
    l2cap = body[:ll_len]              # CRC trailer follows the declared LL length
    crc = body[ll_len:]
    assert len(crc) == 3, "LL CRC trailer must be 3 bytes"
    l2_len, cid = struct.unpack("<HH", l2cap[:4])
    assert cid == ble.L2CAP_CID_ATT, "L2CAP CID must be the ATT channel (0x0004)"
    att = l2cap[4:4 + l2_len]
    return att


def test_unlock_write_frame_layers_for_dlt256():
    frame = ble.unlock_write_frame(0x0014, 0x01)
    att = _walk_le_ll_with_phdr(frame)
    assert att == bytes([ble.ATT_WRITE_REQ, 0x14, 0x00, 0x01])   # opcode, handle LE, value


def test_att_handle_and_value_widths_validated():
    with pytest.raises(ProbeError):
        ble.unlock_write_frame(0x1FFFF, 0x01)      # handle > 16 bits
    with pytest.raises(ProbeError):
        ble.unlock_write_frame(0x0014, 0x100)      # value > 8 bits


def test_scapy_dissects_btatt_opcode():
    pytest.importorskip("scapy")
    from scapy.layers.bluetooth4LE import BTLE_RF
    from scapy.layers.bluetooth import ATT_Hdr

    frame = ble.unlock_write_frame(0x0014, 0x01)
    pkt = BTLE_RF(frame)
    att = pkt.getlayer(ATT_Hdr)
    assert att is not None, "frame did not dissect down to the ATT layer under DLT 256"
    assert att.opcode == ble.ATT_WRITE_REQ
    assert bytes(att) == bytes([ble.ATT_WRITE_REQ, 0x14, 0x00, 0x01])
