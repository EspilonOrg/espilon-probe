"""SocketCAN frame codec - the shared heart of the virtual and socketcan backends."""

import struct

import pytest

from espilon_probe.protocols import can


def test_standard_frame_roundtrip():
    raw = can.encode_frame(0x123, bytes.fromhex("deadbeef"))
    assert len(raw) == can.FRAME_SIZE
    cid, data, ext = can.decode_frame(raw)
    assert cid == 0x123 and data == bytes.fromhex("deadbeef") and ext is False


def test_extended_frame_roundtrip():
    raw = can.encode_frame(0x18DAF110, b"\x01\x02", extended=True)
    cid, data, ext = can.decode_frame(raw)
    assert cid == 0x18DAF110 and data == b"\x01\x02" and ext is True


def test_id_over_11bit_is_extended_automatically():
    cid, _, ext = can.decode_frame(can.encode_frame(0x800, b""))
    assert cid == 0x800 and ext is True


def test_ids_seen_dedups_in_order():
    fs = [can.encode_frame(0x100, b""), can.encode_frame(0x4D0, b""), can.encode_frame(0x100, b"")]
    assert can.ids_seen(fs) == [0x100, 0x4D0]


def test_illegal_dlc_is_rejected():
    # A frame whose DLC byte claims > 8 data bytes is illegal for classic CAN. Decode must
    # reject it, not silently take 9..15 bytes from the 8-byte data field.
    raw = struct.pack("<IB3x8s", 0x123, 9, b"\x00" * 8)
    assert len(raw) == can.FRAME_SIZE
    with pytest.raises(ValueError):
        can.decode_frame(raw)


def test_wrong_size_buffer_is_rejected_not_truncated():
    # A buffer that is not exactly one SocketCAN frame must be refused, not silently truncated.
    good = can.encode_frame(0x1, b"\x01")
    with pytest.raises(ValueError):
        can.decode_frame(good + b"\x00")          # one byte too long
    with pytest.raises(ValueError):
        can.decode_frame(good[:-1])               # one byte too short
