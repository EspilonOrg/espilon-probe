"""SocketCAN frame codec - the shared heart of the virtual and socketcan backends."""

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
