"""Round-trip tests for the probe wire protocol codec."""

import io

from espilon_probe.core import wire


def _roundtrip(msg):
    buf = io.BytesIO()
    wire.send(buf, msg)
    buf.seek(0)
    return wire.decode(buf)


def test_every_message_type_roundtrips():
    msgs = [
        wire.hello(),
        wire.welcome({"protocol": "ble", "channels": [37, 38, 39], "verbs": ["scan", "gatt"]}),
        {"t": wire.SCAN},
        {"t": wire.SCAN_RESULT, "items": [{"name": "ESPILON-LOCK", "addr": "C0:FF:EE:00:1A:7C"}]},
        {"t": wire.OP, "verb": "gatt.write", "args": {"handle": 0x14, "value": "01"}},
        {"t": wire.OP_RESULT, "result": {"ok": True}},
        {"t": wire.INJECT, "frame": "deadbeef", "channel": 37},
        {"t": wire.ACK},
        {"t": wire.REPLAY, "frames": ["aabb", "ccdd"], "filter": "att.write"},
        {"t": wire.REPLAYED, "count": 2},
        {"t": wire.SNIFF, "count": 10, "seconds": None, "channel": 15},
        {"t": wire.SNIFF_END, "count": 10},
        wire.error("nope"),
    ]
    for m in msgs:
        assert _roundtrip(m) == m


def test_frame_roundtrip():
    f = wire.Frame(ts=1.5, channel=15, raw=bytes.fromhex("6188"), direction="rx", protocol="zigbee",
                   meta={"lqi": 200})
    back = wire.Frame.from_msg(_roundtrip(f.to_msg()))
    assert back == f


def test_framing_handles_back_to_back_and_partial_reads():
    # two messages concatenated, read sequentially from one stream
    buf = io.BytesIO()
    wire.send(buf, wire.hello())
    wire.send(buf, {"t": wire.ACK})
    buf.seek(0)
    assert wire.decode(buf)["t"] == wire.HELLO
    assert wire.decode(buf)["t"] == wire.ACK
    assert wire.decode(buf) is None        # clean EOF on boundary


def test_missing_type_is_rejected():
    try:
        wire.encode({"no": "type"})
    except wire.ProtocolError:
        return
    raise AssertionError("expected ProtocolError for message without 't'")


def test_zero_length_body_reports_malformed_not_eof():
    # A length prefix declaring a 0-byte body is a malformed frame, not an EOF. The message
    # must say so rather than the misleading "unexpected EOF".
    buf = io.BytesIO(b"\x00\x00\x00\x00")        # 4-byte length prefix, value 0
    try:
        wire.decode(buf)
    except wire.ProtocolError as e:
        assert "malformed frame" in str(e)
        assert "EOF" not in str(e)
        return
    raise AssertionError("expected ProtocolError for a zero-length body")
