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
