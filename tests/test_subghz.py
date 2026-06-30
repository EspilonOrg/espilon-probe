"""sub-GHz protocol: pseudo-header round-trip, freq/mod parsing, bounded sniff, demod hint,
bands, and replay DLT-vs-session validation.

sub-GHz IS a radio (PACKET shape): all four core verbs apply, BOUNDED. Captures carry the
8-byte pseudo-header under DLT_USER_PROBE_SUBGHZ (147). `replay` must refuse a non-147 pcap
(convention C4). The radio params (--freq/--mod/--rate) extend the core verbs.
"""

import os
import struct

import pytest

from espilon_probe import cli
from espilon_probe.core import wire
from espilon_probe.core.errors import ProbeError
from espilon_probe.core.frame import (DLT_USER_PROBE_SUBGHZ, PcapWriter, read_pcap)
from espilon_probe.protocols import subghz

from _mock_bridge import serve_mock

SUBGHZ_CAPS = {"protocol": "subghz", "channels": [433920000, 868300000, 915000000],
               "verbs": ["scan", "sniff", "inject", "replay", "subghz"],
               "shape": "packet", "pcap_dlt": DLT_USER_PROBE_SUBGHZ,
               "meta": {"sniff_default_seconds": 30.0}}


def _run(argv, port, capsys):
    os.environ["ESP_PROBE"] = f"tcp://127.0.0.1:{port}"
    cli.main(argv)
    return capsys.readouterr().out


# --- pure protocol-module tests (no bridge) ---

def test_pseudo_header_is_8_bytes_and_round_trips():
    raw = subghz.encode_frame(b"\xde\xad", "433.92M", "ook", 2000)
    assert len(raw) == 8 + 2
    assert raw[:8] == struct.pack("<IBHB", 433_920_000, 1, 2000, 2)
    dec = subghz.decode_frame(raw)
    assert dec == {"freq": 433_920_000, "mod": "ook", "rate": 2000, "payload": b"\xde\xad"}


def test_freq_parsing_units():
    assert subghz.parse_freq("433.92M") == 433_920_000
    assert subghz.parse_freq("868.3M") == 868_300_000
    assert subghz.parse_freq("915M") == 915_000_000
    assert subghz.parse_freq(433920000) == 433_920_000


def test_freq_parsing_refuses_garbage():
    with pytest.raises(ProbeError):
        subghz.parse_freq("not-a-freq")
    with pytest.raises(ProbeError):
        subghz.parse_freq("-5M")


def test_modulation_refuses_unknown():
    with pytest.raises(ProbeError):
        subghz.mod_code("am")
    with pytest.raises(ProbeError):
        subghz.mod_name(99)


def test_decode_refuses_truncated_and_mismatched():
    with pytest.raises(ProbeError):
        subghz.decode_frame(b"\x00\x00\x00")          # shorter than pseudo-header
    bad = struct.pack("<IBHB", 433_920_000, 1, 2000, 5) + b"\xaa"   # declares 5, has 1
    with pytest.raises(ProbeError):
        subghz.decode_frame(bad)


# --- CLI / bridge tests ---

def test_subghz_bands(capsys):
    bands = [{"name": "433", "lo": 433050000, "hi": 434790000, "default": 433920000}]

    def respond(msg):
        if msg.get("t") == wire.OP and msg.get("verb") == "subghz.bands":
            return {"t": wire.OP_RESULT, "result": {"bands": bands}}
        return wire.error("unhandled")

    srv, port = serve_mock(SUBGHZ_CAPS, respond)
    try:
        out = _run(["subghz", "bands"], port, capsys)
        assert "433: 433050000..434790000" in out
        assert "default=433920000" in out
    finally:
        srv.shutdown()
        srv.server_close()


SUBGHZ_CAPS_BANDS = dict(SUBGHZ_CAPS, meta={
    "sniff_default_seconds": 30.0,
    "bands": [
        {"name": "433", "lo": 433050000, "hi": 434790000, "default": 433920000},
        {"name": "868", "lo": 863000000, "hi": 870000000, "default": 868300000},
    ],
})


def test_scan_band_filter(capsys):
    rows = [{"name": "fob", "addr": "433.92M", "freq": 433920000, "energy": -30},
            {"name": "sensor", "addr": "868.3M", "freq": 868300000, "energy": -50}]

    def respond(msg):
        if msg.get("t") == wire.SCAN:
            return {"t": wire.SCAN_RESULT, "items": rows}
        return wire.error("unhandled")

    srv, port = serve_mock(SUBGHZ_CAPS_BANDS, respond)
    try:
        out = _run(["scan", "--band", "433"], port, capsys)
        assert "fob" in out and "sensor" not in out
    finally:
        srv.shutdown()
        srv.server_close()


def test_scan_unknown_band_refused(capsys):
    def respond(msg):
        if msg.get("t") == wire.SCAN:
            return {"t": wire.SCAN_RESULT, "items": []}
        return wire.error("unhandled")

    srv, port = serve_mock(SUBGHZ_CAPS_BANDS, respond)
    try:
        with pytest.raises(SystemExit) as ei:
            _run(["scan", "--band", "2400"], port, capsys)
        assert "unknown sub-GHz band" in str(ei.value)
    finally:
        srv.shutdown()
        srv.server_close()


def test_subghz_demod_hint(capsys):
    def respond(msg):
        if msg.get("t") == wire.OP and msg.get("verb") == "subghz.demod":
            return {"t": wire.OP_RESULT, "result": {
                "modulation": "ook", "bitrate": 2000, "encoding": "pwm", "guess_conf": 0.8}}
        return wire.error("unhandled")

    srv, port = serve_mock(SUBGHZ_CAPS, respond)
    try:
        out = _run(["subghz", "demod"], port, capsys)
        assert "modulation=ook" in out
        assert "encoding=pwm" in out
    finally:
        srv.shutdown()
        srv.server_close()


def test_sniff_bounded_writes_dlt_147(tmp_path, capsys):
    frame = subghz.encode_frame(b"\x01\x02\x03", "433.92M", "ook", 2000)

    def respond(msg):
        if msg.get("t") == wire.SNIFF:
            return {"t": wire.FRAME, "ts": 0.0, "channel": 433920000, "direction": "rx",
                    "protocol": "subghz", "raw": frame.hex(), "meta": {}}
        return None

    srv, port = serve_mock(SUBGHZ_CAPS, respond)
    try:
        out = _run(["sniff", "-w", str(tmp_path / "rf.pcap"), "-c", "1",
                    "--freq", "433.92M", "--mod", "ook"], port, capsys)
        assert "captured 1 frame(s)" in out
        dlt, recs = read_pcap(str(tmp_path / "rf.pcap"))
        assert dlt == DLT_USER_PROBE_SUBGHZ == 147
        assert recs == [frame]
        # the captured frame self-describes its radio params (replayable without state)
        assert subghz.decode_frame(recs[0])["freq"] == 433_920_000
    finally:
        srv.shutdown()
        srv.server_close()


def test_inject_builds_pseudo_header(tmp_path, capsys):
    captured = {}

    def respond(msg):
        if msg.get("t") == wire.INJECT:
            captured["frame"] = bytes.fromhex(msg["frame"])
            captured["channel"] = msg["channel"]
            return {"t": wire.ACK}
        return wire.error("unhandled")

    srv, port = serve_mock(SUBGHZ_CAPS, respond)
    try:
        _run(["inject", "--hex", "aabb", "--freq", "868.3M", "--mod", "2fsk", "--rate", "4800"],
             port, capsys)
        assert captured["channel"] == 868_300_000
        dec = subghz.decode_frame(captured["frame"])
        assert dec == {"freq": 868_300_000, "mod": "2fsk", "rate": 4800, "payload": b"\xaa\xbb"}
    finally:
        srv.shutdown()
        srv.server_close()


def test_replay_refuses_wrong_dlt(tmp_path, capsys):
    # A capture taken on a different link type (148 = SPI) must be refused for a sub-GHz replay.
    wrong = tmp_path / "wrong.pcap"
    with PcapWriter(str(wrong), 148) as pw:
        pw.write(wire.Frame(ts=0.0, channel=0, raw=b"\x00\x01\x02\x03"))

    def respond(msg):
        return {"t": wire.REPLAYED, "count": 0}

    srv, port = serve_mock(SUBGHZ_CAPS, respond)
    try:
        with pytest.raises(SystemExit) as ei:
            _run(["replay", "-r", str(wrong)], port, capsys)
        assert "does not match the active protocol's link type" in str(ei.value)
    finally:
        srv.shutdown()
        srv.server_close()


def test_replay_accepts_matching_dlt(tmp_path, capsys):
    cap = tmp_path / "ok.pcap"
    frame = subghz.encode_frame(b"\xfe", "433.92M", "ook", 2000)
    with PcapWriter(str(cap), DLT_USER_PROBE_SUBGHZ) as pw:
        pw.write(wire.Frame(ts=0.0, channel=0, raw=frame))

    def respond(msg):
        if msg.get("t") == wire.REPLAY:
            return {"t": wire.REPLAYED, "count": len(msg.get("frames", []))}
        return wire.error("unhandled")

    srv, port = serve_mock(SUBGHZ_CAPS, respond)
    try:
        out = _run(["replay", "-r", str(cap)], port, capsys)
        assert "replayed 1 frame(s)" in out
    finally:
        srv.shutdown()
        srv.server_close()
