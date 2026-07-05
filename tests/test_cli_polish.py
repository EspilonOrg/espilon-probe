"""Tool-polish tests: `probe info` verb consistency, clean write/hex/handle errors, and the
CAN send-then-dump transaction boundary from the tool's side.

These lock the CLI-formatting fixes that lifted the spi/jtag/can/uart boxes toward 10/10:
  - `probe info` renders each protocol's own action verb, deduplicated (no `scan,scan`, no
    missing `can`);
  - a non-hex CAN payload, a rejected write, and an unreadable GATT handle each surface a
    clean one-line `probe:` error (nonzero exit), never a traceback, a raw dict, or an empty
    line;
  - the virtual backend reads exactly the current SNIFF's frames and holds no cross-connection
    buffer, so a well-behaved bridge's frames do not bleed across dumps (the tool side of the
    CAN queue-boundary contract).
"""

import os

import pytest

from espilon_probe import cli
from espilon_probe.backends.virtual import VirtualBackend
from espilon_probe.core import wire
from espilon_probe.protocols import can

from _mock_bridge import serve_mock


def _caps(verbs, protocol, **extra):
    c = {"protocol": protocol, "channels": [], "verbs": verbs, "pcap_dlt": 227, "meta": {}}
    c.update(extra)
    return c


def _run(argv, port, capsys):
    os.environ["ESP_PROBE"] = f"tcp://127.0.0.1:{port}"
    cli.main(argv)
    return capsys.readouterr().out


def _caps_obj(protocol, verbs):
    return type("C", (), {"protocol": protocol, "verbs": verbs})()


# --- Fix 1: `probe info` verb consistency + dedup ---

def test_info_verbs_dedups_repeats():
    # A sloppy bridge that advertised `scan,...,scan,jtag` must render each verb once.
    caps = _caps_obj("jtag", ["scan", "sniff", "inject", "replay", "scan", "jtag"])
    assert cli._info_verbs(caps) == ["scan", "sniff", "inject", "replay", "jtag"]


def test_info_verbs_appends_missing_protocol_verb():
    # A CAN bridge advertises only the core verbs; `can` is a real CLI command, so info lists it.
    caps = _caps_obj("can", ["scan", "sniff", "inject", "replay"])
    assert cli._info_verbs(caps) == ["scan", "sniff", "inject", "replay", "can"]


def test_info_verbs_keeps_uart_and_does_not_duplicate():
    caps = _caps_obj("uart", ["scan", "uart"])
    assert cli._info_verbs(caps) == ["scan", "uart"]


def test_info_verbs_zigbee_has_no_group_verb():
    # Zigbee is pure packet: no group verb to append, the core list passes through untouched.
    caps = _caps_obj("zigbee", ["scan", "sniff", "inject", "replay"])
    assert cli._info_verbs(caps) == ["scan", "sniff", "inject", "replay"]


def test_info_verbs_all_protocols_include_own_verb():
    for proto, verb in cli._PROTOCOL_VERB.items():
        caps = _caps_obj(proto, ["scan"])
        assert verb in cli._info_verbs(caps)


def test_info_end_to_end_can_shows_can_verb(capsys):
    srv, port = serve_mock(_caps(["scan", "sniff", "inject", "replay"], "can"), lambda m: None)
    try:
        out = _run(["info"], port, capsys)
        verbs = out.split("verbs:")[1].strip().split(",")
        assert verbs == ["scan", "sniff", "inject", "replay", "can"]
    finally:
        srv.shutdown()
        srv.server_close()


def test_info_end_to_end_jtag_dedups(capsys):
    # A bridge that double-lists `scan` must not surface a duplicate in `probe info`.
    caps = _caps(["scan", "sniff", "inject", "replay", "scan", "jtag"], "jtag", shape="transaction")
    srv, port = serve_mock(caps, lambda m: None)
    try:
        out = _run(["info"], port, capsys)
        verbs = out.split("verbs:")[1].strip().split(",")
        assert verbs == ["scan", "sniff", "inject", "replay", "jtag"]
        assert verbs.count("scan") == 1
    finally:
        srv.shutdown()
        srv.server_close()


# --- Fix 2a: non-hex CAN payload is a clean error ---

def test_can_send_bad_hex_is_clean(capsys):
    srv, port = serve_mock(_caps(["scan", "sniff", "inject", "replay"], "can"), lambda m: {"t": wire.ACK})
    try:
        with pytest.raises(SystemExit) as ei:
            _run(["can", "send", "0x7e0", "ZZ"], port, capsys)
        msg = str(ei.value)
        assert "invalid" in msg and "hex" in msg
        assert "fromhex" not in msg
        assert "non-hexadecimal" not in msg
    finally:
        srv.shutdown()
        srv.server_close()


def test_can_send_bad_id_is_clean(capsys):
    srv, port = serve_mock(_caps(["scan", "sniff", "inject", "replay"], "can"), lambda m: {"t": wire.ACK})
    try:
        with pytest.raises(SystemExit) as ei:
            _run(["can", "send", "0xZZ", "01"], port, capsys)
        msg = str(ei.value)
        assert "invalid arbitration id" in msg
        assert "invalid literal" not in msg          # no raw int() text
    finally:
        srv.shutdown()
        srv.server_close()


# --- Fix 2b: a rejected write is a clean line, never a raw dict ---

def _reject_write_respond(verb):
    def respond(msg):
        if msg.get("t") == wire.OP and msg.get("verb") == verb:
            return {"t": wire.OP_RESULT, "result": {"ok": False, "addr": 0x40000004}}
        return wire.error("unhandled")
    return respond


def test_jtag_write_reject_is_clean(capsys):
    caps = _caps(["scan", "jtag"], "jtag", shape="transaction")
    srv, port = serve_mock(caps, _reject_write_respond("jtag.write"))
    try:
        with pytest.raises(SystemExit) as ei:
            _run(["jtag", "write", "--addr", "0x40000004", "--word", "0x1"], port, capsys)
        msg = str(ei.value)
        assert "write rejected at 0x40000004" in msg
        assert "{" not in msg and "'ok'" not in msg          # no raw python dict
    finally:
        srv.shutdown()
        srv.server_close()


def test_spi_write_reject_is_clean(capsys):
    caps = _caps(["scan", "spi"], "spi", shape="transaction")
    srv, port = serve_mock(caps, _reject_write_respond("spi.write"))
    try:
        with pytest.raises(SystemExit) as ei:
            _run(["spi", "write", "--addr", "0x40000004", "--hex", "01"], port, capsys)
        msg = str(ei.value)
        assert "write rejected at 0x40000004" in msg
        assert "{" not in msg
    finally:
        srv.shutdown()
        srv.server_close()


def test_gatt_write_reject_is_clean(capsys):
    caps = _caps(["scan", "gatt"], "ble", pcap_dlt=256)
    srv, port = serve_mock(caps, _reject_write_respond("gatt.write"))
    try:
        with pytest.raises(SystemExit) as ei:
            _run(["gatt", "write", "0x0014", "01"], port, capsys)
        msg = str(ei.value)
        assert "write rejected at 0x40000004" in msg
        assert "'ok'" not in msg
    finally:
        srv.shutdown()
        srv.server_close()


def test_write_reject_includes_reason_when_supplied(capsys):
    def respond(msg):
        if msg.get("t") == wire.OP and msg.get("verb") == "jtag.write":
            return {"t": wire.OP_RESULT,
                    "result": {"ok": False, "addr": 0x20000000, "reason": "write-protected"}}
        return wire.error("unhandled")

    caps = _caps(["scan", "jtag"], "jtag", shape="transaction")
    srv, port = serve_mock(caps, respond)
    try:
        with pytest.raises(SystemExit) as ei:
            _run(["jtag", "write", "--addr", "0x20000000", "--word", "0x1"], port, capsys)
        msg = str(ei.value)
        assert "write rejected at 0x20000000" in msg
        assert "write-protected" in msg
    finally:
        srv.shutdown()
        srv.server_close()


def test_report_write_ok_prints_ok(capsys):
    cli._report_write({"ok": True})
    assert capsys.readouterr().out.strip() == "ok"


# --- Fix 2c: unreadable/unknown GATT handle is not a silent empty line ---

def test_gatt_read_unknown_handle_is_clean(capsys):
    # The bridge answers gatt.read with a result that carries no `value` (unknown handle). The
    # tool must refuse loud, not print an empty line.
    def respond(msg):
        if msg.get("t") == wire.OP and msg.get("verb") == "gatt.read":
            return {"t": wire.OP_RESULT, "result": {}}
        return wire.error("unhandled")

    caps = _caps(["scan", "gatt"], "ble", pcap_dlt=256)
    srv, port = serve_mock(caps, respond)
    try:
        with pytest.raises(SystemExit) as ei:
            _run(["gatt", "read", "0x9999"], port, capsys)
        msg = str(ei.value)
        assert "no such handle 0x9999" in msg
        assert "not readable" in msg
    finally:
        srv.shutdown()
        srv.server_close()


def test_gatt_read_present_value_still_prints(capsys):
    # Regression guard: a real read with an explicit (even empty-ish) value key still renders.
    def respond(msg):
        if msg.get("t") == wire.OP and msg.get("verb") == "gatt.read":
            return {"t": wire.OP_RESULT, "result": {"value": b"OPEN".hex()}}
        return wire.error("unhandled")

    caps = _caps(["scan", "gatt"], "ble", pcap_dlt=256)
    srv, port = serve_mock(caps, respond)
    try:
        assert _run(["gatt", "read", "0x0011"], port, capsys).strip() == "OPEN"
    finally:
        srv.shutdown()
        srv.server_close()


# --- Fix 3: CAN send-then-dump transaction boundary (tool side) ---

def _can_queue_server(state):
    """A CAN target that queues one response frame per INJECT and delivers it on the next SNIFF.

    This models a send-then-dump ordering: a dump issued before any send captures
    nothing, and each delivered frame is popped so a well-behaved target never re-serves it.
    """
    def respond(msg):
        t = msg.get("t")
        if t == wire.INJECT:
            state["queue"].append(can.encode_frame(0x7E8, bytes.fromhex("037f2231")))
            return {"t": wire.ACK}
        if t == wire.SNIFF:
            if state["queue"]:
                raw = state["queue"].pop(0)
                return {"t": wire.FRAME, "ts": 0.0, "channel": 0, "direction": "rx",
                        "protocol": "can", "raw": raw.hex(), "meta": {}}
            return {"t": wire.SNIFF_END, "count": 0}
        if t == wire.SNIFF_END:
            return None
        return wire.error("unhandled")
    return respond


def _read_pcap_frames(path):
    from espilon_probe.core.frame import read_pcap
    _, frames = read_pcap(path)
    return frames


def test_can_send_then_dump_captures_current_frame(tmp_path):
    # send queues the negative response; the following dump captures exactly that frame.
    state = {"queue": []}
    srv, port = serve_mock(_caps(["scan", "sniff", "inject", "replay"], "can"),
                           _can_queue_server(state))
    try:
        os.environ["ESP_PROBE"] = f"tcp://127.0.0.1:{port}"
        cli.main(["can", "send", "0x7e0", "0322f190"])
        cli.main(["can", "dump", "-w", str(tmp_path / "a.pcap"), "-c", "1"])
        frames = _read_pcap_frames(str(tmp_path / "a.pcap"))
        assert len(frames) == 1
        cid, data, _ = can.decode_frame(frames[0])
        assert cid == 0x7E8
        assert data == bytes.fromhex("037f2231")
    finally:
        srv.shutdown()
        srv.server_close()


def test_can_dump_after_drain_does_not_bleed_prior_frame(tmp_path):
    # After the queued frame is consumed, a second dump (a fresh connection) must capture
    # nothing: the tool holds no cross-connection read buffer, so a prior transaction's frame
    # does not bleed into a later dump.
    state = {"queue": []}
    srv, port = serve_mock(_caps(["scan", "sniff", "inject", "replay"], "can"),
                           _can_queue_server(state))
    try:
        os.environ["ESP_PROBE"] = f"tcp://127.0.0.1:{port}"
        cli.main(["can", "send", "0x7e0", "0322f190"])
        cli.main(["can", "dump", "-w", str(tmp_path / "first.pcap"), "-c", "1"])
        cli.main(["can", "dump", "-w", str(tmp_path / "second.pcap"), "-t", "0.2"])
        assert len(_read_pcap_frames(str(tmp_path / "first.pcap"))) == 1
        assert _read_pcap_frames(str(tmp_path / "second.pcap")) == []
    finally:
        srv.shutdown()
        srv.server_close()


def test_virtual_backend_holds_no_cross_instance_buffer():
    # Two backends against the same bridge each own their socket/reader: no shared buffer that
    # could carry a stale frame from one connection into the next.
    srv, port = serve_mock(_caps(["scan", "sniff", "inject", "replay"], "can"), lambda m: None)
    try:
        os.environ["ESP_PROBE"] = f"tcp://127.0.0.1:{port}"
        b1 = VirtualBackend(f"tcp://127.0.0.1:{port}")
        b2 = VirtualBackend(f"tcp://127.0.0.1:{port}")
        b1.open()
        b2.open()
        try:
            assert b1._sock is not b2._sock
            assert b1._r is not b2._r
        finally:
            b1.close()
            b2.close()
    finally:
        srv.shutdown()
        srv.server_close()
