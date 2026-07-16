"""Audit-A cosmetic polish: error-message honesty is consistent across all 7 protocols.

The Sprint-2 BLOCKER fix guarded jtag/spi at source, but the generic `scan` display loop, the
interactive read display (`_fmt_value`), and the operator `--hex` inject/spi-write paths still
leaked Python-internals text (`'NoneType' object has no attribute 'get'`,
`non-hexadecimal number found in fromhex()`) under a clean `probe:` prefix. These tests assert
the at-source protocol-level wording, and that no Python-internals text leaks.

These are consistency tests, not safety tests: the anti-leak BLOCKER is already closed.
"""

import os

import pytest

from espilon_probe import cli
from espilon_probe.core import wire
from espilon_probe.core.errors import ProbeError

from _mock_bridge import serve_mock


def _caps(verbs, protocol, **extra):
    c = {"protocol": protocol, "channels": [37, 38, 39], "verbs": verbs,
         "pcap_dlt": 256, "meta": {}}
    c.update(extra)
    return c


def _run(argv, port, capsys):
    os.environ["ESP_PROBE"] = f"tcp://127.0.0.1:{port}"
    cli.main(argv)
    return capsys.readouterr().out


# --- Fix 1: malformed scan row on a packet protocol (ble/zigbee/subghz) ---

def test_scan_skips_malformed_row_no_internals(capsys):
    # A packet protocol whose SCAN result mixes a good row with a null row must not render
    # `'NoneType' object has no attribute 'get'`; the null row is skipped, the good row prints.
    def respond(msg):
        if msg.get("t") == wire.SCAN:
            return {"t": wire.SCAN_RESULT,
                    "items": [{"name": "DEV-OK", "addr": "AA:BB", "rssi": -40}, None]}
        return wire.error("unhandled")

    srv, port = serve_mock(_caps(["scan"], "zigbee"), respond)
    try:
        out = _run(["scan"], port, capsys)
        assert "DEV-OK" in out
        assert "NoneType" not in out
        assert "has no attribute" not in out
    finally:
        srv.shutdown()
        srv.server_close()


def test_scan_non_list_items_is_clean_protocol_error(capsys):
    # A non-list `items` (here an object) is refused loud with a protocol-level message, never
    # a raw AttributeError/TypeError from iterating a non-list.
    def respond(msg):
        if msg.get("t") == wire.SCAN:
            return {"t": wire.SCAN_RESULT, "items": {"not": "a list"}}
        return wire.error("unhandled")

    srv, port = serve_mock(_caps(["scan"], "subghz"), respond)
    try:
        with pytest.raises(SystemExit) as ei:
            _run(["scan"], port, capsys)
        msg = str(ei.value)
        assert "non-list scan items" in msg
        assert "has no attribute" not in msg
        assert "not iterable" not in msg
    finally:
        srv.shutdown()
        srv.server_close()


def test_scan_rows_helper_skips_and_refuses():
    # Unit-level: non-dict rows skipped, non-list refused clean (matches jtag/spi.scan_rows).
    assert cli._scan_rows([{"name": "a"}, None, 3, {"name": "b"}]) == [{"name": "a"}, {"name": "b"}]
    assert cli._scan_rows(None) == []
    with pytest.raises(ProbeError) as ei:
        cli._scan_rows("not a list")
    assert "non-list scan items" in str(ei.value)


# --- Fix 2: bad backend hex on gatt / spi read display ---

def test_gatt_read_bad_hex_is_clean(capsys):
    # The backend returns a non-hex `value`; the read display must say `malformed hex for
    # gatt.read value`, not leak `non-hexadecimal number found in fromhex()`.
    chars = [{"handle": 0x0011, "uuid": "fff1", "props": "read"}]

    def respond(msg):
        t = msg.get("t")
        if t == wire.OP and msg.get("verb") == "gatt.enum":
            return {"t": wire.OP_RESULT, "result": {"characteristics": chars}}
        if t == wire.OP and msg.get("verb") == "gatt.read":
            return {"t": wire.OP_RESULT, "result": {"value": "zznothex"}}
        return wire.error("unhandled")

    srv, port = serve_mock(_caps(["scan", "gatt"], "ble"), respond)
    try:
        with pytest.raises(SystemExit) as ei:
            _run(["gatt", "read", "0x0011"], port, capsys)
        msg = str(ei.value)
        assert "malformed hex for gatt.read value" in msg
        assert "fromhex" not in msg
        assert "non-hexadecimal" not in msg
    finally:
        srv.shutdown()
        srv.server_close()


def test_spi_read_bad_hex_is_clean(capsys):
    # spi.read returns a non-hex `data`; interactive read display is consistent with spi.dump.
    def respond(msg):
        if msg.get("t") == wire.OP and msg.get("verb") == "spi.read":
            return {"t": wire.OP_RESULT, "result": {"data": "zz"}}
        return wire.error("unhandled")

    srv, port = serve_mock(_caps(["scan", "spi"], "spi", shape="transaction"), respond)
    try:
        with pytest.raises(SystemExit) as ei:
            _run(["spi", "read", "--addr", "0", "--len", "1"], port, capsys)
        msg = str(ei.value)
        assert "malformed hex for spi.read data" in msg
        assert "fromhex" not in msg
        assert "non-hexadecimal" not in msg
    finally:
        srv.shutdown()
        srv.server_close()


# --- Fix 3: operator --hex garbage on inject and spi write ---

def test_inject_hex_garbage_is_clean(capsys):
    # `probe inject --hex zz` must read `invalid hex ...` matching the address-error wording,
    # not fromhex's `non-hexadecimal number found in fromhex()`.
    def respond(msg):
        return wire.error("unhandled")

    srv, port = serve_mock(_caps(["scan", "inject"], "ble"), respond)
    try:
        with pytest.raises(SystemExit) as ei:
            _run(["inject", "--hex", "zz"], port, capsys)
        msg = str(ei.value)
        assert "invalid" in msg and "hex" in msg
        assert "fromhex" not in msg
        assert "non-hexadecimal" not in msg
    finally:
        srv.shutdown()
        srv.server_close()


def test_spi_write_hex_garbage_is_clean(capsys):
    # `probe spi write --hex zz` validates operator hex at source before hitting the backend.
    def respond(msg):
        return wire.error("unhandled")

    srv, port = serve_mock(_caps(["scan", "spi"], "spi", shape="transaction"), respond)
    try:
        with pytest.raises(SystemExit) as ei:
            _run(["spi", "write", "--addr", "0", "--hex", "zz"], port, capsys)
        msg = str(ei.value)
        assert "invalid" in msg and "hex" in msg
        assert "fromhex" not in msg
        assert "non-hexadecimal" not in msg
    finally:
        srv.shutdown()
        srv.server_close()


def test_parse_hex_helper():
    assert cli._parse_hex("0201") == b"\x02\x01"
    with pytest.raises(ProbeError) as ei:
        cli._parse_hex("zz", "inject --hex")
    assert "invalid inject --hex" in str(ei.value)
    assert "fromhex" not in str(ei.value)
