"""I2C protocol: verb set, capability gating, bus-address enumerate, register/EEPROM round-trip.

I2C master is a TRANSACTION protocol: it advertises only ["scan", "i2c"], so
sniff/inject/replay are gated OUT (convention C1) and fail clean. `scan` is repurposed as a bus
sweep (which 7-bit slave addresses ACK). `i2c dump` writes a RAW BINARY EEPROM image (the default
artifact), optionally with a transaction pcap under DLT_USER_PROBE_I2C (151).
"""

import os

import pytest

from espilon_probe import cli
from espilon_probe.core import wire
from espilon_probe.core.errors import ProbeError
from espilon_probe.core.frame import DLT_USER_PROBE_I2C, read_pcap

from _mock_bridge import serve_mock

I2C_CAPS = {"protocol": "i2c", "channels": [], "verbs": ["scan", "i2c"],
            "shape": "transaction", "pcap_dlt": DLT_USER_PROBE_I2C,
            "meta": {"bus": 0}}


def _run(argv, port, capsys):
    os.environ["ESP_PROBE"] = f"tcp://127.0.0.1:{port}"
    cli.main(argv)
    return capsys.readouterr().out


def _eeprom_respond(mem, *, addr=0x50, size=None, extra_acks=()):
    """A scripted AT24-class EEPROM at 7-bit `addr` with a backing byte array `mem`.

    `i2c.scan` enumerates `addr` (plus any bare `extra_acks`); a read/write to a non-ACK address
    NACKs (`{ok:False}` / empty data). `i2c.read` honours an optional `--reg` pointer; `i2c.write`
    page-programs the backing (a plain byte store, no NOR AND-masking) when the write-protect is
    clear. A `config` register carries the advisory write-protect bit.
    """
    state = {"mem": bytearray(mem), "wp": False, "ptr": 0}

    def _dev_list():
        devs = [{"addr": addr, "ack": True, "name": "AT24C-training", "size": size}]
        for a in extra_acks:
            devs.append({"addr": a, "ack": True})
        return devs

    def respond(msg):
        if msg.get("t") != wire.OP:
            return wire.error("unhandled")
        verb = msg.get("verb")
        a = msg.get("args", {})
        if verb == "i2c.scan":
            return {"t": wire.OP_RESULT, "result": {"devices": _dev_list()}}
        if verb == "i2c.read":
            if a.get("addr") != addr:
                return {"t": wire.OP_RESULT, "result": {"addr": a.get("addr"), "data": ""}}
            ptr = a["reg"] if a.get("reg") is not None else state["ptr"]
            n = a["n"]
            chunk = bytes(state["mem"][ptr:ptr + n])
            chunk = chunk + b"\xff" * (n - len(chunk))   # read past end returns erased fill
            state["ptr"] = ptr + n
            return {"t": wire.OP_RESULT, "result": {"addr": addr, "reg": ptr, "data": chunk.hex()}}
        if verb == "i2c.write":
            if a.get("addr") != addr:
                return {"t": wire.OP_RESULT, "result": {"ok": False, "addr": a.get("addr"),
                                                        "reason": "no ACK"}}
            if state["wp"]:
                return {"t": wire.OP_RESULT, "result": {"ok": False, "addr": addr,
                                                        "reason": "write-protected"}}
            ptr = a["reg"] if a.get("reg") is not None else state["ptr"]
            blob = bytes.fromhex(a["data"])
            state["mem"][ptr:ptr + len(blob)] = blob
            state["ptr"] = ptr + len(blob)
            return {"t": wire.OP_RESULT, "result": {"ok": True, "addr": addr, "written": len(blob)}}
        if verb == "i2c.reg":
            name = a.get("name")
            if "value" not in a:
                val = "01" if (name == "config" and state["wp"]) else "00"
                return {"t": wire.OP_RESULT, "result": {"name": name, "value": val}}
            if name == "config":
                state["wp"] = bool(bytes.fromhex(a["value"])[0] & 0x01)
            return {"t": wire.OP_RESULT, "result": {"ok": True, "name": name}}
        return wire.error(f"unhandled verb {verb}")

    return respond


# --- capability gating ------------------------------------------------------------------

def test_capabilities_verb_set():
    assert "scan" in I2C_CAPS["verbs"] and "i2c" in I2C_CAPS["verbs"]
    for gated in ("sniff", "inject", "replay"):
        assert gated not in I2C_CAPS["verbs"]


@pytest.mark.parametrize("gated", ["sniff", "inject", "replay"])
def test_gated_core_verbs_fail_clean(gated, capsys, tmp_path):
    srv, port = serve_mock(I2C_CAPS, _eeprom_respond(b""))
    try:
        if gated == "sniff":
            argv = ["sniff", "-w", str(tmp_path / "x.pcap"), "-c", "1"]
        elif gated == "inject":
            argv = ["inject", "--hex", "00"]
        else:
            argv = ["replay", "-r", str(tmp_path / "x.pcap")]
        with pytest.raises(SystemExit) as ei:
            _run(argv, port, capsys)
        assert f"'{gated}' is not supported on protocol 'i2c'" in str(ei.value)
        assert "supported: scan, i2c" in str(ei.value)
    finally:
        srv.shutdown()
        srv.server_close()


# --- scan (bus sweep) -------------------------------------------------------------------

def test_scan_enumerates_live_addresses(capsys):
    srv, port = serve_mock(I2C_CAPS, _eeprom_respond(b"", addr=0x50, extra_acks=(0x68,)))
    try:
        out = _run(["scan"], port, capsys)
        assert "0x50" in out
        assert "0x68" in out                 # a second ACKing slave surfaces as its own row
        assert "AT24C-training" in out
    finally:
        srv.shutdown()
        srv.server_close()


def test_i2c_scan_subverb_matches_core_scan(capsys):
    srv, port = serve_mock(I2C_CAPS, _eeprom_respond(b"", addr=0x50))
    try:
        out = _run(["i2c", "scan"], port, capsys)
        assert "0x50" in out and "ACK" in out
    finally:
        srv.shutdown()
        srv.server_close()


def test_scan_nack_only_bus_is_reported_empty(capsys):
    def respond(msg):
        if msg.get("t") == wire.OP and msg.get("verb") == "i2c.scan":
            # Every probed address NACKed: no devices on the bus.
            return {"t": wire.OP_RESULT, "result": {"devices": [{"addr": 0x50, "ack": False}]}}
        return wire.error("unhandled")

    srv, port = serve_mock(I2C_CAPS, respond)
    try:
        out = _run(["i2c", "scan"], port, capsys)
        assert "no devices ACKed" in out
    finally:
        srv.shutdown()
        srv.server_close()


# --- read / write round-trip ------------------------------------------------------------

def test_i2c_read_at_register_pointer(capsys):
    srv, port = serve_mock(I2C_CAPS, _eeprom_respond(bytes(range(32)), addr=0x50))
    try:
        out = _run(["i2c", "read", "--addr", "0x50", "--reg", "0x04", "-n", "4"], port, capsys)
        assert out.strip() == bytes(range(4, 8)).hex()
    finally:
        srv.shutdown()
        srv.server_close()


def test_i2c_write_then_read_round_trip(capsys):
    srv, port = serve_mock(I2C_CAPS, _eeprom_respond(bytes(64), addr=0x50))
    try:
        _run(["i2c", "write", "--addr", "0x50", "--reg", "0x10", "--hex", "deadbeef"],
             port, capsys)
        out = _run(["i2c", "read", "--addr", "0x50", "--reg", "0x10", "-n", "4"], port, capsys)
        assert out.strip() == "deadbeef"
    finally:
        srv.shutdown()
        srv.server_close()


def test_i2c_write_to_absent_address_nacks(capsys):
    # A write to an address no slave answers must fail loud (NACK), never print a raw dict.
    srv, port = serve_mock(I2C_CAPS, _eeprom_respond(bytes(16), addr=0x50))
    try:
        with pytest.raises(SystemExit) as ei:
            _run(["i2c", "write", "--addr", "0x51", "--hex", "00"], port, capsys)
        assert "write rejected" in str(ei.value)
        assert "no ACK" in str(ei.value)
    finally:
        srv.shutdown()
        srv.server_close()


def test_read_from_absent_address_returns_no_data(capsys):
    srv, port = serve_mock(I2C_CAPS, _eeprom_respond(bytes(16), addr=0x50))
    try:
        out = _run(["i2c", "read", "--addr", "0x51", "-n", "4"], port, capsys)
        assert out.strip() == ""             # NACK -> empty read, not source bytes
    finally:
        srv.shutdown()
        srv.server_close()


# --- named register + advisory write-protect --------------------------------------------

def test_i2c_reg_write_success_shape_is_not_rejected(capsys):
    srv, port = serve_mock(I2C_CAPS, _eeprom_respond(bytes(8), addr=0x50))
    try:
        out = _run(["i2c", "reg", "config", "--write", "01"], port, capsys)
        assert out.startswith("ok")
        assert "rejected" not in out
    finally:
        srv.shutdown()
        srv.server_close()


def test_advisory_write_protect_blocks_write(capsys):
    # Setting the config write-protect bit makes a subsequent page write NACK (advisory WP honoured
    # by this device model); clearing it lets the write through again.
    srv, port = serve_mock(I2C_CAPS, _eeprom_respond(bytes(16), addr=0x50))
    try:
        _run(["i2c", "reg", "config", "--write", "01"], port, capsys)     # engage WP
        with pytest.raises(SystemExit) as ei:
            _run(["i2c", "write", "--addr", "0x50", "--reg", "0", "--hex", "aa"], port, capsys)
        assert "write-protected" in str(ei.value)
        _run(["i2c", "reg", "config", "--write", "00"], port, capsys)     # release WP
        out = _run(["i2c", "write", "--addr", "0x50", "--reg", "0", "--hex", "aa"], port, capsys)
        assert out.startswith("ok")
    finally:
        srv.shutdown()
        srv.server_close()


# --- dump -------------------------------------------------------------------------------

def test_i2c_dump_writes_raw_binary(tmp_path, capsys):
    mem = bytes(range(128))
    srv, port = serve_mock(I2C_CAPS, _eeprom_respond(mem, addr=0x50, size=128))
    try:
        out_bin = tmp_path / "eeprom.bin"
        out = _run(["i2c", "dump", "--addr", "0x50", "-w", str(out_bin)], port, capsys)
        assert "dumped 128 byte(s)" in out           # size taken from the scan advertisement
        assert out_bin.read_bytes() == mem
    finally:
        srv.shutdown()
        srv.server_close()


def test_i2c_dump_explicit_size_and_pcap_uses_dlt_151(tmp_path, capsys):
    mem = b"\xaa\xbb\xcc\xdd"
    srv, port = serve_mock(I2C_CAPS, _eeprom_respond(mem, addr=0x50))     # no advertised size
    try:
        out_bin = tmp_path / "eeprom.bin"
        out_pcap = tmp_path / "sess.pcap"
        _run(["i2c", "dump", "--addr", "0x50", "--size", "4",
              "-w", str(out_bin), "--pcap", str(out_pcap)], port, capsys)
        assert out_bin.read_bytes() == mem
        dlt, recs = read_pcap(str(out_pcap))
        assert dlt == DLT_USER_PROBE_I2C == 151
        assert len(recs) == 1
        assert recs[0][0] == 1               # op byte == read
        assert recs[0].endswith(mem)
    finally:
        srv.shutdown()
        srv.server_close()


def test_i2c_dump_without_size_or_advert_refuses(capsys):
    srv, port = serve_mock(I2C_CAPS, _eeprom_respond(bytes(8), addr=0x50))   # no advertised size
    try:
        with pytest.raises(SystemExit) as ei:
            _run(["i2c", "dump", "--addr", "0x50", "-w", "/tmp/should-not-write.bin"], port, capsys)
        assert "no size" in str(ei.value)
    finally:
        srv.shutdown()
        srv.server_close()


# --- hardening: bounds + malformed backend responses ------------------------------------

def test_i2c_dump_length_ceiling_refused():
    from espilon_probe.protocols import i2c

    class _B:
        def op(self, *a, **k):
            raise AssertionError("backend must not be called for an over-ceiling dump")

    with pytest.raises(ProbeError) as ei:
        i2c.dump(_B(), 0x50, "/tmp/should-not-write.bin", size=i2c.DUMP_MAX_BYTES + 1)
    assert "exceeds the client ceiling" in str(ei.value)


def test_i2c_read_non_positive_length_refused():
    from espilon_probe.protocols import i2c

    class _B:
        def op(self, *a, **k):
            raise AssertionError("backend must not be called for a non-positive read")

    for bad in (0, -5):
        with pytest.raises(ProbeError) as ei:
            i2c.read(_B(), 0x50, bad)
        assert "must be positive" in str(ei.value)


class _ScriptB:
    def __init__(self, result):
        self.result = result

    def op(self, verb, **k):
        return self.result


def test_scan_rows_null_result_is_clean_probe_error():
    from espilon_probe.protocols import i2c
    with pytest.raises(ProbeError) as ei:
        i2c.scan_rows(_ScriptB(None))
    assert "null result" in str(ei.value)


def test_scan_rows_non_list_devices_is_clean_probe_error():
    from espilon_probe.protocols import i2c
    with pytest.raises(ProbeError) as ei:
        i2c.scan_rows(_ScriptB({"devices": "0x50"}))
    assert "non-list i2c devices" in str(ei.value)


def test_read_null_result_exits_clean(capsys):
    def respond(msg):
        if msg.get("t") == wire.OP and msg.get("verb") == "i2c.read":
            return {"t": wire.OP_RESULT, "result": None}
        return wire.error("unhandled")

    srv, port = serve_mock(I2C_CAPS, respond)
    try:
        with pytest.raises(SystemExit) as ei:
            _run(["i2c", "read", "--addr", "0x50", "-n", "4"], port, capsys)
        assert str(ei.value).startswith("probe:")
        assert "null result" in str(ei.value)
    finally:
        srv.shutdown()
        srv.server_close()


# --- 0x-hex arg handling (shared hardened _hex_value) -----------------------------------

@pytest.mark.parametrize("payload", ["deadbeef", "0xdeadbeef", "0xDEADBEEF"])
def test_i2c_write_accepts_0x_hex(payload, capsys):
    srv, port = serve_mock(I2C_CAPS, _eeprom_respond(bytes(64), addr=0x50))
    try:
        _run(["i2c", "write", "--addr", "0x50", "--reg", "0", "--hex", payload], port, capsys)
        out = _run(["i2c", "read", "--addr", "0x50", "--reg", "0", "-n", "4"], port, capsys)
        assert out.strip() == "deadbeef"
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.mark.parametrize("bad", ["", "0x", "0x ", "zz", "0xzz"])
def test_i2c_write_rejects_empty_or_bad_hex(bad, capsys):
    srv, port = serve_mock(I2C_CAPS, _eeprom_respond(bytes(16), addr=0x50))
    try:
        with pytest.raises(SystemExit) as ei:
            _run(["i2c", "write", "--addr", "0x50", "--hex", bad], port, capsys)
        assert "invalid" in str(ei.value)
    finally:
        srv.shutdown()
        srv.server_close()
