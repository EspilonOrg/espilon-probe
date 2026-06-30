"""JTAG protocol: verb set, capability gating, scan-chain/idcode enumerate, dump artifact.

JTAG is a TRANSACTION protocol: it advertises only ["scan", "jtag"], so sniff/inject/replay
are gated OUT by the CLI capability gate (convention C1) and fail clean. `scan` is repurposed
as scan-chain enumeration. `jtag dump` writes a RAW BINARY memory image (the default
artifact), optionally with a transaction pcap under DLT_USER_PROBE_JTAG (149).
"""

import os
import struct

import pytest

from espilon_probe import cli
from espilon_probe.core import wire
from espilon_probe.core.errors import ProbeError
from espilon_probe.core.frame import DLT_USER_PROBE_JTAG, read_pcap

from _mock_bridge import serve_mock

JTAG_CAPS = {"protocol": "jtag", "channels": [], "verbs": ["scan", "jtag"],
             "shape": "transaction", "pcap_dlt": DLT_USER_PROBE_JTAG, "meta": {"taps": 1}}


def _run(argv, port, capsys):
    os.environ["ESP_PROBE"] = f"tcp://127.0.0.1:{port}"
    cli.main(argv)
    return capsys.readouterr().out


def _jtag_respond(mem):
    """A scripted TAP: one tap with a fixed IDCODE; reads return words from `mem` (addr->u32),
    filling unmapped addresses with 0xFFFFFFFF (like an unmapped region)."""
    taps = [{"index": 0, "idcode": 0x4BA00477, "irlen": 4, "name": "cortex-m"}]

    def respond(msg):
        if msg.get("t") != wire.OP:
            return wire.error("unhandled")
        verb = msg.get("verb")
        a = msg.get("args", {})
        if verb == "jtag.scan_chain":
            return {"t": wire.OP_RESULT, "result": {"taps": taps}}
        if verb == "jtag.idcode":
            return {"t": wire.OP_RESULT, "result": {
                "idcode": 0x4BA00477, "manufacturer": "arm", "part": "cortex-m",
                "version": 4, "name": "cortex-m"}}
        if verb == "jtag.halt":
            return {"t": wire.OP_RESULT, "result": {"state": "halted", "pc": 0x08000100}}
        if verb == "jtag.read":
            addr, words = a["addr"], a["words"]
            out = [mem.get(addr + i * 4, 0xFFFFFFFF) for i in range(words)]
            return {"t": wire.OP_RESULT, "result": {"addr": addr, "words": out}}
        return wire.error(f"unhandled verb {verb}")

    return respond


def test_capabilities_verb_set():
    assert "scan" in JTAG_CAPS["verbs"] and "jtag" in JTAG_CAPS["verbs"]
    for gated in ("sniff", "inject", "replay"):
        assert gated not in JTAG_CAPS["verbs"]


@pytest.mark.parametrize("gated", ["sniff", "inject", "replay"])
def test_gated_core_verbs_fail_clean(gated, capsys, tmp_path):
    srv, port = serve_mock(JTAG_CAPS, _jtag_respond({}))
    try:
        if gated == "sniff":
            argv = ["sniff", "-w", str(tmp_path / "x.pcap"), "-c", "1"]
        elif gated == "inject":
            argv = ["inject", "--hex", "00"]
        else:
            argv = ["replay", "-r", str(tmp_path / "x.pcap")]
        with pytest.raises(SystemExit) as ei:
            _run(argv, port, capsys)
        assert f"'{gated}' is not supported on protocol 'jtag'" in str(ei.value)
        assert "supported: scan, jtag" in str(ei.value)
    finally:
        srv.shutdown()
        srv.server_close()


def test_scan_enumerates_chain(capsys):
    srv, port = serve_mock(JTAG_CAPS, _jtag_respond({}))
    try:
        out = _run(["scan"], port, capsys)
        assert "0x4ba00477" in out
        assert "cortex-m" in out
    finally:
        srv.shutdown()
        srv.server_close()


def test_jtag_idcode(capsys):
    srv, port = serve_mock(JTAG_CAPS, _jtag_respond({}))
    try:
        out = _run(["jtag", "idcode"], port, capsys)
        assert "idcode=0x4ba00477" in out
    finally:
        srv.shutdown()
        srv.server_close()


def test_jtag_read_words(capsys):
    mem = {0x20000000: 0xDEADBEEF, 0x20000004: 0xCAFEBABE}
    srv, port = serve_mock(JTAG_CAPS, _jtag_respond(mem))
    try:
        out = _run(["jtag", "read", "--addr", "0x20000000", "--words", "2"], port, capsys)
        assert "0x20000000: 0xdeadbeef" in out
        assert "0x20000004: 0xcafebabe" in out
    finally:
        srv.shutdown()
        srv.server_close()


def test_jtag_dump_writes_raw_binary(tmp_path, capsys):
    mem = {0x20000000: 0x11223344, 0x20000004: 0x55667788}
    srv, port = serve_mock(JTAG_CAPS, _jtag_respond(mem))
    try:
        out_bin = tmp_path / "img.bin"
        out = _run(["jtag", "dump", "--addr", "0x20000000", "--len", "8",
                    "-w", str(out_bin)], port, capsys)
        assert "dumped 8 byte(s)" in out
        data = out_bin.read_bytes()
        assert data == struct.pack("<II", 0x11223344, 0x55667788)
    finally:
        srv.shutdown()
        srv.server_close()


def test_jtag_dump_optional_pcap_uses_dlt_149(tmp_path, capsys):
    mem = {0x0: 0xAABBCCDD}
    srv, port = serve_mock(JTAG_CAPS, _jtag_respond(mem))
    try:
        out_bin = tmp_path / "img.bin"
        out_pcap = tmp_path / "sess.pcap"
        _run(["jtag", "dump", "--addr", "0x0", "--len", "4",
              "-w", str(out_bin), "--pcap", str(out_pcap)], port, capsys)
        dlt, recs = read_pcap(str(out_pcap))
        assert dlt == DLT_USER_PROBE_JTAG == 149
        assert len(recs) == 1
        # record header op byte == 5 (read), payload carries the word LE
        assert recs[0][0] == 5
        assert recs[0].endswith(struct.pack("<I", 0xAABBCCDD))
    finally:
        srv.shutdown()
        srv.server_close()


def test_jtag_dump_length_ceiling_refused():
    from espilon_probe.protocols import jtag

    class _B:
        def op(self, *a, **k):  # never reached: the ceiling is checked first
            raise AssertionError("backend must not be called for an over-ceiling dump")

    with pytest.raises(ProbeError) as ei:
        jtag.dump(_B(), 0, jtag.DUMP_MAX_BYTES + 4, "/tmp/should-not-write.bin")
    assert "exceeds the client ceiling" in str(ei.value)


def test_jtag_dump_non_word_length_refused():
    from espilon_probe.protocols import jtag

    class _B:
        def op(self, *a, **k):
            raise AssertionError("backend must not be called")

    with pytest.raises(ProbeError) as ei:
        jtag.dump(_B(), 0, 3, "/tmp/should-not-write.bin")
    assert "not a multiple" in str(ei.value)


# --- malformed-backend-response robustness (Sprint 2 audit repros) ---

class _ScriptB:
    """A backend whose `op()` returns a fixed, deliberately-malformed result."""
    def __init__(self, result):
        self.result = result

    def op(self, verb, **k):
        return self.result


@pytest.mark.parametrize("result, note", [
    ({"taps": [None]}, "null tap row is skipped, not .get()'d"),
    ({"taps": {"x": 1}}, "dict (non-list) taps refused clean"),
    ({"taps": None}, "null taps coerced to empty"),
    (None, "explicit null result (not just a missing key)"),
])
def test_scan_rows_survives_malformed_taps(result, note):
    from espilon_probe.protocols import jtag
    try:
        rows = jtag.scan_rows(_ScriptB(result))
        assert isinstance(rows, list)          # coerced to a clean (possibly empty) list
    except ProbeError:
        pass                                   # or a clean refusal - never a raw traceback
    except (AttributeError, TypeError) as e:   # the bug this pins: must NOT happen
        raise AssertionError(f"raw {type(e).__name__} leaked ({note}): {e}")


def test_scan_rows_non_numeric_idcode_is_clean_probe_error():
    from espilon_probe.protocols import jtag
    with pytest.raises(ProbeError) as ei:
        jtag.scan_rows(_ScriptB({"taps": [{"idcode": "GARBAGE", "name": "x"}]}))
    assert "non-numeric idcode" in str(ei.value)


def test_read_words_string_word_is_clean_probe_error():
    from espilon_probe.protocols import jtag
    with pytest.raises(ProbeError) as ei:
        jtag.read_words(_ScriptB({"words": ["not-a-number"]}), 0, 1)
    assert "non-numeric word" in str(ei.value)


def test_cli_scan_chain_null_result_exits_clean(capsys):
    # End-to-end: a bridge returning an explicit null result for scan_chain must yield a clean
    # `probe: ...` exit, never a stack trace (the backstop + protocol coercion together).
    def respond(msg):
        if msg.get("t") == wire.OP and msg.get("verb") == "jtag.scan_chain":
            return {"t": wire.OP_RESULT, "result": None}
        return wire.error("unhandled")

    srv, port = serve_mock(JTAG_CAPS, respond)
    try:
        with pytest.raises(SystemExit) as ei:
            _run(["jtag", "scan-chain"], port, capsys)
        assert str(ei.value).startswith("probe:")
        assert "null result" in str(ei.value)
    finally:
        srv.shutdown()
        srv.server_close()
