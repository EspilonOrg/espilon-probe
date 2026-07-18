"""CLI error-handling and capability-gating tests (convention C1).

The CLI must:
  - gate every protocol verb on `capabilities().verbs` BEFORE routing, and refuse an
    unsupported verb with a clean `probe: ...` message and a nonzero exit (no traceback);
  - render `ProbeError`, `wire.ProtocolError`, and `NotImplementedError` as clean `probe: ...`
    exits, never a traceback.
"""

import argparse
import os

import pytest

from espilon_probe import cli
from espilon_probe.core import wire
from espilon_probe.core.errors import ProbeError

from _mock_bridge import gatt_respond, serve_mock


def _caps(verbs, protocol="ble", **extra):
    c = {"protocol": protocol, "channels": [37, 38, 39], "verbs": verbs,
         "pcap_dlt": 256, "meta": {}}
    c.update(extra)
    return c


def _run(argv, port):
    os.environ["ESP_PROBE"] = f"tcp://127.0.0.1:{port}"
    return cli.main(argv)


def test_require_verb_passes_when_supported():
    caps = type("C", (), {"verbs": ["scan", "gatt"], "protocol": "ble"})()
    cli._require_verb(caps, "gatt")          # supported -> no raise


def test_require_verb_raises_clean_when_absent():
    caps = type("C", (), {"verbs": ["scan"], "protocol": "jtag"})()
    with pytest.raises(ProbeError) as ei:
        cli._require_verb(caps, "sniff")
    msg = str(ei.value)
    assert "'sniff' is not supported on protocol 'jtag'" in msg
    assert "supported: scan" in msg


def test_unsupported_verb_exits_clean_no_traceback():
    # The bridge advertises only scan+gatt; asking to sniff is a clean SystemExit.
    srv, port = serve_mock(_caps(["scan", "gatt"]), gatt_respond({"value": "x"}))
    try:
        with pytest.raises(SystemExit) as ei:
            _run(["sniff", "-w", "/tmp/nope.pcap", "-c", "1"], port)
        assert "is not supported on protocol 'ble'" in str(ei.value)
    finally:
        srv.shutdown()
        srv.server_close()


def test_gatt_unsupported_exits_clean():
    srv, port = serve_mock(_caps(["scan", "sniff", "inject", "replay"]), gatt_respond({"value": "x"}))
    try:
        with pytest.raises(SystemExit) as ei:
            _run(["gatt", "enum"], port)
        assert "'gatt' is not supported" in str(ei.value)
    finally:
        srv.shutdown()
        srv.server_close()


def test_can_send_gates_on_inject():
    # A protocol that does not advertise inject must refuse `can send` cleanly.
    srv, port = serve_mock(_caps(["scan"], protocol="can"), gatt_respond({"value": "x"}))
    try:
        with pytest.raises(SystemExit) as ei:
            _run(["can", "send", "0x123", "01"], port)
        assert "'inject' is not supported on protocol 'can'" in str(ei.value)
    finally:
        srv.shutdown()
        srv.server_close()


def test_probe_error_from_bridge_renders_clean():
    # The bridge returns an ERROR for the op; the client raises RuntimeError, rendered clean.
    def respond(msg):
        if msg.get("t") == wire.OP:
            return wire.error("device refused")
        return wire.error("unhandled")

    srv, port = serve_mock(_caps(["scan", "gatt"]), respond)
    try:
        with pytest.raises(SystemExit) as ei:
            _run(["gatt", "enum"], port)
        assert "probe: device refused" in str(ei.value)
    finally:
        srv.shutdown()
        srv.server_close()


def _capture_args(seconds=None, count=None):
    return argparse.Namespace(seconds=seconds, count=count)


def test_capture_bounds_reject_non_positive_and_nonfinite():
    # Finding 2: `sniff` / `can dump` must validate -t/-c the way scan does. A non-positive /
    # nan / inf value silently captured nothing (and nan/inf leaked stdlib text); now it fails loud.
    for bad in (0.0, -3.0, float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ProbeError):
            cli._capture_bounds(_capture_args(seconds=bad))
    for bad in (0, -1):
        with pytest.raises(ProbeError):
            cli._capture_bounds(_capture_args(count=bad))


def test_capture_bounds_pass_through_valid_and_omitted():
    assert cli._capture_bounds(_capture_args()) == (None, None)          # both omitted: fine
    assert cli._capture_bounds(_capture_args(seconds=2.5, count=4)) == (2.5, 4)


def test_scan_seconds_rejects_nonfinite(monkeypatch):
    # The shared positive-seconds check also hardens scan's window against nan/inf, not just <= 0.
    monkeypatch.delenv("ESP_PROBE_SCAN_SECS", raising=False)
    for bad in (float("nan"), float("inf")):
        with pytest.raises(ProbeError):
            cli._scan_seconds(_capture_args(seconds=bad))


def test_sniff_nan_seconds_exits_clean_no_leak():
    # End-to-end: `probe sniff -t nan` must be a clean `probe: ...` exit, never a raw settimeout leak.
    srv, port = serve_mock(_caps(["scan", "sniff", "inject", "replay"]), gatt_respond({"value": "x"}))
    try:
        with pytest.raises(SystemExit) as ei:
            _run(["sniff", "-w", "/tmp/nope.pcap", "-t", "nan"], port)
        assert "probe:" in str(ei.value)
        assert "positive number of seconds" in str(ei.value)
    finally:
        srv.shutdown()
        srv.server_close()


def test_can_dump_zero_count_exits_clean():
    srv, port = serve_mock(_caps(["scan", "sniff", "inject", "replay"], protocol="can"),
                           gatt_respond({"value": "x"}))
    try:
        with pytest.raises(SystemExit) as ei:
            _run(["can", "dump", "-w", "/tmp/nope.pcap", "-c", "0"], port)
        assert "probe:" in str(ei.value)
        assert "must be > 0" in str(ei.value)
    finally:
        srv.shutdown()
        srv.server_close()


def test_require_verb_rejects_substring_from_string_verbs():
    # Finding 3: a lying bridge sending `verbs` as a bare string must not pass the gate by substring
    # (`"uart" in "scan,uart"`). A non-list verbs field means "nothing advertised": refuse loud.
    caps = type("C", (), {"verbs": "scan,uart", "protocol": "uart"})()
    with pytest.raises(ProbeError):
        cli._require_verb(caps, "uart")
    with pytest.raises(ProbeError):
        cli._require_verb(caps, "a")            # a single char must not pass the substring test


def test_virtual_capabilities_coerce_string_verbs_channels_to_empty():
    # The virtual backend coerces a non-list verbs/channels to the empty list, so a string can never
    # reach the substring gate in the first place.
    from espilon_probe.backends.virtual import VirtualBackend
    caps = {"protocol": "uart", "channels": "37", "verbs": "uart", "shape": "stream", "meta": {}}
    srv, port = serve_mock(caps, lambda m: wire.error("unhandled"))
    try:
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            c = b.capabilities()
            assert c.verbs == []
            assert c.channels == []
    finally:
        srv.shutdown()
        srv.server_close()


def test_notimplemented_renders_clean(monkeypatch):
    # A backend op that raises NotImplementedError must surface as a clean probe: line.
    srv, port = serve_mock(_caps(["scan", "gatt"]), gatt_respond({"value": "x"}))
    try:
        from espilon_probe.backends.virtual import VirtualBackend

        def boom(self, *a, **k):
            raise NotImplementedError("gatt.enum")

        monkeypatch.setattr(VirtualBackend, "op", boom)
        with pytest.raises(SystemExit) as ei:
            _run(["gatt", "enum"], port)
        assert "probe:" in str(ei.value)
        assert "not supported by this backend" in str(ei.value)
    finally:
        srv.shutdown()
        srv.server_close()
