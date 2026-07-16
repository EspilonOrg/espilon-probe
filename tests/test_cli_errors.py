"""CLI error-handling and capability-gating tests (convention C1).

The CLI must:
  - gate every protocol verb on `capabilities().verbs` BEFORE routing, and refuse an
    unsupported verb with a clean `probe: ...` message and a nonzero exit (no traceback);
  - render `ProbeError`, `wire.ProtocolError`, and `NotImplementedError` as clean `probe: ...`
    exits, never a traceback.
"""

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
