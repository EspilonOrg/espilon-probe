"""CLI dispatch tests against the mock wire server (no device/bridge in the tool repo)."""

import os

from espilon_probe import cli

from _mock_bridge import GATT_CAPS, gatt_respond, serve_mock


def _run(argv, port, capsys):
    os.environ["ESP_PROBE"] = f"tcp://127.0.0.1:{port}"
    cli.main(argv)
    return capsys.readouterr().out


def test_cli_scan_info_gatt(capsys):
    state = {"value": "LOCKED", "after": "OPEN SECRET-mock-token"}
    srv, port = serve_mock(GATT_CAPS, gatt_respond(state))
    try:
        assert "protocol: ble" in _run(["info"], port, capsys)
        assert "MOCK-DEV" in _run(["scan"], port, capsys)
        assert "fff2" in _run(["gatt", "enum"], port, capsys)
        assert _run(["gatt", "read", "0x0011"], port, capsys).strip() == "LOCKED"
        _run(["gatt", "write", "0x0014", "01"], port, capsys)
        assert "SECRET-mock-token" in _run(["gatt", "read", "0x0011"], port, capsys)
    finally:
        srv.shutdown()
        srv.server_close()
