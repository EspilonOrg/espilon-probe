"""Capabilities.shape (convention C2): backward-compatible, surfaced by `info`.

`shape` is one of "packet" | "stream" | "transaction"; it defaults to "packet" so the
existing four protocols and any older bridge keep working unchanged.
"""

import os

from espilon_probe import cli
from espilon_probe.backends.serial import SerialBackend
from espilon_probe.backends.socketcan import SocketCanBackend
from espilon_probe.core.backend import Capabilities

from _mock_bridge import GATT_CAPS, gatt_respond, serve_mock


def test_shape_defaults_to_packet():
    c = Capabilities(protocol="x", transport="virtual")
    assert c.shape == "packet"


def test_socketcan_is_packet_and_serial_is_stream():
    assert SocketCanBackend("vcan0").capabilities().shape == "packet"
    assert SerialBackend("/dev/null").capabilities().shape == "stream"


def test_virtual_defaults_shape_when_bridge_omits_it():
    # GATT_CAPS carries no "shape" key; the virtual backend must default it to "packet".
    srv, port = serve_mock(GATT_CAPS, gatt_respond({"value": "x"}))
    try:
        from espilon_probe.backends.virtual import VirtualBackend
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            assert b.capabilities().shape == "packet"
    finally:
        srv.shutdown()
        srv.server_close()


def test_info_prints_shape(capsys):
    srv, port = serve_mock(GATT_CAPS, gatt_respond({"value": "x"}))
    try:
        os.environ["ESP_PROBE"] = f"tcp://127.0.0.1:{port}"
        cli.main(["info"])
        out = capsys.readouterr().out
        assert "shape: packet" in out
    finally:
        srv.shutdown()
        srv.server_close()
