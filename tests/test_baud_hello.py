"""The virtual backend must advertise its --baud to the bridge in the HELLO config.

A real lab garbles output when the client's baud != the device's true line rate, so the
client has to hand the bridge its baud at handshake time. These tests pin that:

  - the wire `hello()` constructor is backward compatible (config defaults to {}), and
  - opening a VirtualBackend(baud=N) sends {"config": {"baud": N}} in its HELLO.
"""

from espilon_probe.backends.virtual import VirtualBackend
from espilon_probe.core import wire

from _mock_bridge import GATT_CAPS, serve_mock


def test_hello_is_backward_compatible():
    # Old callers pass nothing; config must still be present and empty (the bridge reads it).
    assert wire.hello() == {"t": wire.HELLO, "version": wire.PROTO_VERSION, "config": {}}
    assert wire.hello({"baud": 57600})["config"] == {"baud": 57600}


def test_virtual_backend_sends_baud_in_hello_config():
    captured: dict = {}
    srv, port = serve_mock(GATT_CAPS, lambda msg: wire.error("unused"), captured=captured)
    try:
        b = VirtualBackend(f"tcp://127.0.0.1:{port}", baud=57600)
        b.open()
        b.close()
    finally:
        srv.shutdown()
        srv.server_close()
    assert captured["hello"]["t"] == wire.HELLO
    assert captured["hello"].get("config", {}).get("baud") == 57600


def test_virtual_backend_default_baud_is_115200():
    captured: dict = {}
    srv, port = serve_mock(GATT_CAPS, lambda msg: None, captured=captured)
    try:
        b = VirtualBackend(f"tcp://127.0.0.1:{port}")   # no baud -> default
        b.open()
        b.close()
    finally:
        srv.shutdown()
        srv.server_close()
    assert captured["hello"]["config"]["baud"] == 115200
