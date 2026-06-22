"""Client-side robustness tests against the mock wire server (server-side robustness lives
with the bridge in the content repo)."""

import socket
import threading

import pytest

from espilon_probe import cli
from espilon_probe.backends.virtual import VirtualBackend
from espilon_probe.core import frame as pframe

from _mock_bridge import GATT_CAPS, gatt_respond, serve_mock


def test_no_read_timeout_after_connect():
    srv, port = serve_mock(GATT_CAPS, gatt_respond({"value": "x"}))
    try:
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            assert b._sock.gettimeout() is None      # connect timeout must not leak into reads
    finally:
        srv.shutdown()
        srv.server_close()


def test_open_cleans_up_on_failed_handshake():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    port = s.getsockname()[1]

    def run():
        conn, _ = s.accept()
        conn.recv(1024)
        conn.sendall(b"\x00\x00\x00\x02{}")          # a valid frame, but not a welcome
        conn.close()

    threading.Thread(target=run, daemon=True).start()
    b = VirtualBackend(f"tcp://127.0.0.1:{port}")
    with pytest.raises(RuntimeError):
        b.open()
    assert b._sock is None                            # not left half-open
    s.close()


def test_gatt_resolve_by_uuid():
    srv, port = serve_mock(GATT_CAPS, gatt_respond({"value": "x"}))
    try:
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            assert cli._resolve_handle(b, "fff1") == 0x0011
            assert cli._resolve_handle(b, "0x0014") == 0x0014
    finally:
        srv.shutdown()
        srv.server_close()


def test_read_pcap_rejects_non_pcap(tmp_path):
    p = tmp_path / "junk.bin"
    p.write_bytes(b"this is definitely not a pcap file............")
    with pytest.raises(ValueError):
        pframe.read_pcap(str(p))
