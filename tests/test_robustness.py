"""Client-side robustness tests against the mock wire server (server-side robustness is the
target server's responsibility)."""

import socket
import threading
import time

import pytest

from espilon_probe import cli
from espilon_probe.backends.virtual import VirtualBackend
from espilon_probe.core import frame as pframe
from espilon_probe.core.errors import ProbeError

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
    with pytest.raises(ProbeError):
        pframe.read_pcap(str(p))


def test_silent_target_times_out_not_hangs(monkeypatch):
    # A target that WELCOMEs (so open() succeeds) then never answers a control op must NOT hang
    # the client: the request/response path is bounded by ESP_PROBE_TIMEOUT and raises a clean
    # ProbeError well within that budget, rather than blocking forever.
    monkeypatch.setenv("ESP_PROBE_TIMEOUT", "0.5")

    def silent(msg):
        return None                          # WELCOME already sent; every op gets no reply

    srv, port = serve_mock(GATT_CAPS, silent)
    try:
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            start = time.monotonic()
            with pytest.raises(ProbeError) as ei:
                b.scan()
            elapsed = time.monotonic() - start
            assert elapsed < 5.0             # bounded by the 0.5s budget, not a hang
            assert "silent" in str(ei.value).lower()
            assert b._sock.gettimeout() is None   # timeout restored, does not leak to later reads
    finally:
        srv.shutdown()
        srv.server_close()


def test_silent_target_verb_exits_clean(monkeypatch, capsys):
    # End-to-end through the CLI: a silent target surfaces as a one-line `probe: ...` SystemExit
    # (nonzero exit), never a traceback and never a hang.
    monkeypatch.setenv("ESP_PROBE_TIMEOUT", "0.5")

    def silent(msg):
        return None

    srv, port = serve_mock(GATT_CAPS, silent)
    monkeypatch.setenv("ESP_PROBE", f"tcp://127.0.0.1:{port}")
    try:
        start = time.monotonic()
        with pytest.raises(SystemExit) as ei:
            cli.main(["scan"])
        assert time.monotonic() - start < 5.0
        msg = str(ei.value)
        assert msg.startswith("probe:")
        assert "silent" in msg.lower()
    finally:
        srv.shutdown()
        srv.server_close()
