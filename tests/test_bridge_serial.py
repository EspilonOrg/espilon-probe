"""The generic serial bridge medium over a pty (docs/02 sections 1-4).

Exercises the bridge server + serial medium directly (in-process), independent of the loopback
launcher: the framed handshake and truthful capabilities, the STREAM_ATTACH/READY raw upgrade, the
half-duplex pump, and the persistent RX buffer that captures device output between connections.
"""

import os
import pty
import threading
import time

from espilon_probe.backends.virtual import VirtualBackend
from espilon_probe.bridges.media.serial import SerialMedium
from espilon_probe.bridges.server import BridgeServer


def _serve(medium):
    server = BridgeServer(medium, host="127.0.0.1", port=0)
    port = server.bind()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, port


def _pty_with_device(banner=b"", on_line=None):
    """A pty whose master runs a tiny device (banner at boot, echo, optional per-line handler).
    Returns (master_fd, slave_path, start_device)."""
    master, slave = pty.openpty()
    import tty
    tty.setraw(master)
    slave_path = os.ttyname(slave)
    os.close(slave)

    def device():
        if banner:
            os.write(master, banner)
        buf = b""
        while True:
            try:
                data = os.read(master, 1024)
            except OSError:
                break
            if not data:
                break
            os.write(master, data)                 # echo
            buf += data
            while b"\n" in buf:
                line, _, buf = buf.partition(b"\n")
                if on_line:
                    out = on_line(line.strip())
                    if out:
                        os.write(master, out)

    return master, slave_path, device


def test_bridge_advertises_truthful_stream_caps():
    medium = SerialMedium("/dev/null")           # caps do not require a real open
    caps = medium.caps()
    assert caps["protocol"] == "uart"
    assert caps["shape"] == "stream"
    assert "uart" in caps["verbs"]


def test_spawn_daemon_surfaces_child_stderr_reason(monkeypatch, tmp_path):
    # A child daemon that dies before announcing (a missing [ftdi] extra, an unimplemented medium)
    # prints its actionable reason to stderr. The launcher must capture that line and surface it, so
    # the operator sees the FIX and not just "exited before announcing (code 1)". NEGATIVE test for
    # the discarded-hint fix: without capturing stderr, the raised error omits the reason.
    from espilon_probe.backends import serial as serialbk

    reason = ("probe-bridge: the ftdi SPI medium needs the optional [ftdi] extra: "
              "pip install 'espilon-probe[ftdi]'")

    class _FakePopen:
        def __init__(self, cmd, stdout=None, stderr=None, stdin=None,
                     start_new_session=None, env=None):
            stderr.write((reason + "\n").encode())     # the child's real failure line
            stderr.flush()
            self.returncode = 1                        # died before announcing

        def poll(self):
            return self.returncode

        def terminate(self):
            pass

    monkeypatch.setattr(serialbk.subprocess, "Popen", _FakePopen)
    info_path = str(tmp_path / "rendezvous.json")
    try:
        serialbk._spawn_daemon("ftdi-spi", "ftdi://ftdi:232h/1", 115200, info_path)
        raise AssertionError("spawn should have failed for a child that exited before announcing")
    except RuntimeError as e:
        assert "exited before announcing" in str(e)
        assert reason in str(e)                        # the actionable line reached the operator


def test_rx_buffer_is_bounded_and_counts_drops(monkeypatch):
    # The background reader appends device output independent of any client; a chatty device on an
    # un-drained daemon must NOT grow the buffer without bound. Drop-OLDEST keeps the newest cap bytes
    # (like a scrollback ring) and bumps an observable counter surfaced in caps meta.
    from espilon_probe.bridges.media import serial as ser
    monkeypatch.setattr(ser, "_BUF_MAX", 8)
    m = ser.SerialMedium("/dev/null")
    m._append(b"ABCD")
    m._append(b"EFGHIJKL")                        # total 12 -> 4 oldest dropped, newest 8 kept
    assert bytes(m._buf) == b"EFGHIJKL"           # bounded at the cap, newest retained
    assert m._dropped == 4                        # the 4 oldest were dropped and counted
    assert m.caps()["meta"]["rx_dropped"] == 4    # and the loss is observable to a client


def test_bridge_handshake_reports_uart_stream_over_pty():
    master, slave_path, device = _pty_with_device()
    medium = SerialMedium(slave_path)
    medium.open()
    server, port = _serve(medium)
    try:
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            caps = b.capabilities()
            assert caps.protocol == "uart"
            assert caps.shape == "stream"
    finally:
        server.close()
        medium.close()
        os.close(master)


def test_bridge_stream_roundtrip_and_cross_connection_persistence():
    # A persistent bridge holds the pty slave open, so a response emitted after the write
    # connection closed survives to the next read connection (docs/01 section 4).
    def on_line(cmd):
        return b"pong\r\n" if cmd == b"ping" else None

    master, slave_path, device = _pty_with_device(banner=b"BOOT\r\n", on_line=on_line)
    medium = SerialMedium(slave_path)
    medium.open()
    server, port = _serve(medium)
    threading.Thread(target=device, daemon=True).start()
    time.sleep(0.1)                              # let the banner land in the RX buffer
    target = f"tcp://127.0.0.1:{port}"
    try:
        with VirtualBackend(target) as b:        # read connection 1
            assert b.stream_read(1.0) == b"BOOT\r\n"
        with VirtualBackend(target) as b:        # write connection
            assert b.stream_write(b"ping\r\n") == 6
        time.sleep(0.1)
        with VirtualBackend(target) as b:        # read connection 2: echo + response persisted
            assert b.stream_read(1.0) == b"ping\r\npong\r\n"
    finally:
        server.close()
        medium.close()
        os.close(master)
