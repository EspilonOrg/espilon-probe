"""The bridge daemon must reap connections that connect but never make protocol progress.

The single-serving daemon holds ONE connection at a time. A peer that connects and then never sends
a valid HELLO (or completes HELLO then stalls mid-verb) used to wedge the accept loop forever - and
`idle_timeout` could never fire because control never returned to the loop. The framed control reads
now carry a deadline, so a dead/silent connection is reaped and the daemon frees up. An ATTACHED but
idle interactive console is deliberately exempt: it can sit with no bytes for minutes and is ended by
client EOF, not by inactivity. It also clamps an attacker-supplied SNIFF window (Fix 3).
"""

import os
import pty
import socket
import threading
import time
import tty

from espilon_probe.backends.virtual import VirtualBackend
from espilon_probe.bridges.media.serial import SerialMedium
from espilon_probe.bridges.server import BridgeServer
from espilon_probe.core import wire


def _echo_pty():
    """A pty whose master echoes everything written to the slave. Returns (master_fd, slave_path)."""
    master, slave = pty.openpty()
    tty.setraw(master)
    slave_path = os.ttyname(slave)
    os.close(slave)

    def device():
        while True:
            try:
                data = os.read(master, 1024)
            except OSError:
                break
            if not data:
                break
            try:
                os.write(master, data)            # echo
            except OSError:
                break

    threading.Thread(target=device, daemon=True).start()
    return master, slave_path


def _serve(medium, control_timeout=0.5, idle_timeout=None):
    server = BridgeServer(medium, host="127.0.0.1", port=0)
    server._control_timeout = control_timeout
    port = server.bind()
    threading.Thread(target=lambda: server.serve_forever(idle_timeout=idle_timeout),
                     daemon=True).start()
    return server, port


def test_dead_no_hello_connection_is_reaped_then_a_live_client_serves():
    # The core BLOCKER repro (t_nohello/t_wedge): a peer connects and sends 0 bytes, wedging the
    # single-serving daemon. It must be reaped within the control deadline so a concurrent legitimate
    # client is then served.
    master, slave_path = _echo_pty()
    medium = SerialMedium(slave_path)
    medium.open()
    server, port = _serve(medium, control_timeout=0.5)
    dead = socket.create_connection(("127.0.0.1", port))    # sends nothing, holds the socket open
    time.sleep(0.2)                                         # let the daemon accept the dead conn
    try:
        start = time.monotonic()
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            caps = b.capabilities()
        elapsed = time.monotonic() - start
        assert caps.protocol == "uart"                     # the live client got served
        assert elapsed < 5.0                               # after the dead conn was reaped (~0.5s)
    finally:
        dead.close()
        server.close()
        medium.close()
        os.close(master)


def test_idle_timeout_fires_even_after_a_dead_connection():
    # The exact wedge the reviewer flagged: a dead connection must not stop `idle_timeout` from ever
    # firing. Previously the blocking HELLO read never returned, so the daemon never retired.
    master, slave_path = _echo_pty()
    medium = SerialMedium(slave_path)
    medium.open()
    server = BridgeServer(medium, host="127.0.0.1", port=0)
    port = server.bind()
    t = threading.Thread(target=lambda: server.serve_forever(idle_timeout=0.5), daemon=True)
    t.start()
    dead = socket.create_connection(("127.0.0.1", port))    # never sends HELLO
    try:
        time.sleep(3.0)
        assert not t.is_alive(), "daemon wedged on a dead connection / idle_timeout never fired"
    finally:
        dead.close()
        server.close()
        medium.close()
        os.close(master)


def test_packet_client_that_stalls_mid_protocol_is_reaped():
    # A packet client that HELLOs then stalls before its next verb must be reaped, not left holding
    # the daemon. We drive the framed wire directly against a fake packet medium.
    class _FakePacketMedium:
        shape = "packet"

        def apply_config(self, config):
            pass

        def caps(self):
            return {"protocol": "x", "channels": [], "verbs": ["sniff"], "shape": "packet",
                    "pcap_dlt": 147, "meta": {}}

        def scan(self, seconds=None, count=None):
            return []

        def inject(self, frame):
            pass

        def take_frames(self, count, deadline):
            return []

    server = BridgeServer(_FakePacketMedium(), host="127.0.0.1", port=0)
    server._control_timeout = 0.5
    port = server.bind()
    threading.Thread(target=lambda: server.serve_forever(), daemon=True).start()
    s = socket.create_connection(("127.0.0.1", port))
    try:
        r, w = s.makefile("rb"), s.makefile("wb")
        wire.send(w, wire.hello())
        welcome = wire.decode(r)
        assert welcome and welcome.get("t") == wire.WELCOME
        # Now stall: send no further verb. The server must close the connection at the deadline.
        s.settimeout(3.0)
        start = time.monotonic()
        assert s.recv(1) == b""                            # server reaped us and closed
        assert time.monotonic() - start < 2.5
    finally:
        s.close()
        server.close()


def _silent_then_emit_pty(quiet_for, message):
    """A pty whose device stays SILENT for `quiet_for` seconds, then emits `message` once and holds
    the line open. Lets a test prove an attached console survives an idle far longer than the control
    deadline (the device->client read path is the reliable one to observe survival)."""
    master, slave = pty.openpty()
    tty.setraw(master)
    slave_path = os.ttyname(slave)
    os.close(slave)

    def device():
        time.sleep(quiet_for)
        try:
            os.write(master, message)
        except OSError:
            return
        while True:
            try:
                if not os.read(master, 1024):
                    break
            except OSError:
                break

    threading.Thread(target=device, daemon=True).start()
    return master, slave_path


def test_attached_idle_console_is_not_reaped():
    # The exemption: an ATTACHED interactive console can legitimately sit with NO bytes far longer
    # than the control deadline (user reading output, not typing). It must NOT be reaped. The device
    # stays silent past the deadline, then emits; the client still receives it -> not reaped.
    master, slave_path = _silent_then_emit_pty(quiet_for=1.0, message=b"awake-after-idle\r\n")
    medium = SerialMedium(slave_path)
    medium.open()
    server, port = _serve(medium, control_timeout=0.3)
    try:
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            ch = b.stream_open("duplex")                   # attach; then sit idle (send nothing)
            got = ch.drain(2.0)                            # device emits at 1.0s (>> 0.3s deadline)
        assert b"awake-after-idle" in got, "an idle-but-attached console was wrongly reaped"
    finally:
        server.close()
        medium.close()
        os.close(master)


def test_sniff_seconds_is_clamped_server_side():
    # Fix 3: a hostile SNIFF `seconds` (e.g. 1e9) must be clamped to the server ceiling, whatever the
    # wire value, so take_frames cannot be pinned for effectively forever. We assert the deadline the
    # server hands take_frames is bounded by the ceiling.
    from espilon_probe.bridges import server as srv_mod

    seen = {}

    class _Medium:
        shape = "packet"

        def take_frames(self, count, deadline):
            seen["deadline"] = deadline
            return []

    server = BridgeServer(_Medium(), host="127.0.0.1", port=0)

    class _W:
        def write(self, *_):
            pass

        def flush(self):
            pass

    before = time.monotonic()
    server._packet_sniff(_W(), {"t": wire.SNIFF, "seconds": 1e9})
    horizon = seen["deadline"] - before
    assert horizon <= srv_mod._PACKET_SNIFF_MAX + 1.0      # clamped to the ceiling, not ~1e9 seconds
