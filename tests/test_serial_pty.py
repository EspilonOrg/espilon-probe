"""The SHIPPED `probe --backend serial --target <pty>` path over a pty pair (no hardware).

`probe --backend serial --target /dev/pts/N` discovers/spawns a PERSISTENT serial-bridge daemon on a
loopback port and connects over the wire tunnel (docs/00 decision 5, docs/02 sections 3-4). A pty is
a real serial line from the OS point of view, so a device on the master end is driven by the SAME
`uart read`/`uart write` stream verbs that drive the virtual bridge.

The daemon persists across `probe` invocations keyed by target, which is what makes a `uart write`
then a SEPARATE-process `uart read` preserve the device's async output. The `probe_runtime` fixture
isolates the daemon rendezvous and reaps it on teardown.
"""

import glob
import os
import pty
import select
import threading
import time

from espilon_probe.backends.serial import SerialBackend
from espilon_probe.protocols import uart

SECRET = "SECRET-serial-pty-token"


def _count_daemons_for(endpoint: str) -> int:
    """Count running probe-bridge daemons whose --endpoint is `endpoint` (via /proc, Linux)."""
    n = 0
    for cmdline_path in glob.glob("/proc/[0-9]*/cmdline"):
        try:
            with open(cmdline_path, "rb") as fh:
                parts = fh.read().split(b"\0")
        except OSError:
            continue
        if any(b"espilon_probe.bridges" in p for p in parts) and endpoint.encode() in parts:
            n += 1
    return n


def _read_master(master_fd, want, timeout=2.0):
    deadline = time.monotonic() + timeout
    buf = b""
    while time.monotonic() < deadline and want not in buf:
        ready, _, _ = select.select([master_fd], [], [], 0.1)
        if not ready:
            continue
        try:
            data = os.read(master_fd, 1024)
        except OSError:
            break
        if not data:
            break
        buf += data
    return buf


def test_serial_loopback_write_reaches_the_line(probe_runtime):
    # `uart write` over the daemon must land the exact bytes on the real line.
    master, slave = pty.openpty()
    slave_path = os.ttyname(slave)
    os.close(slave)                       # the daemon opens its own fd on the path

    b = SerialBackend(slave_path)
    b.open()                              # spawns/holds the daemon; the master now has a peer
    try:
        n = uart.write(b, b"printenv\r\n")
        assert n == 10
        got = _read_master(master, b"printenv\r\n")
    finally:
        b.close()
        os.close(master)                  # EOF -> the daemon retires
    assert b"printenv\r\n" in got


def test_serial_loopback_read_gets_line_output(probe_runtime):
    # `uart read` over the daemon must return what the device transmits. The device emits AFTER
    # open() (the daemon holds the slave open by then), so the bytes are captured.
    master, slave = pty.openpty()
    slave_path = os.ttyname(slave)
    os.close(slave)

    b = SerialBackend(slave_path)
    b.open()
    try:
        os.write(master, b"login: " + SECRET.encode() + b"\r\n")
        got = uart.read(b, 2.0)
    finally:
        b.close()
        os.close(master)
    assert SECRET.encode() in got


def _pong_device(master, stop):
    buf = b""
    while not stop.is_set():
        ready, _, _ = select.select([master], [], [], 0.05)
        if not ready:
            continue
        try:
            data = os.read(master, 1024)
        except OSError:
            break
        if not data:
            break
        os.write(master, data)            # echo
        buf += data
        while b"\n" in buf:
            line, _, buf = buf.partition(b"\n")
            if line.strip() == b"ping":
                os.write(master, b"pong\r\n")


def test_serial_daemon_persists_across_separate_connections(probe_runtime):
    # The crux the coordinator flagged: two DISCRETE probe-style connections (write then read, each a
    # separate open/close) against the same target preserve the device's async output because the
    # daemon (and its RX FIFO) persists - it is NOT torn down on close.
    master, slave = pty.openpty()
    slave_path = os.ttyname(slave)
    os.close(slave)
    stop = threading.Event()
    dev = threading.Thread(target=_pong_device, args=(master, stop), daemon=True)
    try:
        # connection 1: write (spawns the daemon, holds the slave open)
        b1 = SerialBackend(slave_path)
        b1.open()
        dev.start()
        assert uart.write(b1, b"ping\r\n") == 6
        b1.close()                        # daemon persists (not killed on close)
        time.sleep(0.2)                   # let the device echo + pong land in the daemon FIFO
        # connection 2: a SEPARATE backend/connection reads the persisted echo + response
        b2 = SerialBackend(slave_path)
        b2.open()
        got = uart.read(b2, 2.0)
        b2.close()
    finally:
        stop.set()
        os.close(master)
    assert b"ping\r\npong\r\n" in got


def test_poll_between_write_and_read_does_not_lose_response(probe_runtime):
    # Finding 5 over the REAL shipped path: read -t1; write printenv; read -t0; read -t2 must not
    # LOSE the printenv response. A `-t 0` poll is non-destructive: whatever it did not receive stays
    # buffered, so the response appears in the poll OR the later read - never destroyed.
    master, slave = pty.openpty()
    slave_path = os.ttyname(slave)
    os.close(slave)
    stop = threading.Event()

    def device(master, stop):
        os.write(master, b"boot> ")
        buf = b""
        while not stop.is_set():
            ready, _, _ = select.select([master], [], [], 0.05)
            if not ready:
                continue
            try:
                data = os.read(master, 1024)
            except OSError:
                break
            if not data:
                break
            os.write(master, data)        # echo
            buf += data
            while b"\n" in buf:
                line, _, buf = buf.partition(b"\n")
                if line.strip() == b"printenv":
                    os.write(master, b"bootcmd=run distro_bootcmd\r\nboot> ")

    dev = threading.Thread(target=device, args=(master, stop), daemon=True)
    try:
        b0 = SerialBackend(slave_path); b0.open(); dev.start()
        b0.stream_read(1.0)                       # drain the banner
        b0.close()
        bw = SerialBackend(slave_path); bw.open(); bw.stream_write(b"printenv\r\n"); bw.close()
        bp = SerialBackend(slave_path); bp.open(); polled = bp.stream_read(0); bp.close()
        time.sleep(0.1)
        br = SerialBackend(slave_path); br.open(); later = br.stream_read(2.0); br.close()
    finally:
        stop.set()
        os.close(master)
    # the response must survive the poll: present in the poll or the later read, never lost
    assert b"bootcmd=run distro_bootcmd" in (polled + later)


def test_concurrent_first_touches_spawn_exactly_one_daemon(probe_runtime):
    # MAJOR regression: many concurrent FIRST-touches on a fresh target must converge on ONE daemon.
    # Two daemons would each open the line and steal RX from each other (real data loss). The fix:
    # a large listen backlog (so reachability probes never spuriously fail under fan-out) + trusting
    # the registered PID (a transient probe blip is not "no daemon").
    import concurrent.futures

    master, slave = pty.openpty()
    slave_path = os.ttyname(slave)
    os.close(slave)

    def touch(_):
        b = SerialBackend(slave_path)
        b.open()
        try:
            return b.capabilities().protocol
        finally:
            b.close()

    n = 12
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
            protocols = list(ex.map(touch, range(n)))
        assert protocols == ["uart"] * n           # every first-touch got a working daemon
        assert _count_daemons_for(slave_path) == 1  # ... and there is exactly ONE daemon
        infos = glob.glob(str(probe_runtime / "espilon-probe" / "*.json"))
        assert len(infos) == 1
    finally:
        os.close(master)
