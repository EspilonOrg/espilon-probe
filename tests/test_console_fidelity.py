"""Console fidelity: the SAME keystroke tape, driven through `probe uart console`, produces a
byte-identical DEVICE-VISIBLE input stream against the virtual bridge AND a pty-serial bridge.

This is the fidelity thesis (docs/04), now for the interactive console: the client forwards our
keystrokes identically regardless of which termination is on the far end, so a course/solver that
learns the console on the virtual backend behaves the same on real silicon. We record what the
device actually received (a RecordingConsole on both terminations) and assert the two are equal.
"""

import os
import threading
import time

from conformance.console import Console
from conformance.pty_adapter import ConformanceRealSide
from conformance.virtual_bridge import VirtualConsoleBridge

from espilon_probe.cli import _make_backend
from espilon_probe.core import console


class RecordingConsole(Console):
    """A Console that also records every input byte it is fed - the device-visible input stream."""

    def __init__(self):
        super().__init__()
        self.received = bytearray()

    def feed(self, data: bytes) -> bytes:
        self.received += data
        return super().feed(data)


def _console_against(backend_name: str, target: str, script) -> int:
    """Drive one `uart console` session (run_console in the MAIN thread) against a bridge.

    The keystroke `driver` and the hang `watchdog` both write to `master`; they are gated on a
    `finished` Event and JOINED before `master` is closed. This is load-bearing for the harness'
    own soundness: a thread that wrote to `master` AFTER the finally closed it would land on a
    REUSED fd (the next session's pty master or the bridge socket) and inject a stray ESCAPE into
    an unrelated device-visible stream. All sleeps are `finished.wait(...)` so setting the Event
    wakes both threads at once, and the watchdog only fires the failsafe ESCAPE on a genuine hang.
    """
    backend = _make_backend(backend_name, target)
    backend.open()
    channel = backend.stream_open("duplex")
    master, slave = os.openpty()
    r_out, w_out = os.pipe()
    finished = threading.Event()

    def driver():
        if finished.wait(0.5):                   # daemon banner buffered + attach-clean finishes
            return
        for chunk in script:
            if finished.is_set():
                return
            os.write(master, chunk)
            if finished.wait(0.1):
                return
        if finished.wait(0.3):
            return
        os.write(master, bytes((console.ESCAPE,)))

    def watchdog():
        if finished.wait(10.0):
            return                               # clean detach happened: never touch the fd
        try:
            os.write(master, bytes((console.ESCAPE,)))
        except OSError:
            pass

    t = threading.Thread(target=driver, daemon=True)
    w = threading.Thread(target=watchdog, daemon=True)
    t.start()
    w.start()
    try:
        code = console.run_console(channel, stdin_fd=slave, stdout_fd=w_out,
                                   attach_banner="[probe] attached")
    finally:
        finished.set()                           # wake both writers so the joins return at once
        t.join(timeout=2.0)
        w.join(timeout=2.0)
        os.close(w_out)
        while os.read(r_out, 65536):             # drain so the console's writer never blocks
            pass
        os.close(r_out)
        backend.close()
        os.close(master)                         # safe: no writer thread is alive past the joins
        os.close(slave)
    return code


def test_console_same_tape_virtual_and_pty_serial_device_visible_identical():
    # Bare CR is the REAL Enter (probe's default --eol cr is pass-through), and the pilot Console
    # dispatches on CR - so this is exactly what a `screen`/picocom user types. The device must see
    # byte-identical input on both terminations.
    script = [b"help\r", b"printenv\r", b"echo hi-console\r"]

    v_console = RecordingConsole()
    with VirtualConsoleBridge(v_console) as vb:
        _console_against(vb.backend, vb.target, script)

    r_console = RecordingConsole()
    with ConformanceRealSide(r_console) as rb:
        _console_against(rb.backend, rb.target, script)

    assert bytes(v_console.received) == bytes(r_console.received), (
        f"device-visible streams differ:\n  virtual={bytes(v_console.received)!r}\n"
        f"  serial ={bytes(r_console.received)!r}")
    # And the tape actually reached the device (not a both-empty false pass).
    assert b"echo hi-console\r" in bytes(v_console.received)
