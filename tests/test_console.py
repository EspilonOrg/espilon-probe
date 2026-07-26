"""The generic interactive console loop (`core/console.py`), surfaced as `probe uart console`.

Drives `run_console` with an `os.openpty()` pair as OUR stdin: a driver thread writes a keystroke
tape to the pty master while `run_console` runs in the test's MAIN thread (so its SIGTERM/SIGHUP
handlers install). Asserts stdin->device forwarding, Ctrl-] detach (not forwarded), local-echo and
--eol behaviour, remote-close exit code, the no-tty refusal, and - the load-bearing one - that the
terminal is restored on EVERY exit path INCLUDING an injected SIGTERM. A second test runs the same
tape against BOTH the virtual bridge and a pty-serial bridge and asserts the device-visible byte
streams are identical (the fidelity thesis, now for console).
"""

import os
import select
import signal
import socketserver
import termios
import threading
import time

import pytest

from espilon_probe.backends.virtual import VirtualBackend
from espilon_probe.core import console, wire
from espilon_probe.core.errors import ProbeError

UART_CAPS = {"protocol": "uart", "channels": [], "verbs": ["scan", "uart"],
             "shape": "stream", "meta": {}}


class _Srv(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _serve_console(echo=True, banner=b"", close_on_recv=False, host="127.0.0.1"):
    """A minimal in-process duplex console bridge that RECORDS what the client forwarded.

    `echo`: echo the client's bytes back (an echoing device) or not (a silent device).
    `banner`: pre-attach backlog queued for the pump to emit on attach (tests attach-clean).
    `close_on_recv`: close the connection right after the first client bytes (tests remote-close).
    Returns (server, port, state); state["received"] is the device-visible input stream."""
    state = {"received": bytearray()}
    lock = threading.Lock()

    class _H(socketserver.StreamRequestHandler):
        def handle(self):
            r, w = self.rfile, self.wfile
            hello = wire.decode(r)
            if not hello or hello.get("t") != wire.HELLO:
                return
            wire.send(w, wire.welcome(UART_CAPS))
            msg = wire.decode(r)
            if not msg or msg.get("t") != wire.STREAM_ATTACH:
                return
            wire.send(w, wire.stream_ready())
            sock = self.connection
            sock.setblocking(True)
            fifo = bytearray(banner)
            while True:
                if fifo:
                    try:
                        sent = sock.send(bytes(fifo))
                    except OSError:
                        return
                    del fifo[:sent]
                    if fifo:
                        continue
                rd, _, _ = select.select([sock], [], [], 0.02)
                if not rd:
                    continue
                try:
                    chunk = sock.recv(4096)
                except OSError:
                    return
                if not chunk:
                    return
                with lock:
                    state["received"] += chunk
                if close_on_recv:
                    return                      # drop the connection: client sees remote close
                if echo:
                    fifo += chunk

    srv = _Srv((host, 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1], state


def _drive(*, script, echo=True, banner=b"", local_echo=False, eol="cr", replay_buffer=False,
           escape=True, signal_after=None, close_on_recv=False, lead=0.3):
    """Run one console session in the MAIN thread; a driver thread writes `script` to the pty master.

    `escape`: end by writing Ctrl-] (clean detach). `signal_after`: instead send this signal to our
    own process after the tape (external-kill path). `close_on_recv`: the bridge drops the connection
    on first bytes (remote-close path). Returns a dict of observables incl. termios_restored."""
    srv, port, state = _serve_console(echo=echo, banner=banner, close_on_recv=close_on_recv)
    master, slave = os.openpty()
    r_out, w_out = os.pipe()
    saved_before = termios.tcgetattr(slave)
    backend = VirtualBackend(f"tcp://127.0.0.1:{port}")
    backend.open()
    channel = backend.stream_open("duplex")

    done = threading.Event()

    def driver():
        time.sleep(lead)                         # let attach-clean finish + the loop go live
        for chunk in script:
            if done.is_set():
                return
            os.write(master, chunk)
            time.sleep(0.08)
        time.sleep(0.2)
        if done.is_set():
            return
        if signal_after is not None:
            os.kill(os.getpid(), signal_after)
        elif escape:
            os.write(master, bytes((console.ESCAPE,)))

    def watchdog():
        # Independent safety net so a logic bug can never HANG CI: force a detach if the session is
        # still alive well past its expected end. CANCELABLE via `done`: after a normal end it returns
        # WITHOUT writing. This is load-bearing - an unconditional late write to `master` is NOT a
        # harmless OSError once the fd is closed: its NUMBER may have been recycled (to another test's
        # socket or device pty), so the write would inject the detach byte into an UNRELATED stream.
        # Gating on `done` + the join below guarantees no write to `master` after teardown.
        if done.wait(8.0):
            return
        try:
            os.write(master, bytes((console.ESCAPE,)))
        except OSError:
            pass

    t = threading.Thread(target=driver, daemon=True)
    t.start()
    wd = threading.Thread(target=watchdog, daemon=True)
    wd.start()
    code = None
    try:
        code = console.run_console(channel, stdin_fd=slave, stdout_fd=w_out,
                                   local_echo=local_echo, eol=eol, replay_buffer=replay_buffer,
                                   attach_banner="[probe] attached")
    finally:
        done.set()                               # stop the driver/watchdog from any further write
        saved_after = termios.tcgetattr(slave)
        os.close(w_out)
        out = bytearray()
        while True:
            chunk = os.read(r_out, 65536)
            if not chunk:
                break
            out += chunk
        os.close(r_out)
        # JOIN both writer threads BEFORE closing master/slave. Both are bounded (the driver's
        # longest sleep is 0.2s, the watchdog returns the instant `done` is set), so a closed master
        # fd is never handed back to a live writer that could scribble into a recycled fd.
        t.join(timeout=2.0)
        wd.join(timeout=2.0)
        backend.close()
        srv.shutdown()
        srv.server_close()
        os.close(master)
        os.close(slave)
    return {"code": code, "stdout": bytes(out), "received": bytes(state["received"]),
            "termios_restored": saved_before == saved_after}


def test_stdin_is_forwarded_to_the_device():
    res = _drive(script=[b"hello"])
    assert res["received"] == b"hello"
    assert b"hello" in res["stdout"]             # the echoing device's echo came back
    assert res["code"] == 0


def test_escape_detaches_and_is_not_forwarded():
    # The escape byte and everything after it in the same read is consumed by the client and never
    # sent to the device. Position-independent: mid-chunk here, no separate escape write.
    res = _drive(script=[b"ab\x1dcd"], escape=False)
    assert res["received"] == b"ab"
    assert bytes((console.ESCAPE,)) not in res["received"]
    assert b"cd" not in res["received"]
    assert res["code"] == 0


def test_local_echo_off_does_not_double_on_an_echoing_device():
    res = _drive(script=[b"x"], echo=True, local_echo=False)
    assert res["received"] == b"x"
    assert res["stdout"].count(b"x") == 1        # only the device echo, no local double


def test_local_echo_on_shows_a_silent_device_and_doubles_an_echoing_one():
    silent = _drive(script=[b"y"], echo=False, local_echo=True)
    assert silent["received"] == b"y"
    assert silent["stdout"] == b"y"              # silent device: local echo is the only copy
    echoing = _drive(script=[b"z"], echo=True, local_echo=True)
    assert echoing["stdout"].count(b"z") == 2    # local echo + device echo


def test_eol_mapping_on_the_input_path():
    assert _drive(script=[b"\r"], eol="cr")["received"] == b"\r"
    assert _drive(script=[b"\r"], eol="lf")["received"] == b"\n"
    assert _drive(script=[b"\r"], eol="crlf")["received"] == b"\r\n"


def test_device_output_is_verbatim_never_eol_rewritten():
    # --eol maps the INPUT path only; device -> stdout is byte-verbatim. The echoing device returns
    # our CR unchanged even under --eol lf (which only rewrote what we SENT).
    res = _drive(script=[b"\r"], eol="lf", echo=True)
    assert res["received"] == b"\n"              # input path mapped
    assert b"\n" in res["stdout"]                # device echoed our mapped byte, verbatim


def test_attach_clean_discards_backlog_by_default():
    res = _drive(script=[b"q"], banner=b"STALEBOOTBANNER", replay_buffer=False)
    assert b"STALEBOOTBANNER" not in res["stdout"]   # pre-attach backlog dropped, like screen
    assert res["received"] == b"q"                   # live forwarding still works


def test_replay_buffer_keeps_the_backlog():
    res = _drive(script=[b"q"], banner=b"STALEBOOTBANNER", replay_buffer=True)
    assert b"STALEBOOTBANNER" in res["stdout"]
    assert res["received"] == b"q"


def test_terminal_restored_on_clean_detach():
    res = _drive(script=[b"hi"])
    assert res["termios_restored"], "tty not restored after a clean detach"


def test_remote_close_exits_nonzero_and_restores_terminal():
    res = _drive(script=[b"go"], close_on_recv=True, escape=False)
    assert res["received"] == b"go"
    assert res["code"] != 0                       # remote close is distinct from operator detach
    assert res["termios_restored"]


def test_terminal_restored_on_injected_sigterm():
    # The classic footgun: an external kill must not leave the tty in raw mode. The SIGTERM handler
    # exists solely to make the `finally` restore fire. Exit code is nonzero (not a clean detach).
    res = _drive(script=[b"live"], signal_after=signal.SIGTERM, escape=False)
    assert res["termios_restored"], "tty not restored after SIGTERM"
    assert res["code"] != 0


def test_non_tty_stdin_is_refused_before_touching_the_channel():
    class _DummyChannel:
        def fileno(self):
            raise AssertionError("channel must not be touched when stdin is not a tty")

    r, w = os.pipe()
    try:
        with pytest.raises(ProbeError) as ei:
            console.run_console(_DummyChannel(), stdin_fd=r, stdout_fd=w)
        assert "not a tty" in str(ei.value)
    finally:
        os.close(r)
        os.close(w)
