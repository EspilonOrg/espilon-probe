"""Generic interactive console loop over a StreamChannel - screen/picocom-grade, stdlib only.

This is pure stream plumbing: a `select` over our stdin fd and a channel fd, forwarding our
keystrokes to the device and the device's bytes back to stdout. It holds NO UART / baud / device
knowledge, so any `shape == "stream"` protocol reuses it by wiring a CLI verb to `run_console`
(surfaced today as `probe uart console`). Stdlib only: termios, tty, select, os, signal, sys.

The load-bearing correctness points (docs/design/uart-console.md sections 3-4):
  - full `tty.setraw` on OUR stdin, so Ctrl-C (0x03) / Ctrl-D (0x04) / Ctrl-\\ reach the DEVICE as
    bytes, not local signals; detach is ONLY Ctrl-] (0x1d), a single keystroke never forwarded;
  - device output is written to stdout VERBATIM (a raw pipe; we never rewrite what the device
    emits). The only permitted input rewrite is `--eol` (Enter mapping), on the INPUT path only;
  - the terminal is restored (TCSADRAIN) in a `finally` on EVERY exit path, and SIGTERM/SIGHUP
    handlers exist solely to make that `finally` fire on an external kill (the classic footgun is a
    killed console leaving the operator's tty in raw mode). SIGWINCH is ignored;
  - on attach the pre-attach backlog is discarded client-side (consume take_backlog() then recv to
    one idle gap, drop), so a live line does not replay history - exactly like screen/picocom;
    `--replay-buffer` keeps it. This needs NO wire change.
"""

from __future__ import annotations

import os
import select
import signal
import sys

from .backend import UART_READ_IDLE_GAP
from .errors import ProbeError

# Ctrl-] (GS): the single detach keystroke. Telnet convention, position-independent, and a byte
# effectively never sent to a UART device on purpose. Deliberately NOT screen/picocom's Ctrl-A,
# which is beginning-of-line in every readline shell you would want to drive on the target.
ESCAPE = 0x1d

NO_TTY_MESSAGE = (
    "uart console needs an interactive terminal (stdin is not a tty).\n"
    "       Use 'probe uart send' for scripted send-then-read, or "
    "'probe uart write' / 'uart read'.")


class _ConsoleInterrupt(Exception):
    """Raised by the SIGTERM/SIGHUP handler so the loop unwinds through the `finally` that restores
    the terminal. Its only job is to make that restore fire on an external kill."""


def _map_eol(data: bytes, eol: str) -> bytes:
    """Map Enter (CR, 0x0d) on the INPUT path only. `cr` (default) is verbatim pass-through; in raw
    mode the tty already delivers Enter as CR, so the default forwards stdin unchanged."""
    if eol == "lf":
        return data.replace(b"\r", b"\n")
    if eol == "crlf":
        return data.replace(b"\r", b"\r\n")
    return data


def _write_all(fd: int, data: bytes) -> None:
    """Write every byte to a raw fd (os.write may accept a short count). Unbuffered, so a redirected
    `probe uart console > capture.log` gets the exact device bytes and nothing else."""
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]


def _attach_clean(channel, stdout_fd: int, replay_buffer: bool) -> None:
    """Discard (or, with --replay-buffer, print) the pre-attach backlog, then go live.

    The bridge emits its whole accumulated RX (the virtual boot banner, a real daemon's buffered
    device output) as one burst at pump start. Consume take_backlog() - those bytes are invisible to
    select() - then non-blocking-recv until one idle gap of quiet, dropping everything. This mirrors
    screen/picocom (attaching to a live line does not replay history) and is faithful to hardware: a
    device's boot banner arrives only AFTER a reset, i.e. after attach, so a post-attach banner is
    preserved. An EOF here means the line closed during attach; the main loop observes it next."""
    captured = bytearray(channel.take_backlog())
    while True:
        try:
            ready, _, _ = select.select([channel.fileno()], [], [], UART_READ_IDLE_GAP)
        except (OSError, ValueError):
            break
        if not ready:
            break
        chunk = channel.recv()
        if not chunk:
            break                       # remote close during attach-clean; observed by the loop
        captured += chunk
    if replay_buffer and captured:
        _write_all(stdout_fd, bytes(captured))


def _pump(channel, stdin_fd: int, stdout_fd: int, local_echo: bool, eol: str) -> str:
    """The live select loop. Returns "detach" (Ctrl-] or stdin EOF) or "remote" (channel EOF)."""
    chan_fd = channel.fileno()
    while True:
        try:
            ready, _, _ = select.select([stdin_fd, chan_fd], [], [])
        except InterruptedError:
            continue                    # a benign signal (e.g. ignored SIGWINCH) woke select
        for fd in ready:
            if fd == stdin_fd:
                data = os.read(stdin_fd, 65536)
                if data == b"":
                    return "detach"     # stdin EOF (controlling terminal vanished): clean detach
                idx = data.find(ESCAPE)
                if idx != -1:
                    # Forward everything BEFORE the escape, then detach: the escape byte and every
                    # byte after it in this read is consumed by the client and never sent.
                    _forward(channel, data[:idx], stdout_fd, local_echo, eol)
                    return "detach"
                _forward(channel, data, stdout_fd, local_echo, eol)
            elif fd == chan_fd:
                data = channel.recv()
                if data == b"":
                    return "remote"     # bridge / medium hit EOF: remote close
                _write_all(stdout_fd, data)     # device output is written VERBATIM


def _forward(channel, payload: bytes, stdout_fd: int, local_echo: bool, eol: str) -> None:
    mapped = _map_eol(payload, eol)
    if not mapped:
        return
    channel.send(mapped)
    if local_echo:
        # Opt-in echo for a genuinely silent device: write the EXACT bytes we forward. On an
        # echoing device this doubles - the operator's explicit choice, documented as such.
        _write_all(stdout_fd, mapped)


def run_console(channel, *, stdin_fd: int = 0, stdout_fd: int = 1, stderr=None,
                local_echo: bool = False, eol: str = "cr", replay_buffer: bool = False,
                attach_banner: str | None = None) -> int:
    """Run the interactive console on `channel` until detach / remote close / external kill.

    Returns 0 on an operator-initiated detach (Ctrl-]) or stdin EOF, and nonzero on a remote close
    or an external SIGTERM/SIGHUP (both distinct from a clean detach). Refuses a non-tty stdin up
    front (clean error, no silent line-buffered fallback). The terminal is restored on EVERY path.
    """
    if stderr is None:
        stderr = sys.stderr
    # Refuse a non-tty stdin BEFORE touching termios or the channel: console is definitionally
    # interactive (it raw-ifies the tty and its only detach is a keystroke). The scripted path is
    # `uart send`. No silent degrade to a second, subtly different line-buffered code path.
    if not os.isatty(stdin_fd):
        raise ProbeError(NO_TTY_MESSAGE)

    import termios
    import tty

    saved = termios.tcgetattr(stdin_fd)
    prev_handlers: dict = {}
    outcome = "detach"

    def _on_signal(signum, frame):
        raise _ConsoleInterrupt()

    try:
        # Handlers whose ONLY job is to make the `finally` restore fire on an external kill. Guarded
        # so running off the main thread (tests) does not crash on signal.signal's ValueError.
        for name in ("SIGTERM", "SIGHUP"):
            sig = getattr(signal, name, None)
            if sig is None:
                continue
            try:
                prev_handlers[sig] = signal.signal(sig, _on_signal)
            except (ValueError, OSError):
                pass
        winch = getattr(signal, "SIGWINCH", None)
        if winch is not None:
            try:
                prev_handlers[winch] = signal.signal(winch, signal.SIG_IGN)
            except (ValueError, OSError):
                pass

        # Full raw (not cbreak): a device console needs Ctrl-C/Ctrl-\\ delivered as bytes, and the
        # CR/LF input maps off, exactly like screen/picocom.
        tty.setraw(stdin_fd)
        _attach_clean(channel, stdout_fd, replay_buffer)
        if attach_banner:
            print(attach_banner, file=stderr, flush=True)
        outcome = _pump(channel, stdin_fd, stdout_fd, local_echo, eol)
    except _ConsoleInterrupt:
        outcome = "signal"
    finally:
        # Restore the terminal on EVERY exit path (the classic footgun is a killed console leaving
        # the tty in raw mode). TCSADRAIN so queued output flushes first.
        try:
            termios.tcsetattr(stdin_fd, termios.TCSADRAIN, saved)
        except (termios.error, OSError):
            pass
        for sig, handler in prev_handlers.items():
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError):
                pass
        if outcome == "remote":
            print("[probe] connection closed", file=stderr, flush=True)
        else:
            print("[probe] detached", file=stderr, flush=True)

    return 0 if outcome == "detach" else 1
