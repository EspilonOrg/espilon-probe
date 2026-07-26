"""serial medium: a real UART over a Linux serial device or pty (/dev/ttyUSB0, /dev/pts/N).

This is the migration of the old in-client `backends/serial.py` raw-fd I/O into the generic bridge
(docs/design/00 section 5, docs/design/02 section 3): the client no longer touches the fd; the bridge opens it,
sets raw mode + a best-effort termios baud, and raw-pumps bytes. A pty pair makes it provable with
no hardware. Executor position: a raw byte pump (the purest relay) - it parses nothing; the device
owns all UART semantics.

RX buffering (the load-bearing bit for a persistent bridge): a background thread reads the fd into
a buffer CONTINUOUSLY, independent of any client connection. That is what lets device output that
arrives BETWEEN two discrete per-verb connections (e.g. a command's response emitted after the
write connection closed, before the read connection opens) survive to the next read - the "line
state lives device-side / the persistent session realizes the OS RX buffer" property the corpus
calls for (docs/design/01 section 4). A short-lived auto-spawned bridge that serves one connection then
dies does NOT persist across verbs (its fd closes), exactly like real hardware across port
open/close; the conformance harness therefore runs ONE persistent bridge for a multi-verb tape.

Stdlib only; no third-party dependency.
"""

from __future__ import annotations

import errno
import os
import select
import sys
import threading
import time

# A pty slave whose master has closed reports EOF as b"" and, on Linux, can also surface EIO once
# the master is gone; both mean "the line is dead", not a transient would-block.
_EOF_ERRNOS = (errno.EIO,)
_WOULDBLOCK = (errno.EAGAIN, errno.EWOULDBLOCK)

# Cap on the un-drained RX byte buffer. The background reader appends device output CONTINUOUSLY,
# independent of any client, so a chatty device on a persistent daemon that is never read would grow
# the buffer without bound. At the cap the OLDEST bytes are dropped to admit the newest (a console
# reader wants the most recent output, like a scrollback ring) and a dropped-byte counter is bumped
# so the loss is observable, never silent. 1 MiB is generous for interactive console backlog.
_BUF_MAX = 1024 * 1024


class SerialMedium:
    shape = "stream"

    def __init__(self, endpoint: str, baud: int = 115200, reset_on_open: bool = False):
        self.endpoint = endpoint
        self.baud = baud
        self.reset_on_open = reset_on_open
        self._fd: int | None = None
        self._buf = bytearray()
        self._dropped = 0            # bytes dropped-oldest at the buffer cap (observable in caps/meta)
        self._lock = threading.Lock()
        self._reader: threading.Thread | None = None
        self._closed = threading.Event()

    def open(self) -> None:
        try:
            fd = os.open(self.endpoint, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        except OSError as e:
            raise RuntimeError(f"cannot open serial endpoint {self.endpoint!r}: {e}")
        self._configure(fd)
        self._fd = fd
        self._reader = threading.Thread(target=self._read_loop, name="serial-rx", daemon=True)
        self._reader.start()
        if self.reset_on_open:
            # Reset the board AFTER the RX reader is running so the boot banner is captured. On a
            # board whose banner is only emitted at boot, this is how the real-device conformance
            # run captures it (docs conformance/hardware/uart-console-esp32/README.md).
            self._reset_board(fd)

    def _configure(self, fd: int) -> None:
        """Best-effort raw + baud for a real tty; a pty is not a tty so termios is a harmless
        no-op there (the pilot's pty has no bit clock - baud is cosmetic on it).

        Use TCSANOW, NOT tty.setraw's default TCSAFLUSH: TCSAFLUSH DISCARDS buffered RX when the
        port is configured, so opening the line would drop device output already in the OS/pty
        buffer (verified on a pty: TCSAFLUSH -> empty, TCSANOW -> bytes preserved). A serial line
        must not lose pending RX just because it was opened."""
        try:
            import termios
            import tty
            tty.setraw(fd, termios.TCSANOW)
        except Exception:
            pass
        self._apply_baud(fd, self.baud)

    def _apply_baud(self, fd: int, baud: int) -> None:
        try:
            import termios
            attrs = termios.tcgetattr(fd)
            baud_const = getattr(termios, f"B{baud}", None)
            if baud_const is not None:
                attrs[4] = baud_const   # ispeed
                attrs[5] = baud_const   # ospeed
                termios.tcsetattr(fd, termios.TCSANOW, attrs)
        except Exception:
            pass

    def _reset_board(self, fd: int) -> None:
        """Pulse the classic ESP32 auto-reset (run mode): keep IO0 high (DTR deasserted) and pulse
        EN low->high via RTS, so the board reboots and re-emits its boot banner. Best-effort: on a
        pty (or a wire without an auto-reset circuit) the modem-control lines are a harmless no-op,
        so this is safe to call unconditionally in CI. Mirrors esptool's ClassicReset polarity."""
        try:
            import fcntl
            import struct
            import termios
            dtr = struct.pack("I", termios.TIOCM_DTR)
            rts = struct.pack("I", termios.TIOCM_RTS)
            fcntl.ioctl(fd, termios.TIOCMBIC, dtr)      # DTR off  -> IO0 high (run, not download)
            fcntl.ioctl(fd, termios.TIOCMBIS, rts)      # RTS on   -> EN low  (reset asserted)
            time.sleep(0.1)
            fcntl.ioctl(fd, termios.TIOCMBIC, rts)      # RTS off  -> EN high (released -> boots)
            time.sleep(0.05)
        except Exception:
            pass

    def apply_config(self, config: dict) -> None:
        """Honour client link settings from HELLO.config before serving any verb (docs/design/01
        section 2). Today that is `{"baud": N}`; on a real tty it re-sets termios, on a pty it is
        a no-op."""
        if self._fd is None:
            return
        baud = config.get("baud")
        if isinstance(baud, int) and baud > 0:
            self.baud = baud
            self._apply_baud(self._fd, baud)

    def _read_loop(self) -> None:
        while not self._closed.is_set():
            try:
                ready, _, _ = select.select([self._fd], [], [], 0.05)
            except (OSError, ValueError):
                break
            if not ready:
                continue
            try:
                data = os.read(self._fd, 4096)
            except OSError as e:
                if e.errno in _WOULDBLOCK:
                    continue
                break               # EIO / hard error: the line is gone
            if not data:
                break               # EOF: the far side closed
            self._append(data)

    def _append(self, data: bytes) -> None:
        """Append device RX to the buffer, dropping the OLDEST bytes past the cap and counting the
        loss. Split out from the reader so the drop-oldest bound is unit-testable without a real fd."""
        with self._lock:
            self._buf += data
            overflow = len(self._buf) - _BUF_MAX
            if overflow > 0:
                del self._buf[:overflow]            # drop-oldest: keep the newest _BUF_MAX bytes
                self._dropped += overflow
                print(f"serial-rx: buffer full ({_BUF_MAX} bytes), dropping oldest "
                      f"(dropped={self._dropped})", file=sys.stderr)

    def drain(self) -> bytes:
        """Return and clear all buffered RX (non-blocking)."""
        with self._lock:
            if not self._buf:
                return b""
            data = bytes(self._buf)
            self._buf.clear()
            return data

    def peek(self) -> bytes:
        """Return buffered RX WITHOUT removing it (non-blocking). The pump removes only what it
        actually sends (`consume`), so device output the client did not receive is never cleared."""
        with self._lock:
            return bytes(self._buf)

    def consume(self, n: int) -> None:
        """Drop the first `n` buffered RX bytes (those just sent to a client)."""
        if n <= 0:
            return
        with self._lock:
            del self._buf[:n]

    def write(self, data: bytes) -> None:
        if self._fd is None:
            raise RuntimeError("serial medium not open")
        view = memoryview(data)
        while view:
            try:
                n = os.write(self._fd, view)
            except OSError as e:
                if e.errno in _WOULDBLOCK:
                    select.select([], [self._fd], [], 0.5)
                    continue
                raise
            view = view[n:]

    def caps(self) -> dict:
        with self._lock:
            dropped = self._dropped
        return {"protocol": "uart", "channels": [], "verbs": ["scan", "uart"],
                "shape": "stream", "meta": {"port": self.endpoint, "baud": self.baud,
                                            "rx_dropped": dropped, "rx_buf_max": _BUF_MAX}}

    def scan(self, seconds: float | None = None, count: int | None = None) -> list[dict]:
        # A stream port advertises itself instantly; the listen-window/count hints do not apply.
        return [{"port": self.endpoint, "baud": self.baud}]

    def alive(self) -> bool:
        """False once the RX reader has stopped because the line hit EOF / a hard error (e.g. a
        pty whose master closed). The daemon uses this to retire when the medium goes away."""
        return self._reader is not None and self._reader.is_alive()

    def close(self) -> None:
        self._closed.set()
        if self._reader is not None:
            self._reader.join(timeout=0.5)
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
        self._fd = None
