"""A minimal UART Console reference model for the pilot harness.

This is the SAME model bound two ways: served over the TCP stream by the virtual bridge, and bound
onto a pty master by the real-side adapter. Because both terminations run identical code, any byte
difference the harness observes is a TRANSPORT difference, which is exactly what the conformance
diff is there to catch.

Deliberately minimal (docs/protocols/uart.md): a boot banner, a prompt, a few stateless commands,
per-byte echo, and a real CR-terminated line discipline (Enter is CR, 0x0d - what a terminal and
probe's default `--eol cr` send; see `feed`). The full kit `Console` reference model (author-declared handlers, the `garble`
baud model, `emit`/`payload` flag staging, `assert_clean` idle-surface audit) and the
`uart-bootloader` device.py rewrite are a SEPARATE follow-up; this model carries NO flag and NO
challenge content, only enough behaviour to drive the harness.

Model contract (delivery-agnostic on purpose - the persistence lives in the bridge, docs/design/01
section 4): `banner()` is emitted once at device boot; `feed(data)` processes input and RETURNS the
output bytes it produces (echo, then any command response + prompt), in order. It holds no delivery
FIFO of its own, so it composes with either a virtual-bridge FIFO or a pty's RX buffer.
"""

from __future__ import annotations

BANNER = b"=== espilon uart console (pilot) ===\r\n"
PROMPT = b"boot> "
EOL = b"\r\n"

# Line-buffer cap, byte-for-byte with the firmware's LINE_MAX (uart_console.c). A line longer than
# this drops the OVERFLOW bytes from the buffer (echo still happens for every byte), so a >LINE_MAX
# line dispatches only its first LINE_MAX bytes - exactly what the C does. Without this the virtual
# model would buffer unbounded and diverge from real silicon on a pathological long line while the
# harness stayed green. The conformance tape lines are short, so this is never hit in the pilot tape.
LINE_MAX = 2048


class Console:
    def __init__(self, echo: bool = True):
        self.echo = echo
        self._line = bytearray()      # partial-line buffer across feeds (a real UART FIFO)
        self._prev_term = b""         # the terminator just dispatched (b"\r"/b"\n"), for CRLF collapse

    def banner(self) -> bytes:
        """The bytes a real peripheral emits at power-on: banner then the first prompt."""
        return BANNER + PROMPT

    def feed(self, data: bytes) -> bytes:
        """Consume input bytes; return the output bytes to transmit back, in order.

        This is a REAL U-Boot/`boot>`-style console: Enter is CR (0x0d), the byte a terminal
        (screen/picocom) and probe's default `--eol cr` actually send. So the line terminator is
        CR, NOT LF. Behaviour per byte:

        - CR (0x0d): dispatch the accumulated line, then reset the buffer.
        - LF (0x0a): also dispatches (bare-LF tolerance, so LF-only clients still work).
        - The SECOND half of a CRLF/LFCR pair - a terminator of the OTHER kind immediately after
          one that just dispatched - is SWALLOWED, so a two-byte Enter dispatches exactly once and
          never emits a spurious empty line.
        - A dispatching terminator emits `\\r\\n` (a real console moves to a fresh line) in place of
          echoing the raw terminator byte; the response and prompt follow. Non-terminator bytes are
          echoed verbatim (when `echo`) and buffered. CR/LF never enter the buffer, so the dispatched
          command bytes are clean (no stray CR/LF)."""
        out = bytearray()
        for byte in data:
            b = bytes((byte,))
            if b == b"\r" or b == b"\n":
                if self._prev_term and b != self._prev_term:
                    self._prev_term = b""     # pair consumed; the next terminator dispatches
                    continue
                line = bytes(self._line)
                self._line.clear()
                if self.echo:
                    out += EOL                # Enter -> fresh line, in place of the raw terminator
                out += self._dispatch(line)
                self._prev_term = b
            else:
                if self.echo:
                    out += b                  # echo every byte, even past the cap (matches firmware)
                if len(self._line) < LINE_MAX:
                    self._line += b           # but only buffer up to LINE_MAX; overflow is dropped
                self._prev_term = b""
        return bytes(out)

    def _dispatch(self, line: bytes) -> bytes:
        cmd, _, arg = line.partition(b" ")
        cmd = cmd.strip()
        if cmd == b"":
            return PROMPT
        if cmd == b"help":
            body = b"commands: help printenv echo <text>\r\n"
        elif cmd == b"printenv":
            body = b"bootcmd=run distro_bootcmd\r\nbaudrate=115200\r\nver=pilot-1\r\n"
        elif cmd == b"echo":
            body = arg + EOL
        else:
            body = b"unknown command: " + cmd + EOL
        return body + PROMPT

    def idle_surfaces(self) -> list[bytes]:
        """Idle surfaces for a future `assert_clean` audit hook. This pilot Console stages no flag,
        so every surface here is non-secret by construction; the real audit lands with the kit
        Console (separate follow-up)."""
        return [BANNER, PROMPT, b"commands: help printenv echo <text>\r\n"]
