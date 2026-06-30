"""serial backend: real UART over a Linux serial device or pty (/dev/ttyUSB0, /dev/pts/N).

Raw file-descriptor I/O, no third-party dependency. Optional best-effort raw+baud setup via
termios for a real tty (harmless to skip on a pty). The same `uart read` / `uart write`
verbs that drive the virtual lab drive a real line here, which is the dual-purpose payoff
for UART. A pty pair makes this provable locally with no hardware.
"""

from __future__ import annotations

import errno
import os
import select

from ..core.backend import Backend, Capabilities
from ..core.errors import ProbeError


class SerialBackend(Backend):
    def __init__(self, target: str | None = None, baud: int = 115200):
        self.path = target or "/dev/ttyUSB0"
        self.baud = baud
        self._fd: int | None = None

    def open(self) -> None:
        try:
            fd = os.open(self.path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        except OSError as e:
            raise RuntimeError(f"cannot open serial device {self.path!r}: {e}")
        self._configure(fd)
        self._fd = fd

    def _configure(self, fd: int) -> None:
        # best-effort raw + baud for a real tty; a pty is not a tty so this is skipped
        try:
            import termios
            import tty
            tty.setraw(fd)
            attrs = termios.tcgetattr(fd)
            baud_const = getattr(termios, f"B{self.baud}", None)
            if baud_const is not None:
                attrs[4] = baud_const   # ispeed
                attrs[5] = baud_const   # ospeed
                termios.tcsetattr(fd, termios.TCSANOW, attrs)
        except Exception:
            pass

    def close(self) -> None:
        try:
            if self._fd is not None:
                os.close(self._fd)
        except Exception:
            pass
        self._fd = None

    def _require(self) -> int:
        if self._fd is None:
            raise RuntimeError("serial backend not open (call open() first)")
        return self._fd

    def capabilities(self) -> Capabilities:
        return Capabilities(protocol="uart", transport="serial", channels=[],
                            verbs=["uart"], shape="stream",
                            meta={"port": self.path, "baud": self.baud})

    def scan(self) -> list[dict]:
        return [{"port": self.path, "baud": self.baud}]

    def op(self, verb: str, **kwargs) -> dict:
        fd = self._require()
        if verb == "uart.write":
            os.write(fd, bytes.fromhex(kwargs["data"]))
            return {"ok": True}
        if verb == "uart.read":
            buf = b""
            ready, _, _ = select.select([fd], [], [], 0.5)   # wait for the first byte
            while ready:
                try:
                    data = os.read(fd, 4096)
                except OSError as e:
                    if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                        break
                    raise
                if not data:
                    break
                buf += data
                ready, _, _ = select.select([fd], [], [], 0.1)   # drain the rest
            return {"data": buf.hex()}
        raise ProbeError(f"protocol verb '{verb}' is not supported on protocol 'uart'")

    # UART is a byte stream, not packets; the packet verbs do not apply. The CLI gate
    # refuses these first (they are not in capabilities().verbs); refuse defensively here too
    # with a clean operator-facing error rather than a bare NotImplementedError.
    def sniff(self, *a, **k) -> int:
        raise ProbeError("'sniff' is not supported on protocol 'uart' (a byte stream; use uart read)")

    def inject(self, *a, **k) -> None:
        raise ProbeError("'inject' is not supported on protocol 'uart' (a byte stream; use uart write)")

    def replay(self, *a, **k) -> int:
        raise ProbeError("'replay' is not supported on protocol 'uart' (a byte stream; use uart write)")
