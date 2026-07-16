"""UART protocol: a RAW-STREAM byte pipe, not packets - a different protocol shape.

No scan/sniff frames and no `OP` transactions on the data path: the verbs are `uart write` /
`uart read` and they map straight onto the backend's RAW-STREAM surface (`stream_write` /
`stream_read`, i.e. send / recv on the raw pipe), so the SAME verbs drive the virtual bridge and
a real serial bridge (pty / USB-UART) with byte-for-byte identical behaviour (docs/design/01-transport.md
section 3, docs/protocols/uart.md). A FRAMED backend inherits a clean "not a byte stream" refusal
from Backend, so calling these on the wrong protocol fails loud, never silently.
"""

from __future__ import annotations

from ..core.backend import UART_READ_TIMEOUT_DEFAULT, Backend

PROTOCOL = "uart"
VERBS = ["uart"]


def write(backend: Backend, data: bytes) -> int:
    """Send `data` on the line. Returns the number of bytes written."""
    return backend.stream_write(data)


def read(backend: Backend, timeout: float = UART_READ_TIMEOUT_DEFAULT) -> bytes:
    """Read from the line: block up to `timeout` for the first byte, then drain the line until it
    goes idle. Raw bytes; the caller decodes for display. An empty read on a silent line is not an
    error."""
    return backend.stream_read(timeout)


def send(backend: Backend, payload: bytes, timeout: float = UART_READ_TIMEOUT_DEFAULT,
         read: bool = True) -> bytes:
    """Atomic send-then-drain on ONE duplex connection: attach duplex, write `payload`, then drain
    the response (raw bytes; the caller renders / gates on it). An empty response on a silent line
    is not an error. With `read=False`, send only and return b"".

    It MUST attach DUPLEX, and that is the whole point of `send` existing (docs/protocols/
    uart-console.md section 5): a "write" attach puts the bridge pump in feed=False, so device RX is
    not fed back on the connection - `stream_write` then `stream_read` would attach "write" and the
    read would see nothing. Keeping the write and the drain on a SINGLE duplex connection captures
    the response to THIS command deterministically on any bridge (persistent or short-lived), which
    is why solvers / smoke / adversarial / CI use `send` and not two separate processes."""
    ch = backend.stream_open("duplex")
    ch.send(payload)
    if not read:
        return b""
    return ch.drain(timeout)
