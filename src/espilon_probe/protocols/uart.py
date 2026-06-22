"""UART protocol: a byte stream, not packets - a different protocol shape.

No scan/sniff frames; the verbs are `uart write` / `uart read` over the line, routed
through Backend.op so they work the same against the virtual bridge and a real serial
backend (pty / USB-UART).
"""

from __future__ import annotations

from ..core.backend import Backend

PROTOCOL = "uart"
VERBS = ["uart"]


def write(backend: Backend, data: bytes) -> None:
    backend.op("uart.write", data=data.hex())


def read(backend: Backend) -> bytes:
    return bytes.fromhex(backend.op("uart.read").get("data", ""))
