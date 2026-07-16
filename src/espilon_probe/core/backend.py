"""The Backend contract - the single interface every backend implements.

A backend is the bottom layer: it is the only thing that knows HOW bytes reach the
target. Everything above it (CLI, protocol semantics) is backend-agnostic, so the exact
same `probe scan` runs against the virtual backend or a real hardware backend.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field

from .errors import ProbeError

# Shared RAW-STREAM read constants (docs/design/01-transport.md section 3). One home so the tunnel
# backend and every stream bridge cannot drift on how a stream read is bounded:
#   - the DEFAULT first-byte wait when the CLI is given no -t;
#   - how long a line must be quiet ("one inter-byte idle gap") before a read returns the bytes
#     it has drained so far. Not player-facing; a wall-clock cadence the contract lets differ.
UART_READ_TIMEOUT_DEFAULT = 1.0
UART_READ_IDLE_GAP = 0.1
# Hard cap on how long the WHOLE read may run past its first-byte budget. Without it, a target
# that dribbles one byte faster than UART_READ_IDLE_GAP keeps the idle-gap drain from ever
# elapsing, so `uart read` would hang forever. With it, the total read is bounded by
# `timeout + UART_READ_DRAIN_CAP`, so a chatty / dribbling / silent target always returns.
UART_READ_DRAIN_CAP = 2.0


@dataclass
class Capabilities:
    """What a backend can do, returned by `capabilities()` and shown by `probe info`."""

    protocol: str                     # "ble", "zigbee", "uart", "jtag", ...
    transport: str                    # "virtual", "hci", "killerbee", "openocd", ...
    channels: list[int] = field(default_factory=list)
    verbs: list[str] = field(default_factory=list)   # core + protocol verbs offered
    shape: str = "packet"             # "packet" | "stream" | "transaction" (C2)
    meta: dict = field(default_factory=dict)


class Backend(abc.ABC):
    """Implemented by virtual.py (a target server over TCP) and the real adapters (hci, killerbee...).

    The core verbs below are common to every protocol. Connection-oriented or bus-specific
    operations (BLE gatt, JTAG halt, SPI dump) are exposed by the protocol layer and routed
    through `op()`, and are only offered when advertised in `Capabilities.verbs`.
    """

    # Frames dropped by the LAST `sniff` because they were malformed (skip-and-count policy).
    # A backend that captures sets this each `sniff`; the CLI surfaces it after the frame count.
    dropped_frames: int = 0

    @abc.abstractmethod
    def open(self) -> None:
        """Bind the protocol: open the TCP session (virtual) or the USB device (real)."""

    @abc.abstractmethod
    def close(self) -> None:
        """Release the protocol and any capture resources."""

    @abc.abstractmethod
    def capabilities(self) -> Capabilities:
        ...

    @abc.abstractmethod
    def scan(self, seconds: float | None = None, count: int | None = None) -> list[dict]:
        """Enumerate what is on the protocol (advertisers / PANs / nodes / bus devices).

        `seconds` is how long to listen on a packet medium (BLE/CAN/...); None means the medium's
        own default window. `count` optionally stops the enumerate early once that many distinct
        devices are seen. Both are hints a transaction bus-enumerate (jtag/spi) ignores.
        """

    @abc.abstractmethod
    def sniff(self, out_pcap: str, count: int | None = None,
              seconds: float | None = None, channel: int | None = None) -> int:
        """Stream frames to a standard pcap. Returns the number of frames captured."""

    @abc.abstractmethod
    def inject(self, frame: bytes, channel: int | None = None) -> None:
        """Transmit one raw frame on the protocol."""

    @abc.abstractmethod
    def replay(self, in_pcap: str, frame_filter: str | None = None) -> int:
        """Re-transmit frames from a pcap. Returns the number of frames replayed."""

    @abc.abstractmethod
    def op(self, verb: str, **kwargs) -> dict:
        """Execute a protocol-specific verb (e.g. gatt.write, jtag.halt, spi.dump).

        The protocol layer builds the call; the backend carries it to the target (over the
        wire protocol for virtual, or via the native lib for a real adapter).
        """

    # RAW-STREAM data path (docs/design/01-transport.md section 3). These are CONCRETE, not abstract:
    # they default to a clean refusal so every FRAMED backend (CAN, BLE, JTAG, SPI, ...) inherits
    # a clean "this protocol is not a byte stream" for free, and ONLY the tunnel/stream backend
    # overrides them. A stream verb (`uart read`/`uart write`) routes here, NOT through `op()`.
    def stream_write(self, data: bytes) -> int:
        """Send raw bytes on the pipe. Returns the count written."""
        raise ProbeError("this protocol is not a byte stream")

    def stream_read(self, timeout: float) -> bytes:
        """Receive from the pipe, blocking up to `timeout` for the FIRST byte, then draining
        until the line is idle for one inter-byte gap. Empty result on a silent line is not
        an error."""
        raise ProbeError("this protocol is not a byte stream")

    def __enter__(self) -> "Backend":
        self.open()
        return self

    def __exit__(self, *exc) -> None:
        self.close()
