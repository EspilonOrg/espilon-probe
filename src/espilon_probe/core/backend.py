"""The Backend contract - the single interface every backend implements.

STRUCTURE PHASE: this defines the contract only. No backend is implemented yet.

A backend is the bottom layer: it is the only thing that knows HOW bytes reach the
target. Everything above it (CLI, protocol semantics) is backend-agnostic, so the exact
same `probe scan` runs against the virtual lab backend or a real hardware backend.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field


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
    """Implemented by virtual.py (lab over TCP) and the real adapters (hci, killerbee...).

    The core verbs below are common to every protocol. Connection-oriented or bus-specific
    operations (BLE gatt, JTAG halt, SPI dump) are exposed by the protocol layer and routed
    through `op()`, and are only offered when advertised in `Capabilities.verbs`.
    """

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
    def scan(self) -> list[dict]:
        """Enumerate what is on the protocol (advertisers / PANs / nodes / bus devices)."""

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

    def __enter__(self) -> "Backend":
        self.open()
        return self

    def __exit__(self, *exc) -> None:
        self.close()
