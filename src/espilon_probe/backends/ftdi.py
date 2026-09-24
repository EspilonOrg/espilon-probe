"""ftdi backend: a loopback launcher for a real SPI (later I2C) master over a USB-FTDI adapter.

`probe --backend ftdi --target 'ftdi://ftdi:232h/1' spi id` stays simple for the user, but internally
probe reaches a PERSISTENT `probe-bridge` daemon for the ftdi medium and connects to it over the
ordinary wire tunnel (docs/design/00 decision 5, docs/design/real-bus-backends.md sections 1-2). The
client holds ZERO medium knowledge and ZERO third-party dependency: the pyftdi MPSSE I/O and its lazy
`[ftdi]` extra live in the bridge's ftdi medium (bridges/media/ftdi.py); here the client only does
process orchestration + rendezvous.

Why PERSISTENT (same rationale as serial/CAN/hci): a flash-clip read holds the ESP32 in reset (EN
low) for the WHOLE session so the SoC releases the flash bus and only the FT232H drives it. Reset is
asserted once and held across `spi id` -> `spi read` -> `spi dump`, which are discrete per-verb
`probe` processes; a daemon that opened and tore down the adapter per verb would drop that held state.
So the FIRST invocation for a target spawns a detached daemon that holds the adapter; SUBSEQUENT
invocations for the same target DISCOVER and connect to it. The rendezvous machinery is shared
verbatim with the serial/CAN/hci launchers (it takes the medium name as a parameter).

One FT232H MPSSE channel is physically wired for SPI OR I2C at a time, not both, so the backend needs
to know which mode to spawn. The operator already typed the verb group (`spi`/`i2c`); rather than add
a `--mode` flag (daily use stays light and flag-free), `_ftdi_mode` maps the verb to a mode and
`open()` spawns the matching medium. `scan`/`info` default to SPI (the flash-dump demo is the
headline). This increment ships the SPI medium; the I2C twin lands once the i2c protocol does.

This is a subclass of the tunnel client (VirtualBackend), the twin of SerialBackend/CanBackend/
HciBackend: once connected it IS the tunnel client, so `scan`/`op` are inherited unchanged. `close()`
only closes the tunnel connection; it does NOT kill the daemon (that is the whole point of persistence).
"""

from __future__ import annotations

from .serial import _ensure_bridge
from .virtual import VirtualBackend

# The default pyftdi URL when the operator passes no --target (matched by string so the client core
# imports no bridge/medium module; the medium re-derives the same default from its own constant).
_DEFAULT_URL = "ftdi://ftdi:232h/1"


def _ftdi_mode(verb: str | None) -> str:
    """SPI vs I2C from the verb group the operator typed (no --mode flag). `spi`/`scan`/`info`
    default to SPI (the flash-dump demo is the headline); `i2c` picks the I2C bus once that medium
    lands (docs/design/real-bus-backends.md section 2.1)."""
    return "i2c" if verb == "i2c" else "spi"


class FtdiBackend(VirtualBackend):
    _transport_label = "ftdi"

    def __init__(self, target: str | None = None, baud: int = 115200, mode: str = "spi"):
        # The tunnel target is not known until we discover/spawn the daemon (set in open()).
        super().__init__(target=None, baud=baud)
        self.endpoint = target or _DEFAULT_URL
        self.mode = mode

    def open(self) -> None:
        medium = "ftdi-spi" if self.mode == "spi" else "ftdi-i2c"
        port = _ensure_bridge(medium, self.endpoint, self.baud)   # reuse serial.py's rendezvous
        self.target = f"tcp://127.0.0.1:{port}"
        super().open()

    # close() is inherited from VirtualBackend: it closes ONLY the tunnel connection. The daemon is
    # persistent and retires on its own idle timeout / medium death; we deliberately do not kill it.
