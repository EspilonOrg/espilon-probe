"""ftdi medium: real SPI master over a USB-FTDI adapter (FT232H / FT2232H) via pyftdi.

The transaction-medium sibling of the virtual SPI target (docs/design/real-bus-backends.md
section 2): the SAME `BridgeServer._serve_op` drives either, so virtual vs real is a medium
substitution and a course authored once runs either way (docs/design/real-bus-backends.md
section 5.1). Here the medium drives real MPSSE clocking through pyftdi's `SpiController` instead of
the in-process flash model, so the JEDEC id and the flash bytes are real silicon.

This increment ships the SPI READ PATH only - the highest-value demo (ESP32 external-flash
extraction over a SOIC-8 clip) at the least code (docs/design/real-bus-backends.md section 7 step 1):

  - `spi.id`   - RDID (0x9F), read 3 bytes, return the 24-bit JEDEC id (+ descriptive part name);
  - `spi.read` - READ (0x03) + 24-bit address, read exactly `len` bytes (the client `spi dump` loop
                 treats a short read as a HARD error, so the medium never pads or truncates);
  - `scan`     - the JEDEC-id enumerate, one row, the same shape `protocols/spi.scan_rows` yields.

`spi.write` / `spi.reg` / `spi.xfer` are DEFERRED to a later increment: the capability gate still
advertises the whole `spi` group (the single truthful advertisement, docs/design/real-bus-backends.md
section 4), so an operator who runs one of them reaches `op()` here and is refused LOUD with an
actionable line, never a silent or fabricated result.

pyftdi is imported LAZILY inside `open()`, mirroring the hci medium and the `[ftdi]` extra, so:

  - the client core, the virtual bridge, and the whole virtual conformance leg never touch pyftdi;
  - `python -m espilon_probe.bridges --medium ftdi-spi ...` selected WITHOUT the extra fails with one
    clear, actionable line instead of an ImportError traceback;
  - the test suite drives this whole surface against a FAKE pyftdi controller, no adapter, no silicon.

The medium simulates NOTHING (docs/design/real-bus-backends.md section 5.1): an op it cannot perform
raises a clean error the server renders as a wire ERROR; it never fabricates a plausible answer. The
JEDEC part `name` is DESCRIPTIVE metadata from a tiny built-in table and DEGRADES to unknown (the
field is simply omitted), it is never guessed.
"""

from __future__ import annotations

from ...core.fields import as_int
from ...protocols import spi

# The actionable hint printed when ftdi-spi is selected without pyftdi / an adapter present.
_INSTALL_HINT = (
    "the ftdi SPI medium needs the optional [ftdi] extra: pip install 'espilon-probe[ftdi]' "
    "(pyftdi over an FT232H/FT2232H adapter) plus the wired flash. "
    "The virtual SPI leg needs neither - use `probe --backend virtual`.")

# The default pyftdi URL when the operator passes no --target (docs/design/real-bus-backends.md
# section 2.1). Handed straight to SpiController.configure(); pyftdi owns its grammar.
DEFAULT_URL = "ftdi://ftdi:232h/1"

# SPI NOR flash opcodes (the only two this read-path increment issues).
_RDID = 0x9F                     # read JEDEC id: 3 id bytes back
_READ = 0x03                     # read data: 24-bit address, then N bytes back

# JEDEC manufacturer id (first id byte) -> name. Authoritative: these are JEDEC-assigned ids, a
# lookup and not a guess. An unlisted manufacturer id degrades to omitted.
_JEDEC_MFG = {
    0xEF: "winbond", 0xC8: "gigadevice", 0xC2: "macronix",
    0x20: "micron", 0xBF: "sst", 0x1F: "atmel", 0x01: "spansion",
}

# Full 24-bit JEDEC id -> (part name, capacity). Descriptive metadata about common silicon, not
# challenge content, so it stays generalist. An unlisted id yields just the number (name/capacity
# omitted), never a guessed part - a fabricated name would be the "careless author" hazard the
# corpus warns about, one layer down (docs/design/real-bus-backends.md section 5.1).
_JEDEC_PARTS = {
    0xEF4014: ("W25Q80", "1MiB"),
    0xEF4015: ("W25Q16", "2MiB"),
    0xEF4016: ("W25Q32", "4MiB"),
    0xEF4017: ("W25Q64", "8MiB"),
    0xEF4018: ("W25Q128", "16MiB"),
    0xC22016: ("MX25L3206E", "4MiB"),
    0xC22017: ("MX25L6406E", "8MiB"),
    0xC22018: ("MX25L12835F", "16MiB"),
    0xC84015: ("GD25Q16", "2MiB"),
    0xC84016: ("GD25Q32", "4MiB"),
    0xC84017: ("GD25Q64", "8MiB"),
}


def _jedec_meta(id_bytes: bytes) -> dict:
    """Descriptive metadata for a 3-byte JEDEC id, degrading to {} for an unknown part.

    `manufacturer` is filled only from the authoritative JEDEC manufacturer-id table; `name` and
    `capacity` only when the FULL id is a known part. Anything not looked up is omitted, never
    guessed, so an unknown chip surfaces just its number."""
    meta: dict = {}
    mfg = _JEDEC_MFG.get(id_bytes[0])
    if mfg is not None:
        meta["manufacturer"] = mfg
    part = _JEDEC_PARTS.get(int.from_bytes(id_bytes, "big"))
    if part is not None:
        meta["name"], meta["capacity"] = part
    return meta


class SpiFtdiMedium:
    """Transaction medium over a real FTDI SPI master (pyftdi SpiController). Owns the adapter for
    the daemon's lifetime so the ESP32 flash bus stays held (reset asserted) across the per-verb
    `probe spi` processes, exactly like the shipped serial/CAN/hci daemons."""

    shape = "transaction"

    def __init__(self, endpoint: str | None = None, baud: int = 115200):
        # `baud` is accepted for launcher-signature parity with the other media; SPI clocking is set
        # by `spi_hz` via apply_config, not a UART baud, so it is deliberately unused here.
        self.endpoint = endpoint or DEFAULT_URL
        self._freq: float | None = None      # SPI clock Hz from apply_config; None -> pyftdi default
        self._ctrl = None                    # the held pyftdi SpiController
        self._ports: dict[int, object] = {}  # one configured port per chip-select
        self._closed = False

    # --- lifecycle --------------------------------------------------------------------------------

    def open(self) -> None:
        """Open the FTDI adapter. pyftdi is imported HERE (lazy), so the client core and the virtual
        leg never touch it and a missing extra fails with one actionable line, not a traceback."""
        try:
            from pyftdi.spi import SpiController
        except ImportError as e:
            raise SystemExit(f"probe-bridge: {_INSTALL_HINT}") from e
        ctrl = SpiController()
        try:
            ctrl.configure(self.endpoint)
        except Exception as e:
            # A bad URL / no adapter present: fail loud so the launcher surfaces the nonzero exit
            # (docs/design/real-bus-backends.md section 4 point 2), never a half-open medium.
            raise RuntimeError(f"cannot open FTDI SPI adapter at {self.endpoint!r}: {e}")
        self._ctrl = ctrl

    def apply_config(self, config: dict) -> None:
        """Honour a link setting from HELLO.config. For SPI the useful one is the bus clock,
        `{"spi_hz": N}`; an absent / non-positive value keeps the pyftdi default (never guessed).
        Applied before the first op and to any already-configured port."""
        if not isinstance(config, dict):
            return
        hz = config.get("spi_hz")
        if isinstance(hz, (int, float)) and not isinstance(hz, bool) and hz > 0:
            self._freq = float(hz)
            for port in self._ports.values():
                try:
                    port.set_frequency(self._freq)
                except Exception:
                    pass

    def alive(self) -> bool:
        """True while the controller is open and the adapter is present; False after a USB detach so
        the daemon retires (mirrors SerialMedium.alive). When pyftdi exposes connection state we
        trust it; otherwise we report present, and a detached adapter still fails the next op loud."""
        if self._closed or self._ctrl is None:
            return False
        ftdi = getattr(self._ctrl, "ftdi", None)
        if ftdi is not None:
            try:
                return bool(ftdi.is_connected)
            except Exception:
                return False
        return True

    def close(self) -> None:
        self._closed = True
        ctrl, self._ctrl = self._ctrl, None
        self._ports = {}
        if ctrl is not None:
            try:
                ctrl.terminate()
            except Exception:
                pass

    # --- capabilities -----------------------------------------------------------------------------

    def caps(self) -> dict:
        # verbs = spi.VERBS (["scan","spi"]) ONLY: an SPI master is not a sniffer, so the client
        # capability gate (_require_verb, convention C1) refuses the other buses and the relay verbs
        # automatically. This is the single truthful advertisement the whole gate rests on
        # (docs/design/real-bus-backends.md sections 2.4, 4).
        return {"protocol": spi.PROTOCOL, "channels": [],
                "verbs": list(spi.VERBS), "shape": "transaction",
                "meta": {"url": self.endpoint, "freq": self._freq, "adapter": "ft232h"}}

    # --- scan -------------------------------------------------------------------------------------

    def scan(self, seconds: float | None = None, count: int | None = None) -> list[dict]:
        """`probe scan` on the SPI protocol is a JEDEC-id enumerate: one row, the shape
        `protocols/spi.scan_rows` yields. The listen-window / count args are accepted for interface
        parity with the packet/BLE media and ignored (a JEDEC read is a single fixed transaction)."""
        info = self._spi_id(cs=0)
        jedec = info["jedec_id"]
        return [{"name": info.get("name", ""), "addr": f"0x{jedec:06x}", "cs": 0}]

    # --- op ---------------------------------------------------------------------------------------

    def op(self, verb: str, args: dict) -> dict:
        """Run an `spi` verb against the real adapter. `args` is untrusted (off the wire): every
        field is coerced AUTHORITATIVELY (as_int), so an uninterpretable value raises (a clean wire
        ERROR via _serve_op), never a guessed byte on the bus."""
        if verb == "spi.id":
            return self._spi_id(self._cs(args))
        if verb == "spi.read":
            cs = self._cs(args)
            addr = as_int(args.get("addr", 0), "spi.read addr")
            length = as_int(args.get("len", 0), "spi.read len")
            return self._spi_read(addr, length, cs)
        if verb in ("spi.write", "spi.reg", "spi.xfer"):
            # Advertised as part of the `spi` group but not yet implemented on this real medium.
            # Refuse LOUD with an actionable line (surfaced as a clean wire ERROR), never a
            # fabricated result (docs/design/real-bus-backends.md sections 5.1, 7 step 1).
            raise RuntimeError(
                f"{verb} is not implemented on the ftdi SPI medium yet "
                f"(this increment ships the read path: spi.id, spi.read, scan)")
        # An unknown op verb: fail loud, never a silent empty result the client might misread.
        raise ValueError(f"unsupported spi op {verb!r}")

    def _cs(self, args: dict) -> int:
        return as_int(args.get("cs", 0), "spi cs")

    def _spi_id(self, cs: int) -> dict:
        """RDID (0x9F): clock the opcode out and read 3 id bytes back. A short read is a hard error,
        never padded, so a bad clip contact surfaces as an error rather than a fake id."""
        resp = bytes(self._port(cs).exchange(bytes([_RDID]), 3, start=True, stop=True))
        if len(resp) != 3:
            raise RuntimeError(f"spi.id: RDID returned {len(resp)} byte(s), expected 3")
        result = {"jedec_id": int.from_bytes(resp, "big")}
        result.update(_jedec_meta(resp))
        return result

    def _spi_read(self, addr: int, length: int, cs: int) -> dict:
        """READ (0x03) + 24-bit address, read exactly `length` bytes. The client `spi dump` loop
        treats a short read as a HARD error (docs/protocols/spi.md), so the medium returns exactly
        `length` bytes or raises - it never pads or truncates (docs/design/real-bus-backends.md
        section 5.1). `addr`/`length` are already coerced from the untrusted wire args."""
        if length <= 0:
            raise ValueError(f"spi.read: length {length} must be positive")
        if addr < 0 or addr > 0xFFFFFF:
            raise ValueError(f"spi.read: addr 0x{addr:x} out of the 24-bit range (0..0xFFFFFF)")
        cmd = bytes([_READ, (addr >> 16) & 0xFF, (addr >> 8) & 0xFF, addr & 0xFF])
        resp = bytes(self._port(cs).exchange(cmd, length, start=True, stop=True))
        if len(resp) != length:
            raise RuntimeError(
                f"spi.read: adapter returned {len(resp)} byte(s), expected {length} at "
                f"0x{addr:06x} (a short read is a hard error, check the clip contact)")
        return {"data": resp.hex()}

    def _port(self, cs: int):
        """The configured pyftdi SPI port for a chip-select, created lazily and cached. Flash mode 0;
        the clock is `self._freq` (set by apply_config) or pyftdi's default when unset."""
        if self._ctrl is None:
            raise RuntimeError("ftdi SPI medium not open (call open() first)")
        port = self._ports.get(cs)
        if port is None:
            port = self._ctrl.get_port(cs=cs, freq=self._freq, mode=0)
            self._ports[cs] = port
        return port
