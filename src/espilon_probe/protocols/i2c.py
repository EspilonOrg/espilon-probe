"""I2C protocol (master role): device transactions + the `i2c` verb group over Backend.op.

Shape: TRANSACTION/REGISTER (see docs/protocols/i2c.md). The probe acts as I2C MASTER, so it
does not passively sniff its own bus; `sniff`/`inject`/`replay` are GATED OUT (the protocol
advertises only ["scan", "i2c"] and the CLI capability gate refuses the rest cleanly).
Passive bus sniffing (a logic-analyzer tap on someone else's I2C) is a different hardware
mode, explicitly not modeled in v1. `scan` is repurposed as a bus enumerate: the classic
address sweep that probes every 7-bit address and reports which slaves ACK.

The named transactions (`i2c.scan`, `i2c.read`, `i2c.write`, `i2c.reg`) travel over the
existing `op()` carrier, so the identical commands later run against a real `ftdi` / bus-pirate
backend (i2c.read -> START, addr|R, read N, STOP; i2c.write -> START, addr|W, bytes, STOP; the
optional `--reg` is the register-pointer write that precedes a read). The protocol module and
CLI do not change; only the backend swaps.

`dump` is protocol-layer sugar (contract item C3): a bounded, chunked loop of `i2c.read` written
straight to a raw binary EEPROM image (what an EEPROM programmer extracts). The dump length is
capped client-side so the read is always bounded; the length comes from `--size`, or - when the
address sweep advertised the part's size - from that. The optional transaction pcap
(DLT_USER_PROBE_I2C = 151) is an off-by-default secondary artifact.
"""

from __future__ import annotations

import struct

from ..core.backend import Backend
from ..core.errors import ProbeError
from ..core.fields import as_int, hex_bytes
from ..core.frame import DLT_USER_PROBE_I2C, PcapWriter
from ..core.wire import Frame

PROTOCOL = "i2c"
VERBS = ["scan", "i2c"]
PCAP_DLT = DLT_USER_PROBE_I2C           # 151, optional transaction pcap only

# Client-side ceiling on a `dump` length: a master read loop must always be bounded. A single
# EEPROM never approaches this; 32 MiB matches the spec default. Reads are chunked (4 KiB) so a
# single transaction is never pathological.
DUMP_MAX_BYTES = 32 * 1024 * 1024
_READ_CHUNK_BYTES = 4096

# transaction pcap op codes (docs/protocols/i2c.md section 4)
_OP_READ = 1
_OP_WRITE = 2
_OP_REG = 3
_I2C_REC = struct.Struct("<BBHHH")      # op, addr(7-bit), flags, reg, length


def _hex_bytes(value, field: str) -> bytes:
    """Coerce a backend hex string to bytes, or raise a clean `ProbeError`.

    Thin alias for `core.fields.hex_bytes` (the single sound place hex coercion lives), kept so
    existing i2c/cli imports of `_hex_bytes` keep working unchanged."""
    return hex_bytes(value, field)


def _result(backend: Backend, verb: str, **kwargs) -> dict:
    """Call `op()` and guarantee a dict result (see spi._result for the rationale).

    A null or non-dict result is a clean `ProbeError`, never an AttributeError from `.get()`.
    """
    res = backend.op(verb, **kwargs)
    if res is None:
        raise ProbeError(f"backend returned a null result for {verb}")
    if not isinstance(res, dict):
        raise ProbeError(f"backend returned a non-object result for {verb}: {res!r}")
    return res


# named transactions (used by the CLI dispatch and by tests/scripts)
def bus_scan(backend: Backend) -> dict:
    """`i2c.scan` -> the address-sweep result: which 7-bit slave addresses ACK."""
    return _result(backend, "i2c.scan")


def read(backend: Backend, addr: int, length: int, reg: int | None = None) -> dict:
    # A single-shot read length must be positive; a non-positive `-n` is refused here so it never
    # reaches the backend (the same bound `dump` enforces, applied to the sugar's core op).
    if length <= 0:
        raise ProbeError(f"i2c read: length {length} must be positive")
    kwargs = {"addr": addr, "n": length}
    if reg is not None:
        kwargs["reg"] = reg
    return _result(backend, "i2c.read", **kwargs)


def write(backend: Backend, addr: int, data_hex: str, reg: int | None = None) -> dict:
    kwargs = {"addr": addr, "data": data_hex}
    if reg is not None:
        kwargs["reg"] = reg
    return _result(backend, "i2c.write", **kwargs)


def reg(backend: Backend, name: str, value_hex: str | None = None) -> dict:
    if value_hex is None:
        return _result(backend, "i2c.reg", name=name)
    return _result(backend, "i2c.reg", name=name, value=value_hex)


def _addr_str(value) -> str:
    """Render a 7-bit slave address as `0xNN`, or verbatim when the backend already sent a string.

    A string address is accepted as a legitimate display form; any other non-int type is a clean
    `ProbeError` rather than a formatting traceback, matching spi.scan_rows' jedec handling."""
    if isinstance(value, str):
        return value
    return f"0x{as_int(value, 'addr'):02x}"


def scan_rows(backend: Backend) -> list[dict]:
    """`probe scan` = `probe i2c scan` flattened into the generic scan row shape.

    The bus sweep result `{devices: [{addr, ack, ...}]}` becomes one row per ACKing device,
    `{name?, addr, ack}` so the generic core verb and the protocol verb both surface the same
    enumeration. Only ACKing addresses are rows (a NACK is the absence of a device). A non-list
    `devices`, or a non-dict device row, is refused/skipped rather than crashing the display.
    """
    info = bus_scan(backend)
    devices = info.get("devices", [])
    if devices is None:
        return []
    if not isinstance(devices, list):
        raise ProbeError(f"backend returned non-list i2c devices {devices!r}")
    rows: list[dict] = []
    for dev in devices:
        if not isinstance(dev, dict):
            continue
        if not dev.get("ack", True):
            continue
        row = {"addr": _addr_str(dev.get("addr", 0)), "ack": "ACK"}
        if dev.get("name"):
            row = {"name": dev.get("name"), **row}
        if dev.get("size") is not None:
            row["size"] = dev.get("size")
        rows.append(row)
    return rows


def _device_size(backend: Backend, addr: int) -> int | None:
    """The memory size the address sweep advertised for slave `addr`, or None if unknown.

    Used by `dump` to size a whole-EEPROM read when the operator did not pass `--size`. A device
    that advertises no size makes `dump` ask for `--size` rather than guess a length."""
    info = bus_scan(backend)
    devices = info.get("devices", [])
    if not isinstance(devices, list):
        return None
    for dev in devices:
        if not isinstance(dev, dict):
            continue
        try:
            dev_addr = as_int(dev.get("addr", -1), "addr")
        except ProbeError:
            continue
        if dev_addr == addr and dev.get("size") is not None:
            return as_int(dev.get("size"), "size")
    return None


def dump(backend: Backend, addr: int, out_path: str, size: int | None = None,
         reg_base: int = 0, pcap_path: str | None = None) -> int:
    """Dump a whole EEPROM to a RAW BINARY image (contract item C3, sugar over `i2c.read`).

    The length is `size` when given, else the size the address sweep advertised for `addr`; if
    neither is available `dump` refuses (it never guesses an unbounded length). The length is
    capped client-side (`DUMP_MAX_BYTES`); a request above the ceiling is a clean `ProbeError`.
    Reads are chunked (`_READ_CHUNK_BYTES`), each anchored at an explicit register pointer so the
    device's address auto-increment is never relied on. A short read from the backend (fewer bytes
    than requested for a chunk) is a hard error, not a silently-truncated dump.

    If `pcap_path` is given, an optional transaction pcap (DLT_USER_PROBE_I2C) is written alongside
    the binary, one record per `i2c.read`. Returns the number of bytes written.
    """
    if size is None:
        size = _device_size(backend, addr)
    if size is None:
        raise ProbeError(
            f"i2c dump: no size for 0x{addr:02x}; pass --size <bytes> (the address sweep did not "
            f"advertise this device's size, so the dump length is unknown)")
    if size < 0:
        raise ProbeError(f"i2c dump: negative size {size}")
    if size > DUMP_MAX_BYTES:
        raise ProbeError(
            f"i2c dump: size {size} exceeds the client ceiling {DUMP_MAX_BYTES} bytes; refusing "
            f"an unbounded dump")

    pw = PcapWriter(pcap_path, DLT_USER_PROBE_I2C) if pcap_path else None
    written = 0
    try:
        with open(out_path, "wb") as fh:
            cur = reg_base
            remaining = size
            while remaining > 0:
                n = min(_READ_CHUNK_BYTES, remaining)
                res = read(backend, addr, n, reg=cur)
                blob = _hex_bytes(res.get("data", ""), f"i2c.read data at reg 0x{cur:04x}")
                if len(blob) != n:
                    raise ProbeError(
                        f"i2c dump: backend returned {len(blob)} bytes, expected {n} at reg "
                        f"0x{cur:04x}")
                fh.write(blob)
                written += len(blob)
                if pw is not None:
                    pw.write(_read_record(addr, cur, blob))
                cur += n
                remaining -= n
    finally:
        if pw is not None:
            pw.close()
    return written


def _read_record(addr: int, reg_ptr: int, data: bytes) -> Frame:
    """One DLT_USER_PROBE_I2C transaction record for an `i2c.read` response."""
    flags = 0x0001                      # bit0 = response
    header = _I2C_REC.pack(_OP_READ, addr & 0xFF, flags, reg_ptr & 0xFFFF, len(data) & 0xFFFF)
    return Frame(ts=0.0, channel=0, raw=header + data, direction="rx", protocol=PROTOCOL)
