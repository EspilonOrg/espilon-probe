"""SPI protocol (master role): device transactions + the `spi` verb group over Backend.op.

Shape: TRANSACTION/REGISTER (see docs/protocol-spi.md). The probe acts as SPI MASTER, so it
does not passively sniff its own bus; `sniff`/`inject`/`replay` are GATED OUT (the protocol
advertises only ["scan", "spi"] and the CLI capability gate refuses the rest cleanly).
Passive bus sniffing (a logic-analyzer tap on someone else's SPI) is a different hardware
mode, explicitly not modeled in v1. `scan` is repurposed as JEDEC-ID / device enumeration.

The named transactions (`spi.id`, `spi.read`, `spi.write`, `spi.reg`, `spi.xfer`) travel over
the existing `op()` carrier, so the identical commands later run against a real `ftdi`
backend (spi.read -> flash 0x03, spi.write -> page-program 0x02, spi.id -> RDID 0x9F,
spi.xfer -> a raw exchange). The protocol module and CLI do not change; only the backend
swaps.

`dump` is protocol-layer sugar (contract item C3): a bounded, chunked loop of `spi.read`
written straight to a raw binary flash image (what `flashrom -r` produces). The dump length
is capped client-side so the read is always bounded. The optional transaction pcap
(DLT_USER_PROBE_SPI = 148) is an off-by-default secondary artifact.
"""

from __future__ import annotations

import struct

from ..core.backend import Backend
from ..core.errors import ProbeError
from ..core.fields import as_int
from ..core.frame import DLT_USER_PROBE_SPI, PcapWriter
from ..core.wire import Frame

PROTOCOL = "spi"
VERBS = ["scan", "spi"]
PCAP_DLT = DLT_USER_PROBE_SPI           # 148, optional transaction pcap only

# Client-side ceiling on a `dump` length: a master read loop must always be bounded. 32 MiB
# matches the spec default. Reads are chunked (4 KiB) so a single transaction is never
# pathological.
DUMP_MAX_BYTES = 32 * 1024 * 1024
_READ_CHUNK_BYTES = 4096

# transaction pcap op codes (docs/protocol-spi.md section 4)
_OP_ID = 1
_OP_READ = 2
_OP_WRITE = 3
_OP_REG = 4
_OP_XFER = 5
_SPI_REC = struct.Struct("<BBHIHH")     # op, cs, flags, addr, mosi_len, miso_len


def _hex_bytes(value, field: str) -> bytes:
    """Coerce a backend hex string to bytes, or raise a clean `ProbeError`.

    A non-string, or a string that is not valid hex, is refused with a field-named message
    instead of leaking a bare `ValueError`/`TypeError` from `bytes.fromhex`."""
    if not isinstance(value, str):
        raise ProbeError(f"backend returned non-string {field}: {value!r}")
    try:
        return bytes.fromhex(value)
    except ValueError:
        raise ProbeError(f"backend returned malformed hex for {field}: {value!r}")


def _result(backend: Backend, verb: str, **kwargs) -> dict:
    """Call `op()` and guarantee a dict result (see jtag._result for the rationale).

    A null or non-dict result is a clean `ProbeError`, never an AttributeError from `.get()`.
    """
    res = backend.op(verb, **kwargs)
    if res is None:
        raise ProbeError(f"backend returned a null result for {verb}")
    if not isinstance(res, dict):
        raise ProbeError(f"backend returned a non-object result for {verb}: {res!r}")
    return res


# named transactions (used by the CLI dispatch and by tests/scripts)
def device_id(backend: Backend, cs: int = 0) -> dict:
    return _result(backend, "spi.id", cs=cs)


def read(backend: Backend, addr: int, length: int, cs: int = 0) -> dict:
    return _result(backend, "spi.read", addr=addr, len=length, cs=cs)


def write(backend: Backend, addr: int, data_hex: str, cs: int = 0) -> dict:
    return _result(backend, "spi.write", addr=addr, data=data_hex, cs=cs)


def reg(backend: Backend, name: str, value_hex: str | None = None, cs: int = 0) -> dict:
    if value_hex is None:
        return _result(backend, "spi.reg", name=name, cs=cs)
    return _result(backend, "spi.reg", name=name, value=value_hex, cs=cs)


def xfer(backend: Backend, mosi_hex: str, cs: int = 0) -> dict:
    return _result(backend, "spi.xfer", mosi=mosi_hex, cs=cs)


def scan_rows(backend: Backend, cs: int = 0) -> list[dict]:
    """`probe scan` = `probe spi id` flattened into the generic scan row shape.

    The device becomes `{name, addr=jedec_id}` so the generic core verb and the protocol
    verb both surface the same enumeration. A `jedec_id` is rendered as a 24-bit hex string;
    a string `jedec_id` is accepted verbatim (a legitimate display form), but any other
    non-int/non-str type is a clean `ProbeError` rather than a formatting traceback.
    """
    info = device_id(backend, cs=cs)
    jedec = info.get("jedec_id", 0)
    if isinstance(jedec, str):
        addr = jedec
    else:
        addr = f"0x{as_int(jedec, 'jedec_id'):06x}"
    return [{"name": info.get("name", ""), "addr": addr, "cs": cs}]


def dump(backend: Backend, length: int, out_path: str, addr: int = 0,
         cs: int = 0, pcap_path: str | None = None) -> int:
    """Dump a flash range to a RAW BINARY image (contract item C3, sugar over spi.read).

    The length is capped client-side (`DUMP_MAX_BYTES`); a request above the ceiling is a
    clean `ProbeError`, never a best-effort partial. Reads are chunked (`_READ_CHUNK_BYTES`)
    so one transaction is never pathological. A short read from the backend (fewer bytes than
    requested for a chunk) is treated as a hard error, not a silently-truncated dump.

    If `pcap_path` is given, an optional transaction pcap (DLT_USER_PROBE_SPI) is written
    alongside the binary, one record per `spi.read`. Returns the number of bytes written.
    """
    if length < 0:
        raise ProbeError(f"spi dump: negative length {length}")
    if length > DUMP_MAX_BYTES:
        raise ProbeError(
            f"spi dump: length {length} exceeds the client ceiling {DUMP_MAX_BYTES} bytes; "
            f"refusing an unbounded dump")

    pw = PcapWriter(pcap_path, DLT_USER_PROBE_SPI) if pcap_path else None
    written = 0
    try:
        with open(out_path, "wb") as fh:
            cur = addr
            remaining = length
            while remaining > 0:
                n = min(_READ_CHUNK_BYTES, remaining)
                res = read(backend, cur, n, cs=cs)
                blob = _hex_bytes(res.get("data", ""), f"spi.read data at 0x{cur:06x}")
                if len(blob) != n:
                    raise ProbeError(
                        f"spi dump: backend returned {len(blob)} bytes, expected {n} at "
                        f"0x{cur:06x}")
                fh.write(blob)
                written += len(blob)
                if pw is not None:
                    pw.write(_read_record(cur, blob, cs))
                cur += n
                remaining -= n
    finally:
        if pw is not None:
            pw.close()
    return written


def _read_record(addr: int, miso: bytes, cs: int) -> Frame:
    """One DLT_USER_PROBE_SPI transaction record for a `spi.read` response."""
    flags = 0x0001                      # bit0 = response
    header = _SPI_REC.pack(_OP_READ, cs & 0xFF, flags, addr & 0xFFFFFFFF,
                           0, len(miso) & 0xFFFF)
    return Frame(ts=0.0, channel=0, raw=header + miso, direction="rx", protocol=PROTOCOL)
