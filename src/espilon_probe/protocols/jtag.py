"""JTAG protocol: TAP transactions + the `jtag` verb group, routed through Backend.op.

Shape: TRANSACTION/REGISTER (see docs/protocol-jtag.md). JTAG is a TAP state machine driven
by request/response transactions, not a packet stream you sniff. So `sniff`/`inject`/`replay`
are GATED OUT (the protocol advertises only ["scan", "jtag"] and the CLI capability gate
refuses the rest cleanly). `scan` is repurposed as scan-chain / IDCODE enumeration.

The named transactions (`jtag.scan_chain`, `jtag.idcode`, `jtag.halt`, `jtag.resume`,
`jtag.read`, `jtag.write`, `jtag.reg`) all travel over the existing `op()` carrier, so the
identical commands later run against a real `openocd` backend (jtag.read -> mdw,
jtag.write -> mww, jtag.halt -> halt, jtag.dump -> dump_image). The protocol module and CLI
do not change; only the backend swaps.

`dump` is protocol-layer sugar (contract item C3): a bounded loop of `jtag.read` written
straight to a raw binary memory image (the firmware/SRAM extraction the operator actually
wants). The dump length is capped client-side so a hostile/buggy backend cannot drive an
unbounded read. The optional transaction pcap (DLT_USER_PROBE_JTAG = 149) is an off-by-default
secondary artifact for operators who want one container of the session.
"""

from __future__ import annotations

import struct

from ..core.backend import Backend
from ..core.errors import ProbeError
from ..core.frame import DLT_USER_PROBE_JTAG, PcapWriter
from ..core.wire import Frame

PROTOCOL = "jtag"
VERBS = ["scan", "jtag"]
PCAP_DLT = DLT_USER_PROBE_JTAG          # 149, optional transaction pcap only

# Client-side ceiling on a `dump` length: a hostile/buggy backend must never drive an
# unbounded read. 16 MiB matches the spec default. Each `jtag.read` chunk is also capped.
DUMP_MAX_BYTES = 16 * 1024 * 1024
_READ_CHUNK_WORDS = 256                 # words per jtag.read in the dump loop (1 KiB)
WORD_BYTES = 4

# transaction pcap op codes (docs/protocol-jtag.md section 4)
_OP_SCAN_CHAIN = 1
_OP_IDCODE = 2
_OP_HALT = 3
_OP_RESUME = 4
_OP_READ = 5
_OP_WRITE = 6
_OP_REG = 7
_JTAG_REC = struct.Struct("<BBHIIHH")   # op, tap, flags, addr, value, count, payload_len


# named transactions (used by the CLI dispatch and by tests/scripts)
def scan_chain(backend: Backend) -> dict:
    return backend.op("jtag.scan_chain")


def idcode(backend: Backend, tap: int = 0) -> dict:
    return backend.op("jtag.idcode", tap=tap)


def halt(backend: Backend, tap: int = 0) -> dict:
    return backend.op("jtag.halt", tap=tap)


def resume(backend: Backend, tap: int = 0, addr: int | None = None) -> dict:
    args: dict = {"tap": tap}
    if addr is not None:
        args["addr"] = addr
    return backend.op("jtag.resume", **args)


def read(backend: Backend, addr: int, words: int = 1) -> dict:
    return backend.op("jtag.read", addr=addr, words=words)


def write(backend: Backend, addr: int, word: int) -> dict:
    return backend.op("jtag.write", addr=addr, word=word)


def reg(backend: Backend, name: str | None = None) -> dict:
    if name is None:
        return backend.op("jtag.reg")
    return backend.op("jtag.reg", name=name)


def scan_rows(backend: Backend) -> list[dict]:
    """`probe scan` = `probe jtag scan-chain` flattened into the generic scan row shape.

    Each TAP becomes `{name, addr=idcode, index}` so the generic core verb and the protocol
    verb both surface the same chain enumeration.
    """
    taps = scan_chain(backend).get("taps", [])
    rows: list[dict] = []
    for tap in taps:
        rows.append({
            "name": tap.get("name", ""),
            "addr": f"0x{int(tap.get('idcode', 0)):08x}",
            "index": tap.get("index", 0),
        })
    return rows


def _words_to_bytes(words: list[int]) -> bytes:
    out = bytearray()
    for w in words:
        out += struct.pack("<I", int(w) & 0xFFFFFFFF)
    return bytes(out)


def dump(backend: Backend, addr: int, length: int, out_path: str,
         pcap_path: str | None = None) -> int:
    """Dump a memory range to a RAW BINARY image (contract item C3, sugar over jtag.read).

    The length is capped client-side (`DUMP_MAX_BYTES`); a request above the ceiling is a
    clean `ProbeError`, never a best-effort partial. Reads are chunked so a single
    transaction is never pathological. `length` must be a whole number of 32-bit words (the
    JTAG read granularity); a non-multiple is refused rather than silently rounded.

    If `pcap_path` is given, an optional transaction pcap (DLT_USER_PROBE_JTAG) is written
    alongside the binary, one record per `jtag.read`. Returns the number of bytes written.
    """
    if length < 0:
        raise ProbeError(f"jtag dump: negative length {length}")
    if length > DUMP_MAX_BYTES:
        raise ProbeError(
            f"jtag dump: length {length} exceeds the client ceiling {DUMP_MAX_BYTES} bytes; "
            f"refusing an unbounded dump")
    if length % WORD_BYTES != 0:
        raise ProbeError(
            f"jtag dump: length {length} is not a multiple of {WORD_BYTES} (JTAG reads "
            f"whole 32-bit words)")

    total_words = length // WORD_BYTES
    pw = PcapWriter(pcap_path, DLT_USER_PROBE_JTAG) if pcap_path else None
    written = 0
    try:
        with open(out_path, "wb") as fh:
            cur = addr
            remaining = total_words
            while remaining > 0:
                n = min(_READ_CHUNK_WORDS, remaining)
                res = read(backend, cur, words=n)
                words = res.get("words", [])
                if len(words) != n:
                    raise ProbeError(
                        f"jtag dump: backend returned {len(words)} words, expected {n} at "
                        f"0x{cur:08x}")
                blob = _words_to_bytes(words)
                fh.write(blob)
                written += len(blob)
                if pw is not None:
                    pw.write(_read_record(cur, words))
                cur += n * WORD_BYTES
                remaining -= n
    finally:
        if pw is not None:
            pw.close()
    return written


def _read_record(addr: int, words: list[int]) -> Frame:
    """One DLT_USER_PROBE_JTAG transaction record for a `jtag.read` response."""
    payload = _words_to_bytes(words)
    first = int(words[0]) & 0xFFFFFFFF if words else 0
    flags = 0x0001                      # bit0 = response
    header = _JTAG_REC.pack(_OP_READ, 0, flags, addr & 0xFFFFFFFF, first,
                            len(words) & 0xFFFF, len(payload) & 0xFFFF)
    return Frame(ts=0.0, channel=0, raw=header + payload, direction="rx", protocol=PROTOCOL)
