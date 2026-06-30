# Protocol: SPI (virtual)

Read `protocol-conventions.md` first. This doc specifies `protocols/spi.py` and what a
virtual backend must simulate. Implementation is probe-dev.

## 1. What it models

An operator acting as SPI MASTER through an adapter (Bus Pirate, FT2232 via pyftdi,
`flashrom`-style flash access):

- identify the device by JEDEC ID / RDID (`9F`),
- dump a SPI NOR flash to a file (READ `03` / fast-read `0B`),
- read/write registers or status (RDSR `05`, WRSR `01`, WREN `06`),
- issue an arbitrary raw transaction (CS-low, clock N bytes out, capture N bytes back).

This is the half-duplex / full-duplex MASTER role. Passive bus sniffing (a logic-analyzer
tap on someone else's SPI bus) is a DIFFERENT hardware mode and is explicitly NOT modeled in
v1; see shape note below.

Tradecraft mapping:

| Real tool | probe verb |
|---|---|
| `flashrom --probe`, RDID `9F` | `probe scan` / `probe spi id` |
| `flashrom -r dump.bin` | `probe spi dump -w dump.bin` |
| read N bytes at addr | `probe spi read --addr A --len N` |
| page program `02` | `probe spi write --addr A --hex ...` |
| RDSR/WRSR | `probe spi reg --read status` / `--write status XX` |
| raw Bus Pirate transaction | `probe spi xfer --hex <mosi>` |

## 2. Shape and verb set

Shape: TRANSACTION/REGISTER. SPI master is request/response, full-duplex per CS assertion.

Core verbs:

| Core verb | SPI | Reason |
|---|---|---|
| `scan` | OFFERED (repurposed) | JEDEC-ID / device enumerate (one or more chip-selects) |
| `sniff` | GATED OUT | a master does not passively sniff its own bus; passive tap not modeled in v1 |
| `inject` | GATED OUT | no free-standing "frame"; you issue a CS-framed transaction (`spi xfer`) |
| `replay` | GATED OUT | no pcap capture verb exists for SPI master mode |

Gated verb -> `ProbeError`:
`probe: 'sniff' is not supported on protocol 'spi' (supported: scan, spi)`.

Protocol verbs (group `spi`), routed through `Backend.op`:

| CLI | op verb | args | returns |
|---|---|---|---|
| `probe spi id` | `spi.id` | `cs?` (default 0) | `{jedec_id, manufacturer, capacity, name}` |
| `probe spi read` | `spi.read` | `addr` (int), `len` (int), `cs?` | `{addr, data}` (hex) |
| `probe spi write` | `spi.write` | `addr` (int), `data` (hex), `cs?` | `{ok, addr, written}` |
| `probe spi reg` | `spi.reg` | `name` (e.g. "status"), `value?` (hex) | read: `{name, value}` / write: `{ok}` |
| `probe spi xfer` | `spi.xfer` | `mosi` (hex), `cs?` | `{miso}` (hex, same length as mosi) |
| `probe spi dump` | (built on `spi.read`) | `addr?`, `len`, `-w out.bin` | writes binary, returns `{bytes}` |

`probe scan` and `probe spi id` share the same enumeration; `scan` returns the device row(s)
in the generic shape (`{name, addr=jedec_id}`).

`xfer` is the raw escape hatch: it clocks `mosi` out and returns `miso` of identical length
(full-duplex). It is how an author models any vendor command not covered by the named verbs,
and how an operator reproduces an arbitrary Bus Pirate sequence.

`dump` is protocol-layer sugar (contract item C3): a bounded loop of `spi.read` writing
straight to a binary file. The client MUST cap `len` (default ceiling 32 MiB, `ProbeError`
above it) so the dump is always bounded client-side; it also chunks reads (e.g. 4 KiB per
`spi.read`) so one transaction is never pathological.

## 3. `capabilities()` shape

```python
Capabilities(
    protocol="spi",
    transport="virtual",           # later "ftdi"
    channels=[],                   # SPI has no channels; chip-selects live in meta
    verbs=["scan", "spi"],         # NOTE: no sniff/inject/replay
    meta={
        "shape": "transaction",    # contract item C2
        "chip_selects": 1,
        "mode": 0,                 # CPOL/CPHA, informational
        "max_xfer": 4096,          # bytes per single spi.xfer/spi.read the backend accepts
        "flash": {"size": 8388608, "page": 256, "sector": 4096},  # if a NOR is present
    },
)
```

`verbs` omits `sniff`, `inject`, `replay` - the gate.

## 4. DLT and capture representation

SPI has NO standard pcap DLT and no capture verb, so by default no pcap is emitted.

Primary artifact: `probe spi dump` writes a RAW BINARY flash image (what `flashrom -r`
produces), and named transactions print a structured result to stdout / JSON.

Optional secondary artifact: a transaction pcap under `DLT_USER_PROBE_SPI = 148`, opt-in via
`probe spi dump --pcap session.pcap`. One pcap record per SPI transaction (one CS
assertion), little-endian:

```
offset  size  field
0       1     op        (1=id 2=read 3=write 4=reg 5=xfer)
1       1     cs
2       2     flags     (bit0 = response, bit1 = error)
4       4     addr      (read/write; 0 otherwise)
8       2     mosi_len
10      2     miso_len
12      ...   mosi      (bytes clocked out)
...     ...   miso      (bytes clocked back, same transaction)
```

Off by default. The raw flash image is the primary, honest output; do not emit a
standard-DLT pcap that no dissector understands.

## 5. What the virtual backend must simulate (for a lab author)

A `device.py` author exposes a SPI device model:

- one or more chip-selects, each a device with a `jedec_id` and a backing byte array
  (a NOR flash image), plus a status register and a write-enable latch.
- address space with regions and permissions; a `write`/page-program only succeeds when the
  region is writable and WREN is set (a lab can model an OTP / locked region).
- the flag (Model B): flag bytes staged at a flash offset that is only readable after the
  correct unlock (e.g. write a key to a status/config register via `spi.reg`, which flips a
  protection bit, then `spi.read` the now-readable region). Delivered over the wire as the
  read data, never in filesystem/env. Mirrors the JTAG and BLE unlock-then-read pattern.

Backend hooks (`device.py`, all via existing `OP`):

```
on_op("spi.id", cs)               -> {jedec_id, ...}
on_op("spi.read", addr, len, cs)  -> {addr, data}        # enforce region perms
on_op("spi.write", addr, data,cs) -> {ok, written}       # enforce WREN + writable; may unlock
on_op("spi.reg", name, value?)    -> {...}               # status/config; may flip protection
on_op("spi.xfer", mosi, cs)       -> {miso}              # raw command decode
```

Same-commands-transfer note: the identical `probe spi *` commands later run against the
`ftdi` real backend (pyftdi / Bus Pirate). `spi.read`/`spi.write`/`spi.id` map to the
corresponding flash commands (`03`/`02`/`9F`), `spi.xfer` to a raw `spi.exchange`,
`spi.dump` to a chunked read loop. The protocol module and CLI are unchanged; only the
backend swaps. The flash/register model the virtual backend simulates is the same surface a
real NOR exposes, so a virtual solve transfers to a real chip.

## 6. Contract-evolution items touched

- C1 (`ProbeError` + `_require_verb` gate) - needed for the gated core verbs.
- C2 (`Capabilities.shape`) - SPI sets `shape="transaction"`.
- C3 (`protocols/spi.py::dump` sugar over `op("spi.read")`) - new protocol-layer helper.
- No new Backend method, no new wire message type. `op()` carries every SPI transaction.
