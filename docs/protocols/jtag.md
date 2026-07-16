# Protocol: JTAG

**Status:** shape `transaction`. The `virtual` backend works today; the real `openocd`
backend is not built yet.

Read `../protocol-conventions.md` first. This doc specifies the JTAG protocol module
(`protocols/jtag.py`) and what a virtual backend must simulate; the same `probe jtag *` commands
drive the future `openocd` backend unchanged.

## 1. What it models

A JTAG operator driving a TAP through an adapter, as you would with OpenOCD or a JTAGulator:

- find the pins / enumerate the scan chain and read IDCODEs (JTAGulator + `scan_chain`),
- halt and resume the core (OpenOCD `halt` / `resume`),
- read/write memory and CPU registers on the halted core (`mdw`/`mww`, `reg`),
- dump a memory range to a file (firmware/SRAM extraction).

Tradecraft mapping (what the operator would otherwise type):

| Real tool | probe verb |
|---|---|
| `jtagulator` pin/chain discovery, `scan_chain` | `probe scan` / `probe jtag scan-chain` |
| `scan_chain` IDCODE row | `probe jtag idcode` |
| `halt` | `probe jtag halt` |
| `resume` | `probe jtag resume` |
| `mdw addr count` | `probe jtag read --addr A --words N` |
| `mww addr value` | `probe jtag write --addr A --word V` |
| `dump_image file addr len` | `probe jtag dump --addr A --len L -w out.bin` |

## 2. Shape and verb set

Shape: TRANSACTION/REGISTER. JTAG is a TAP state machine, not packet-sniffable.

Core verbs:

| Core verb | JTAG | Reason |
|---|---|---|
| `scan` | OFFERED (repurposed) | enumerate the scan chain: TAPs + IDCODEs, like a bus enumerate |
| `sniff` | GATED OUT | no passive frame stream on a TAP you are mastering |
| `inject` | GATED OUT | a raw "frame" is meaningless; you issue IR/DR transactions |
| `replay` | GATED OUT | nothing to replay; no pcap capture verb exists for JTAG |

Asking for a gated verb -> `ProbeError` (rule 2), e.g.
`probe: 'sniff' is not supported on protocol 'jtag' (supported: scan, jtag)`.

Protocol verbs (group `jtag`), each routed through `Backend.op`:

| CLI | op verb | args | returns |
|---|---|---|---|
| `probe jtag scan-chain` | `jtag.scan_chain` | - | `{taps:[{index, idcode, irlen, name}]}` |
| `probe jtag idcode` | `jtag.idcode` | `tap?` (default 0) | `{idcode, manufacturer, part, version, name}` |
| `probe jtag halt` | `jtag.halt` | `tap?` | `{state:"halted", pc?}` |
| `probe jtag resume` | `jtag.resume` | `tap?`, `addr?` | `{state:"running"}` |
| `probe jtag read` | `jtag.read` | `addr` (int), `words?` (default 1) | `{addr, words:[u32,...]}` |
| `probe jtag write` | `jtag.write` | `addr` (int), `word` (u32) | `{ok:bool, addr}` |
| `probe jtag reg` | `jtag.reg` | `name?` | `{regs:{name:value}}` or `{name, value}` |
| `probe jtag dump` | (built on `jtag.read`) | `addr`, `len`, `-w out.bin` | writes binary, returns `{bytes}` |

`probe scan` and `probe jtag scan-chain` are aliases of the same enumeration so the generic
core verb and the protocol verb both work; `scan` returns the `taps` list flattened into the
generic `scan` row shape (`{name, addr=idcode, index}`).

`dump` is protocol-layer sugar (contract item C3): a bounded loop of `jtag.read` that the
client writes straight to a binary file. The client MUST cap `len` (refuse a dump larger
than a configurable ceiling, default 16 MiB, with `ProbeError`) so a hostile/buggy backend
cannot drive an unbounded read.

## 3. `capabilities()` shape

```python
Capabilities(
    protocol="jtag",
    transport="virtual",           # later "openocd"
    channels=[],                   # JTAG has no channels; empty
    verbs=["scan", "jtag"],        # NOTE: no sniff/inject/replay
    meta={
        "shape": "transaction",    # contract item C2
        "taps": 1,                 # advertised chain length
        "irlen": [4],              # per-TAP IR length
        "endian": "little",
        "word_bits": 32,
    },
)
```

`verbs` deliberately omits `sniff`, `inject`, `replay`. That omission IS the gate.

## 4. DLT and capture representation

JTAG has NO standard pcap DLT and no capture verb, so by default it emits NO pcap.

Primary artifact: `probe jtag dump` writes a RAW BINARY image of the memory range (exactly
like `dump_image`), which is what the operator actually wants for firmware extraction. The
transaction log (each `jtag.read`/`write`) is printed to stdout / available as JSON for
scripting.

Optional secondary artifact: a transaction pcap under `DLT_USER_PROBE_JTAG = 149` for
operators who want one container of the session. Record layout (one pcap record per
transaction), all multi-byte fields little-endian:

```
offset  size  field
0       1     op        (1=scan_chain 2=idcode 3=halt 4=resume 5=read 6=write 7=reg)
1       1     tap
2       2     flags     (bit0 = response, bit1 = error)
4       4     addr      (read/write; 0 otherwise)
8       4     value     (write value / first read word / idcode)
12      2     count     (words for read; 0 otherwise)
14      2     payload_len
16      ...   payload   (read words u32[] LE, or reg blob, or scan-chain idcodes)
```

This is OPTIONAL and OFF by default (`probe jtag dump --pcap session.pcap` opts in). The raw
binary image is the default and primary output. Do not emit an empty/garbage standard-DLT
pcap.

## 5. What a virtual target must simulate

A virtual target exposes a small TAP model:

- a scan chain: a list of TAPs, each with `idcode` (u32), `irlen`, optional `name`.
- a flat memory map: address -> word, with regions (rom/sram/mmio) and per-region
  read/write permission. Reads outside a mapped region return a defined fill (e.g.
  `0xFFFFFFFF`) or raise a transaction error.
- core state: `running` / `halted`; `halt` is required before `read`/`reg` (a target can
  model a locked core that refuses `halt`, i.e. a DAP-lock / RDP scenario).
- gated regions: a region that only becomes readable after the correct steps (e.g.
  halt -> write an unlock word to an MMIO register -> read the now-mapped region), so the
  target can model a protected-memory unlock. Delivered over the wire as the read result.
  This mirrors the BLE "write to unlock then read" pattern.

Backend hooks a virtual target implements (all via the existing `OP` message):

```
on_op("jtag.scan_chain") -> {taps:[...]}
on_op("jtag.idcode", tap) -> {...}
on_op("jtag.halt", tap)   -> {state, pc?}
on_op("jtag.resume", ...) -> {state}
on_op("jtag.read", addr, words) -> {addr, words:[...]}   # enforce region perms + halted
on_op("jtag.write", addr, word) -> {ok, addr}            # may mutate unlock state
on_op("jtag.reg", name?) -> {...}
```

Same-commands-transfer note: the identical `probe jtag *` commands later run against the
`openocd` real backend, which maps `jtag.read` -> `mdw`, `jtag.write` -> `mww`,
`jtag.halt` -> `halt`, `jtag.scan_chain` -> OpenOCD `scan_chain`, `jtag.dump` ->
`dump_image`. The protocol module and CLI do not change; only the backend swaps. The TAP
model the virtual backend simulates is the same surface OpenOCD exposes, so a workflow
validated virtually transfers to a real J-Link/FT2232 target.

## 6. Contract-evolution items touched

- C1 (`ProbeError` + `_require_verb` gate) - needed so the three gated core verbs fail clean.
- C2 (`Capabilities.shape`) - JTAG sets `shape="transaction"`.
- C3 (`protocols/jtag.py::dump` sugar over `op("jtag.read")`) - new protocol-layer helper.
- No new Backend method, no new wire message type. `op()` carries every JTAG transaction.
