# Protocol design conventions (cross-cutting)

Shared rules every protocol module must obey. All seven protocols (BLE, CAN, UART, Zigbee,
JTAG, SPI, sub-GHz) follow these. Read this before the per-protocol docs
(`protocol-jtag.md`, `protocol-spi.md`, `protocol-subghz.md`).

## 1. `capabilities()` is the gate

`capabilities().verbs` is the single source of truth for what a protocol offers. The CLI
MUST consult it before dispatching any verb and hard-error clean if the verb is absent.
There is no implicit "all core verbs always work" rule: a protocol that is not packet
oriented does not advertise `sniff`/`replay`, and asking for them is a clean error, not a
traceback.

`verbs` lists both core verbs (`scan`, `sniff`, `inject`, `replay`) and protocol verbs
(`jtag`, `spi`, `subghz`, ...) that the protocol actually supports. `info` already prints
`verbs`; that print is now also contractual (it is the operator-visible gate).

Protocol verbs are addressed in `capabilities().verbs` by their TOP-LEVEL group name only
(e.g. `jtag`, `spi`, `subghz`), matching how `gatt` and `can` appear today. The sub-command
set (`jtag idcode`, `jtag dump`, ...) is fixed by the protocol module and the CLI parser;
the backend does not need to enumerate every sub-verb in `verbs`.

## 2. One clean error type: `ProbeError`

Shared error type in `core/` (see contract-evolution below):

```python
# core/errors.py
class ProbeError(Exception):
    """Operator-facing, expected failure. The CLI prints `probe: {msg}` and exits non-zero.
    Never a traceback. Used for: unsupported verb on this protocol, malformed argument that
    only the protocol layer can judge, a target/transaction-level refusal."""
```

The CLI catch list becomes `(ProbeError, RuntimeError, OSError, ValueError)`. The
"verb is meaningless on this protocol" case raises `ProbeError` with a message of the form:

```
probe: 'sniff' is not supported on protocol 'jtag' (supported: scan, jtag)
```

`ProbeError` is distinct from `wire.ProtocolError` (a wire-framing fault, lower layer). A
wire fault may be wrapped into a `ProbeError` for presentation, but they are not the same
type.

Gating mechanism (where the check lives): the CLI, in `_dispatch`, looks up the verb against
`backend.capabilities().verbs` BEFORE routing. A single helper:

```python
def _require_verb(caps, verb):           # cli.py
    if verb not in caps.verbs:
        raise ProbeError(f"'{verb}' is not supported on protocol "
                         f"'{caps.protocol}' (supported: {', '.join(caps.verbs)})")
```

This keeps the gate in ONE place and out of every backend. Backends still refuse defensively
(an `op()` for an unknown verb returns/raises a clean error), but the CLI gate is the
primary, content-agnostic guard.

## 3. Shape taxonomy: PACKET vs BYTE-STREAM vs TRANSACTION/REGISTER

Every protocol declares exactly one primary shape. The shape decides which core verbs are
meaningful:

| Shape | Core verbs that apply | Core verbs gated OUT | Examples |
|---|---|---|---|
| PACKET (radio/bus) | scan, sniff, inject, replay | (none) | BLE, Zigbee, CAN, sub-GHz |
| BYTE-STREAM | (none of the four) + protocol verbs | scan, sniff, inject, replay | UART |
| TRANSACTION/REGISTER | scan (as bus enumerate, optional) + protocol verbs | sniff, replay, (usually inject) | JTAG, SPI, I2C |

Rationale for the new three:

- sub-GHz IS a radio: PACKET. All four core verbs apply, BOUNDED (see rule 4).
- JTAG is a TAP state machine driven by request/response transactions. It is NOT
  packet-sniffable in the radio sense. `sniff`/`replay` are gated OUT. `inject` is gated
  OUT (a raw "frame" has no meaning; you issue scan-chain/IR/DR transactions instead).
  `scan` is repurposed as bus enumeration (scan-chain / IDCODE discovery) and IS offered.
- SPI is master-driven full-duplex transactions. Also TRANSACTION/REGISTER. `sniff`/`replay`
  gated OUT by default (a probe acting as SPI MASTER does not passively sniff its own bus;
  passive bus-sniffing is a different, real but separate, hardware mode and is NOT modeled in
  v1). `inject` gated OUT. `scan` repurposed as device/JEDEC-ID enumeration and IS offered.

Do NOT bolt the four core verbs onto JTAG/SPI to look uniform. Uniformity is in the
contract and the `op()` carrier, not in pretending a flash chip is a radio.

## 4. The tool bounds every receive (client-side)

Any capture/sniff verb MUST terminate on a client-enforced bound. The client passes
`count`/`seconds` to the backend AND independently stops reading when EITHER is reached,
plus a hard wall-clock `timeout`. A backend that never sends `SNIFF_END` must not hang the
client.

Mandatory rule for sub-GHz (the only new protocol with sniff):

- At least one of `count` or `seconds` MUST be provided; if neither is given the CLI
  supplies a default ceiling (`seconds = 30.0`) rather than capturing unbounded. State this
  default in `info`/help.
- The client loop stops at `frames_read >= count` OR `now - start >= seconds` OR
  `now - start >= timeout` (timeout = `seconds + 5s` guard, or a fixed `60s` if only
  `count` was given). Whichever fires first wins; the client then sends a stop and stops
  reading regardless of further server frames.

This is the bound the existing `sniff` fails to enforce. New protocols must not repeat it.

## 5. pcap DLT is first-class

Each PACKET protocol declares a `PCAP_DLT` and the emitted `Frame.raw` bytes MUST actually
layer for that DLT (so the capture dissects in stock tools). TRANSACTION/REGISTER protocols
do NOT emit a pcap from a capture verb (they have no capture verb); their transaction
records are dumped to a deliberate artifact instead (see each doc).

`replay` MUST validate the input pcap's DLT against the active protocol's `PCAP_DLT` and
refuse with `ProbeError` on mismatch (you cannot replay an 802.15.4 capture onto a sub-GHz
link). This check is added to the `replay` path generally.

### DLT_USER allocation (probe-wide registry)

There is no standard pcap linktype for JTAG, SPI, or a raw sub-GHz symbol/packet envelope
that carries our metadata. We allocate from the `LINKTYPE_USER` range (147..162,
`DLT_USER0..DLT_USER15`), which is the libpcap-sanctioned space for private link types.
Allocations are recorded HERE so the two sides and the docs never drift:

| DLT value | Name (this project) | Used by | Layered payload |
|---|---|---|---|
| 147 (USER0) | `DLT_USER_PROBE_SUBGHZ` | sub-GHz capture | 8-byte probe sub-GHz pseudo-header + raw demod payload |
| 148 (USER1) | `DLT_USER_PROBE_SPI` | SPI transaction dump (optional pcap form) | SPI transaction record (see spi doc) |
| 149 (USER2) | `DLT_USER_PROBE_JTAG` | JTAG transaction dump (optional pcap form) | JTAG transaction record (see jtag doc) |
| 150..162 | reserved | future (I2C, SWD, ...) | - |

DLT_USER carries no globally-registered dissector, so a stock tshark will show these as
raw `USERn` bytes unless the operator loads a profile/Lua. That is acceptable and honest:
for the TRANSACTION protocols the primary artifact is a human/JSON transaction log
(see each doc), and the DLT_USER pcap is an OPTIONAL secondary form for operators who want
one container. For sub-GHz the pseudo-header is documented so a trivial Lua dissector or
`scapy` reader can decode it; we ship the layout, not a dissector.

## 6. `op()` is the transaction carrier; no new core method needed

The Backend contract already has `op(verb, **kwargs) -> dict`, used today by BLE `gatt.*`
and UART `uart.*`. JTAG and SPI transactions are exactly this: a named request with args, a
structured dict response. They route through `op()` over the existing wire `OP`/`OP_RESULT`
messages. NO new contract method (no `transaction()`), NO new wire message type is required
for JTAG/SPI to function.

What IS needed (contract-evolution items, none are blockers for a first target):

- C1. Add `core/errors.py::ProbeError` and wire the CLI catch + `_require_verb` gate (rule 2).
- C2. Add a `shape` field to `Capabilities` (`"packet" | "stream" | "transaction"`) so the
  CLI and `info` can reason about a protocol generically instead of hard-coding verb lists.
  Defaulted to `"packet"` for backward compatibility with the existing four.
- C3. Add an OPTIONAL `dump(out_path, fmt) -> int` convenience at the protocol layer for the
  transaction protocols (JTAG memory dump, SPI flash dump). This is sugar built ON TOP of
  `op()` (a loop of `op("spi.read", ...)`), NOT a new Backend method. It lives in
  `protocols/spi.py` / `protocols/jtag.py`, mirroring `can.dump`.
- C4. `replay` DLT-vs-session validation (rule 5) belongs in the shared replay path, not per
  protocol.

These are the only contract touch-points. The wire protocol (`core/wire.py`) is unchanged:
`OP`/`OP_RESULT` already carry arbitrary `{verb, args}` / `{result}`, which is all the
transaction protocols need.
