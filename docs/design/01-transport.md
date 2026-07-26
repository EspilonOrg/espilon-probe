# 01 - The TCP tunnel: handshake, two payload shapes, the raw-stream seam

Status: spec, governed by `00-architecture.md`. Grounded in `core/wire.py`,
`backends/virtual.py`, and `espilon_probe_bridge/server.py` as they stand.

This document specifies the single wire tunnel every `probe` connection speaks: the framed
handshake, capability/baud/param negotiation, the two payload shapes (FRAMED and RAW-STREAM),
the one-way upgrade seam that turns a stream connection raw, half-close/EOF, and `sniff` per
shape. It states exactly what changes versus today's framed-JSON wire.

The tunnel is the ONLY coupling between the client and any bridge (decision: `core/wire.py` is
the shared contract; the bridge imports it, so the two sides cannot drift). Nothing below this
document is a second protocol; the raw regime is *defined in* the wire, not a side channel.

---

## 1. The wire, as it is today (baseline)

`core/wire.py` is length-prefixed JSON: each message is `[4-byte big-endian length][UTF-8 JSON
object]`, the object always carries a `"t"` type field, raw PDUs travel hex-encoded in
`raw`/`frame`/`data` fields. `MAX_MSG` is 8 MiB. The message set:

| Type | Direction | Body |
|---|---|---|
| `HELLO` | client -> bridge | `{version, config}` (config carries `{"baud": N}` today) |
| `WELCOME` | bridge -> client | `{version, capabilities}` |
| `SCAN` / `SCAN_RESULT` | c->b / b->c | `{}` / `{items:[...]}` |
| `OP` / `OP_RESULT` | c->b / b->c | `{verb, args}` / `{result}` |
| `INJECT` / `ACK` | c->b / b->c | `{frame, channel}` / `{}` |
| `REPLAY` / `REPLAYED` | c->b / b->c | `{frames:[hex], filter}` / `{count}` |
| `SNIFF` / `FRAME` / `SNIFF_END` | c->b / b->c / b->c | `{count, seconds, channel}` / `Frame` / `{count}` |
| `ERROR` | either | `{msg}` |

`capabilities` is `{protocol, channels, verbs, shape, meta}` where `meta` carries `pcap_dlt`,
band tables, chip-selects, etc. The client caches it from `WELCOME` and the CLI gates every verb
against `capabilities.verbs` (`protocol-conventions.md` rule 1).

This is the **FRAMED** shape. It already carries semantic ops (`OP` = `gatt.read` / `jtag.read`
/ `spi.read` / `uart.*`) and frame relay (`INJECT`/`SNIFF`/`REPLAY`). It stays exactly as-is for
every FRAMED protocol. The only additions this corpus makes are the two control messages for the
RAW-STREAM upgrade (section 3) and one clarifying convention on `OP` args (section 6).

---

## 2. Negotiation: protocol + shape + capabilities + baud/params

Negotiation is the existing `HELLO` -> `WELCOME` exchange, unchanged in mechanics. What the
handshake settles, made explicit:

- **protocol** - `capabilities.protocol` (`"uart"`, `"can"`, `"ble"`, ...). Drives the client's
  codec selection and `probe info`.
- **shape** - `capabilities.shape` in `{"packet", "stream", "transaction"}`. This is the
  semantic shape (`protocol-conventions.md` rule 3). The **transport shape** (FRAMED vs
  RAW-STREAM) is *derived* from it, not carried as a separate field:

  > `shape == "stream"` -> RAW-STREAM transport. `shape in {"packet","transaction"}` -> FRAMED
  > transport.

  Recommendation (`00` section 8): derive, do not add a `transport_shape` field, so there is
  nothing new to keep in sync. A future exotic case that needs an explicit override can add the
  field then; nothing today needs it.
- **capabilities** - `verbs`, `channels`, `meta` (pcap DLT, bands, chip-selects, max transfer,
  flash geometry). The CLI reads these to gate verbs and format output.
- **baud / link params** - the client declares link settings in `HELLO.config`. Today that is
  `{"baud": N}` (consumed by the UART garble model). The field is a free dict, so a future
  medium adds its params here (`{"spi_mode": 0}`, `{"can_bitrate": 500000}`) without a wire
  change. The bridge reads them via `on_client_config` **before serving any verb**, so a
  baud-aware protocol garbles from the first read.

Negotiation carries **no per-byte tagging** and no framing metadata on a data path. For a stream
protocol the data path is pure bytes (section 3); everything the client needs to know about the
line is settled in this framed pre-upgrade phase.

---

## 3. The RAW-STREAM shape and its upgrade seam

A stream protocol (UART, and any future console-like line) is a continuous octet flow whose
message boundaries are an application convention, not a transport fact. Forcing it through
`OP`/`OP_RESULT` hex transactions emulates an async line over a synchronous RPC; the corpus
deletes that emulation and uses a real byte pipe.

### Establishment (two phases; first framed, then raw)

A stream connection is established framed, then upgraded once to raw:

1. **TCP connect** to the bridge (`--target` / `ESP_PROBE`, or the loopback port of an
   auto-spawned bridge; `02`).
2. **Framed handshake:** `HELLO` (with `config`) -> `WELCOME` (with `capabilities`,
   `shape="stream"`). Cache caps. This is identical to every other protocol and is the *only*
   framed exchange on a stream connection.
3. **Upgrade to raw, lazily, only when a stream *data* verb runs** (`uart read` / `uart write`
   / `uart sniff`): the client sends `STREAM_ATTACH` (framed, control-only, no data), the bridge
   replies `STREAM_READY` (framed), and **from the byte after `STREAM_READY` both directions are
   raw bytes.** No length prefix, no JSON, no `Frame` on that socket ever again.

Control verbs never go raw: `probe info` and `probe scan` run entirely in the framed pre-upgrade
phase (handshake, read caps or send `SCAN`, close), so they still know the protocol, its shape,
and its verbs without the data path ever carrying a message. Each `probe` invocation is one
short-lived connection running one verb; the upgrade is per-connection.

### The two new control messages (the entire wire delta)

Add to `core/wire.py`:

```
STREAM_ATTACH = "stream_attach"   # client -> bridge   {t}            control-only, no data
STREAM_READY  = "stream_ready"    # bridge -> client   {t}            after this: raw bytes
```

plus their small constructors, and a documented note: **after `STREAM_READY` the socket carries
raw bytes; the length-prefix codec no longer applies to that connection.** `Frame` and the FRAMED
codec are untouched. This is the one honest structural change: the "one uniform wire" property now
has a documented, in-contract, one-way seam. Small in code, load-bearing in design.

### Why lazy per-verb, not "socket goes raw at WELCOME"

Considered and rejected: `WELCOME` declares `shape=stream` and the socket goes raw immediately.
Simpler on the wire, but it loses framed `info`/`scan` coexistence on the same short-lived
connection (you would need a separate framed connection just to read caps). Lazy upgrade keeps
one connection able to do `info`, `scan`, OR a raw data verb, deciding at the first data verb.
The cost is the two control messages, which are trivial. Keep lazy.

### The client stream surface

`core/backend.py` gains two **concrete** methods (not abstract), defaulting to a clean refusal so
FRAMED backends inherit the refusal for free and only the tunnel/stream backend overrides them:

```
def stream_write(self, data: bytes) -> int:
    """Send raw bytes on the pipe. Returns the count written."""
    raise ProbeError("this protocol is not a byte stream")

def stream_read(self, timeout: float) -> bytes:
    """Receive from the pipe, blocking up to `timeout` for the FIRST byte, then draining
    until the line is idle for one inter-byte gap. Empty result on a silent line is not
    an error."""
    raise ProbeError("this protocol is not a byte stream")
```

Read semantics (pyserial-faithful, transport-independent): block up to `timeout` for the first
byte, then drain until one inter-byte idle gap elapses, then return everything accumulated.
`-t 0` = non-blocking poll (return whatever is buffered). Shared constants in one home so the
loopback serial bridge and the virtual bridge cannot drift:

- `UART_READ_TIMEOUT_DEFAULT = 1.0`
- `UART_READ_IDLE_GAP ~= 0.1` (how "the line went quiet" is decided; not player-facing).

The CLI adds `-t/--timeout` (float, default `1.0`) to `uart read`, routes `uart read`/`write` to
`stream_read`/`stream_write`, prints `wrote N byte(s)` from the returned count. Gate stays the
existing `uart`-in-`caps.verbs` check; optionally also assert `caps.shape == "stream"` for stream
verbs. Full step list in `../protocols/uart.md`.

---

## 4. Half-close and EOF

FRAMED: unchanged. `wire.decode` returns `None` on a clean EOF at a message boundary and raises
`ProtocolError("unexpected EOF mid-message")` on a truncated one. The client bounds every
control-path recv by a total deadline (`ESP_PROBE_TIMEOUT`, default 30s; `virtual.py`), and
`sniff` carries its own client-side capture budget, so a silent or dribbling bridge can never
hang the client. The bridge sends exactly one `SNIFF_END` to terminate a capture; the client
drains it to stay aligned on a persistent connection.

RAW-STREAM: after `STREAM_READY`, the pipe follows ordinary socket EOF. `recv` returning `b""` is
end-of-input on that direction; the bridge pump drains any remaining device output, then closes
(`02` specifies the pump). The client's stream `recv` is bounded by the player's `-t` (the first
byte wait) and then the idle-gap drain, never the flat control-path timeout - a `uart read -t 60`
must be allowed its 60 seconds without tripping the "target went silent" guard. Because probe runs
one verb per process, `uart write` and a later `uart read` are separate connections; a raw
socket's OS buffer does not persist across close, so line state that must survive between the two
discrete verbs lives device-side in the `Console` model (a plain FIFO, not a scheduler), and
the property "the OS buffer is the RX/TX buffer" is fully realized only in the future persistent
`probe uart console` session (out of scope here; the transport is designed so it composes on top
with no further wire change).

---

## 5. `sniff` per shape

- **FRAMED packet protocols (CAN, BLE, sub-GHz, Zigbee):** `sniff` is the existing
  `SNIFF`/`FRAME`/`SNIFF_END` capture to a pcap under the protocol's `pcap_dlt`, bounded entirely
  client-side (`protocol-conventions.md` rule 4). Unchanged.
- **FRAMED transaction protocols (JTAG, SPI):** `sniff` is **gated OUT** (a master does not
  passively sniff its own transactions). The optional transaction pcap under `DLT_USER_PROBE_*`
  is produced by `dump --pcap`, not by `sniff`. Unchanged.
- **RAW-STREAM (UART):** `sniff` is **redefined** as a byte-log tee of the raw pipe with
  per-record direction (TX = bytes the client sends, RX = bytes it receives). For a passive
  `sniff` the client only reads, so every record is RX. Use `LINKTYPE_RTAC_SERIAL` (DLT 250),
  which Wireshark's `rtacser` dissects out of the box with a direction flag and a per-record
  timestamp in a small pseudo-header. The stream pcap writer is **distinct** from the packet
  `PcapWriter` (`core/frame.py`): each record is a chunk of stream bytes with a direction, not a
  protocol `Frame`. Lift the RTAC pseudo-header layout from the Wireshark source at implementation
  time (`wiretap/rtac_serial.c` / `packet-rtacser.c`); do not hand-guess offsets, and unit-test
  that a produced capture opens in `tshark -r` with the right direction. Register DLT 250 in
  `protocol-conventions.md` rule 5. This is deferrable with UART `sniff` itself (not needed for
  the `read`/`write` pilot).

---

## 6. One clarifying `OP`-args convention (no message change)

For an `op` whose result may legitimately take a while (a stream-adjacent read carrying a
`timeout`, a long dump), the client bounds that op's reply recv by
`max(control_timeout, timeout + margin)` **when the op's args carry a numeric `timeout`**. This
is verb-agnostic (it reads a well-known arg name, encodes no challenge knowledge) and lives in the
tunnel backend. Under RAW-STREAM this is moot for UART reads (they run on the raw pipe, not
`OP`), but the convention stays for any FRAMED op that declares a `timeout`. No new message type;
`OP`/`OP_RESULT` already carry arbitrary `{verb, args}` / `{result}`.

---

## 7. What changes vs today's framed-JSON wire (summary)

| Piece | Change | Size |
|---|---|---|
| `core/wire.py` | add `STREAM_ATTACH` / `STREAM_READY` + constructors + document the raw seam | S in code, load-bearing in design |
| FRAMED codec (`encode`/`decode`/`Frame`) | **none** | - |
| `core/backend.py` | add concrete `stream_read`/`stream_write` (default: refuse); define the two shared UART constants | S |
| tunnel backend (`backends/virtual.py` -> `tunnel.py`) | add lazy `_attach_stream`; implement `stream_read`/`stream_write` (raw sendall / recv-first-then-idle-drain); stream `sniff` tee | M |
| capability negotiation | derive transport shape from `shape`; carry link params in `HELLO.config` (already a free dict) | S |
| CLI | `uart read -t`; route stream verbs to `stream_*`; `wrote N byte(s)` | S |

The FRAMED path for every packet/transaction protocol is byte-identical to today. The RAW-STREAM
path is new but confined to the tunnel backend and the two control messages. This is the whole
transport delta the pilots build against.
