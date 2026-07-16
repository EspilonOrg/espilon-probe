# Protocol: BLE

**Status:** shape `packet` + `op`. The `virtual` backend works today; the real `hci` (Linux
BlueZ) backend is not built yet.

Read `../protocol-conventions.md` first. This doc specifies `protocols/ble.py` and what a virtual
backend must simulate; the same `probe gatt`/`sniff`/`inject`/`replay` commands are designed to
drive the future `hci` backend unchanged.

## 1. What it models

BLE spans two surfaces in one protocol:

- a **relay surface** - `scan`/`sniff`/`inject`/`replay` of raw advertising / Link-Layer PDUs. One
  wire frame is one radio PDU.
- a **stack surface** - `gatt enum`/`read`/`write` over `op()`. A GATT operation is NOT one PDU: on
  real hardware it is connect, MTU exchange, ATT read/write (with Read Blob for long values), and
  error mapping. The stack runs on the server / bridge side.

An operator with a BLE sniffer and a GATT client:

- scan for advertisers, sniff advertising / LL PDUs to a pcap,
- enumerate a peripheral's services and characteristics,
- read / write a characteristic (including a write-to-unlock-then-read flow).

Tradecraft mapping:

| Real tool | probe verb |
|---|---|
| `hcitool lescan` / sniffer capture | `probe scan` / `probe sniff -w cap.pcap` |
| `gatttool --characteristics` | `probe gatt enum` |
| `gatttool --char-read` | `probe gatt read --handle H` |
| `gatttool --char-write-req` | `probe gatt write --handle H --hex ...` |

## 2. Shape and verb set

Shape: PACKET on the relay surface, `op`-routed on the stack surface.

Core verbs:

| Core verb | BLE | Notes |
|---|---|---|
| `scan` | OFFERED | enumerate advertisers |
| `sniff` | OFFERED, BOUNDED | advertising / LL PDUs -> pcap; client enforces count / seconds |
| `inject` | OFFERED | transmit a raw PDU |
| `replay` | OFFERED | re-transmit captured PDUs; DLT-vs-session validated |

Protocol verbs (group `gatt`), routed through `Backend.op`:

| CLI | op verb | args | returns |
|---|---|---|---|
| `probe gatt enum` | `gatt.enum` | - | `{services:[...], characteristics:[{handle, uuid, props}]}` |
| `probe gatt read` | `gatt.read` | `handle` | `{value}` (hex) or `{error}` (ATT code) |
| `probe gatt write` | `gatt.write` | `handle`, `value` (hex) | `{ok}` or `{error}` (ATT code) |

An op that the peripheral refuses returns an ATT error code, which the CLI renders deterministically
(the way UDS renders a negative-response code) so the error path is comparable. The named codes are
in `protocols/ble.py::ATT_ERRORS` (e.g. `0x02` Read Not Permitted, `0x03` Write Not Permitted,
`0x05` Insufficient Authentication, `0x0A` Attribute Not Found).

## 3. DLT and capture representation

Sniff/replay use `DLT_BLUETOOTH_LE_LL_WITH_PHDR` (256), so a pcap opens cleanly in
wireshark/tshark. A frame under DLT 256 must carry the FULL layering that link type requires - LE
pseudo-header + Link Layer data PDU + L2CAP + ATT - not a bare ATT PDU. `unlock_write_frame` builds
exactly that, so a captured write dissects as `btatt.opcode == 0x12`; a bare ATT PDU under DLT 256
does NOT dissect. `replay` validates the capture DLT against the active protocol and refuses a
non-BLE pcap with `ProbeError` (rule 5).

## 4. What a virtual target must simulate

A virtual target exposes a peripheral model:

- an advertising set: `AdvA` + AD structures (flags, names, manufacturer data), built and parsed
  faithfully, so `scan`/`sniff` see well-formed advertising PDUs.
- a GATT attribute table: handles -> `{uuid, props}`, with read/write branches and the ATT
  error-code table, so a write to a read-only characteristic returns `0x03`, not a guess. A
  reference `GattServer` owns the discovery handle layout (declaration + value + CCCD handles), the
  MTU, and read-blob fragmentation, so a target declares only its attribute table and the layout /
  error codes become correct by construction.
- a gated value: a characteristic that only becomes readable after the correct write (write-to-
  unlock, then read), delivered over the wire as the read result.

Same-commands-transfer note: the identical `probe gatt`/`sniff`/`inject`/`replay` commands are meant
to run against the real `hci` backend (a `probe-bridge --medium hci` over BlueZ: HCI socket /
D-Bus), which relays raw PDUs for scan/sniff/inject and drives the BlueZ GATT client (connect, MTU,
ATT read/write, error mapping) for the `gatt.*` ops. The protocol module and CLI do not change; only
the backend swaps. SMP / pairing (real ECDH / AES-CMAC) is a separate, harder model, scoped only
when an objective is pairing.

## 5. Contract items touched

- `Capabilities.shape` - BLE uses the packet shape plus `op`-routed `gatt` verbs.
- `op()` carries every GATT transaction; the ATT error path renders deterministically.
- `replay` DLT-vs-session validation (must reject a non-256 pcap) and the full DLT-256 layering.
- The sniff client-bound (rule 4).
- No new Backend method and no new wire message type: `sniff`/`inject`/`replay`/`op` cover BLE.
