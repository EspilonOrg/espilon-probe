# Protocol: CAN

**Status:** shape `packet`. Both backends work today: the `virtual` backend and the real
`socketcan` backend (a Linux vcan loopback, or a real bus via a SocketCAN adapter).

Read `../protocol-conventions.md` first. This doc specifies `protocols/can.py` and what a virtual
backend must simulate; the same `probe can`/`sniff`/`inject`/`replay` commands drive the real
`socketcan` backend unchanged.

## 1. What it models

An operator on a CAN bus (SocketCAN, a USB-CAN adapter, `cansend`/`candump`, an OBD / UDS session
against an ECU):

- sniff the bus to a pcap,
- inject a crafted frame,
- replay captured frames,
- send / dump with CAN-native sugar.

A CAN frame is a discrete, self-delimited bus unit (arbitration id + DLC), so the physical layer
defines the boundary -> PACKET. The bridge is a byte mover. Higher-layer state (an ISO-TP transport,
a UDS session / security-access state machine) is NOT in the client or the bridge; it lives in the
target device model, exactly as it lives in a real ECU.

Tradecraft mapping:

| Real tool | probe verb |
|---|---|
| `candump vcan0` | `probe sniff -w cap.pcap` / `probe can dump -w cap.pcap` |
| `cansend vcan0 7E0#0210...` | `probe inject --hex ...` / `probe can send 7E0 0210...` |
| replay a capture | `probe replay -r cap.pcap` |

## 2. Shape and verb set

Shape: PACKET. `capabilities.shape == "packet"`. All four core verbs apply, BOUNDED per
`protocol-conventions.md` rule 4.

Core verbs:

| Core verb | CAN | Notes |
|---|---|---|
| `scan` | OFFERED | enumerate the arbitration ids seen on the bus |
| `sniff` | OFFERED, BOUNDED | frames -> pcap; client enforces count / seconds / timeout |
| `inject` | OFFERED | transmit one 16-byte SocketCAN frame |
| `replay` | OFFERED | re-transmit captured frames; DLT-vs-session validated |

No core verb is gated out.

Protocol verbs (group `can`) are sugar over the core verbs, so the same behaviour runs against the
virtual and `socketcan` backends:

| CLI | maps to | args | returns |
|---|---|---|---|
| `probe can send` | `inject` | `id` (hex), `data` (hex) | `{ok}` |
| `probe can dump` | `sniff` | `-w cap.pcap`, `count?`, `seconds?` | frame count |

`can send <id> <data>` builds a 16-byte SocketCAN frame and injects it; `can dump -w` captures to a
pcap. The CLI records that `send -> inject` and `dump -> sniff` so the verb gate applies to the
sugar too.

## 3. Frame codec

`protocols/can.py` `encode_frame`/`decode_frame` is the classic-CAN codec shared by the client and
the socketcan path (the dual-purpose proof). On-wire and in the pcap, a frame is the classic 16-byte
SocketCAN `struct can_frame`, little-endian:

```
offset  size  field
0       4     can_id      (arbitration id | EFF/RTR flag bits)
4       1     dlc         (data length, 0..8)
5       3     padding
8       8     data        (dlc bytes, zero-padded)
```

- 11-bit (SFF) and 29-bit (EFF) ids; `CAN_EFF_FLAG` set for extended, `CAN_RTR_FLAG` for remote.
- DLC is the 4-bit data length; classic CAN requires 0..8, and the codec rejects a larger value
  rather than silently truncating.
- `decode_frame` accepts exactly 16 bytes and refuses a buffer that is not a whole frame, rather
  than reading past or truncating trailing bytes.

## 4. DLT and capture representation

Captures use `DLT_CAN_SOCKETCAN` (227), so a pcap dissects as CAN in tshark/wireshark with no
custom dissector. `replay` validates the capture's DLT against the active protocol and refuses a
non-CAN pcap with `ProbeError` (rule 5).

## 5. What a virtual target must simulate

A virtual target exposes a bus / ECU model:

- a set of nodes emitting frames on given arbitration ids (the server pushes these as `FRAME`
  during a `sniff`); `scan` reports which ids are active.
- a receiver for `inject`/`replay`: a frame addressed to a node drives that node's state.
- higher-layer behaviour (ISO-TP reassembly, a UDS session -> seed -> key -> DID exchange with its
  negative-response codes and retry lockout) lives in the device model, not the CAN codec. A gated
  value reaches the wire only after its unlocking exchange, delivered over the bus as the response.

Same-commands-transfer note: the identical `probe can`/`sniff`/`inject`/`replay` commands run
against the real `socketcan` backend (`probe-bridge --medium socketcan --endpoint vcan0`), which
binds a `PF_CAN` raw socket and relays frames verbatim. The codec and CLI are unchanged; only the
backend swaps. Because vcan is a kernel loopback, a workflow validated virtually transfers to a real
bus with no hardware in between.

## 6. Contract items touched

- `Capabilities.shape` - CAN sets `shape="packet"`.
- The shared `encode_frame`/`decode_frame` codec, used by both backends.
- `replay` DLT-vs-session validation (must reject a non-227 pcap).
- The sniff client-bound (rule 4).
- No new Backend method and no new wire message type: `sniff`/`inject`/`replay` cover CAN; there is
  no `op` group.
