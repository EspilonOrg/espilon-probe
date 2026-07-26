# Protocol: Zigbee / 802.15.4

**Status:** shape `packet`. The `virtual` backend works today, but it builds structurally shaped
frames only (see section 4), not cryptographically valid ones; the real `killerbee` backend is not
built yet.

Read `../protocol-conventions.md` first. This doc specifies `protocols/zigbee.py` and what a virtual
backend must simulate; the same `probe scan`/`sniff`/`inject`/`replay` commands are designed to
drive the future `killerbee` backend unchanged.

## 1. What it models

An operator with an 802.15.4 sniffer (ApiMote / CC2531) working Zigbee traffic:

- scan for active channels / nodes,
- sniff 802.15.4 PDUs to a pcap,
- inject a crafted frame,
- replay captured frames.

This is a pure PACKET protocol with NO protocol verb group: analysis of the capture stays in the
operator's stock tools (`zbdsniff`, tshark with the `zigbee_pc_keys` store). The core verbs carry
raw 802.15.4 PDUs unchanged; frame layering is the target server's responsibility.

Tradecraft mapping:

| Real tool | probe verb |
|---|---|
| `killerbee zbdump` capture | `probe sniff -w cap.pcap` |
| replay a capture | `probe replay -r cap.pcap` |
| inject a crafted frame | `probe inject --hex ...` |
| `zbdsniff` / tshark decode | (operator's own tools, on the pcap) |

## 2. Shape and verb set

Shape: PACKET. `capabilities.shape == "packet"`. Core `scan`/`sniff`/`inject`/`replay` only; there
is no `op` group.

Core verbs:

| Core verb | Zigbee | Notes |
|---|---|---|
| `scan` | OFFERED | enumerate active channels / nodes |
| `sniff` | OFFERED, BOUNDED | 802.15.4 PDUs -> pcap; client enforces count / seconds |
| `inject` | OFFERED | transmit one raw 802.15.4 frame |
| `replay` | OFFERED | re-transmit captured frames; DLT-vs-session validated |

No protocol verbs: `capabilities().verbs` lists only the core packet verbs. Analysis lives in stock
tools, not in the client.

## 3. DLT and capture representation

Captures use `DLT_IEEE802_15_4_WITHFCS` (195), so a pcap dissects as 802.15.4 in wireshark/tshark
and feeds `zbdsniff`. The `raw` bytes on the wire are the on-air PDU (including the FCS). `replay`
validates the capture DLT against the active protocol and refuses a non-802.15.4 pcap with
`ProbeError` (rule 5).

## 4. What a virtual target must simulate

A virtual target exposes an 802.15.4 emitter model that builds MAC frames the operator's tools can
key on:

- MAC frames with a valid FCF / command-id and FCS, shaped like 802.15.4 so tshark and `zbdsniff`
  parse the structure.
- Honest fidelity limit: the virtual side today builds **structurally shaped** frames, not a real
  NWK/APS stack with valid `AES-CCM*` crypto. Frames look like 802.15.4 but are not cryptographically
  valid, so a capture does not actually decrypt in `zbdsniff`/tshark. A faithful join-and-decrypt
  scenario needs a real NWK/APS + `AES-CCM*` builder (a valid Transport-Key command encrypted under
  the Trust-Center link key, NWK frames with a real frame counter under the network key, correct
  FCS); getting `CCM*` exactly right is required, because a wrong `CCM*` means the tool will not
  decrypt, which is worse than an obviously placeholder frame. That builder is not shipped yet.

Same-commands-transfer note: the identical `probe scan`/`sniff`/`inject`/`replay` commands are meant
to run against the real `killerbee` backend (a `probe-bridge --medium killerbee` over an ApiMote /
CC2531), which relays raw 802.15.4 PDUs. The protocol module and CLI do not change; only the backend
swaps. A real bridge (and the crypto builder) is what would make a captured pcap decrypt end to end.

## 5. Contract items touched

- `Capabilities.shape` - Zigbee sets `shape="packet"`, with no `op` group.
- `replay` DLT-vs-session validation (must reject a non-195 pcap).
- The sniff client-bound (rule 4).
- No new Backend method and no new wire message type: `sniff`/`inject`/`replay` cover Zigbee.
