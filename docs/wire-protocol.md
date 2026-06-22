# probe wire protocol (draft)

Spoken between the `virtual` backend (player side) and the lab bridge (server side) over
TCP. Agnostic at the transport so one bridge core serves every protocol; protocol
meaning lives in the client `protocols/`, not here.

## Session

1. Client connects to `tcp://host:port` (from `ESP_PROBE`).
2. `HELLO` handshake: version negotiation.
3. `CAPABILITIES` from server: `{protocol, channels, verbs, meta}` (drives `probe info`).

## Messages (shape, to be finalized in Phase 1)

Two logical channels over the one connection:

- Control (request/response):
  - `SCAN` -> `[{...advertiser/node/device...}]`
  - `OP {verb, args}` -> `{result}`        (protocol verbs: gatt.read, gatt.write, ...)
  - `INJECT {frame, channel}` -> `{ack}`
  - `REPLAY {frames[], filter}` -> `{count}`
- Stream (server push, started by `SNIFF {count?, seconds?, channel?}`):
  - `FRAME {ts, channel, direction, protocol, raw, meta}` repeated; client writes pcap.

## Frame envelope

```
{ ts: float, channel: int, direction: "rx"|"tx", protocol: str, raw: bytes, meta: {} }
```

`raw` is the on-protocol PDU (802.15.4 / LL / bus word). The client writes it to a standard
pcap with the protocol's DLT; analysis is done by the operator's stock tools.

## Notes

- Framing: length-prefixed messages; encoding TBD (CBOR or length-prefixed JSON + raw
  bytes side-channel). Decide in Phase 1, keep it boring.
- Auth: per-session port allocation + network isolation by `lab_runtime`; no token in v1.
- The same envelope is what a real backend produces locally, so `protocols/` code is shared
  across virtual and real.
