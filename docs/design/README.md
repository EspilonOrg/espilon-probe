# Design notes

Internal design notes and decision records - background for contributors, not user documentation.

These files capture how `probe`'s fidelity architecture was reasoned out and how each pilot is
built. If any of them contradicts the shipped behaviour or the user docs, the user docs and the
code win.

- [`00-architecture.md`](00-architecture.md) - **source of truth.** The client -> TCP tunnel ->
  bridge -> {sim | real medium} picture, the fidelity contract, the honest caveats, and the build
  sequence.
- [`01-transport.md`](01-transport.md) - the TCP tunnel: handshake, the two payload shapes
  (FRAMED / RAW-STREAM), capability/param negotiation, the raw-stream upgrade seam, half-close/EOF.
- [`02-bridge-contract.md`](02-bridge-contract.md) - what a bridge is; the relay vs stack-runner
  executor spectrum; the loopback auto-spawn for local hardware.
- [`03-conformance.md`](03-conformance.md) - the harness: tape format, runner, normalizer, the
  "same tape, two bridges" diff, and the honest per-protocol limits.

Detailed, buildable pilot specs (each extends the matching per-protocol doc in
[`../protocols/`](../protocols/)):

- [`uart-console.md`](uart-console.md) - the RAW-STREAM interactive console + one-shot send.
- [`can-framed.md`](can-framed.md) - the FRAMED (packet) relay pilot.
- [`ble-gatt.md`](ble-gatt.md) - the TRANSACTION / semantic-op stack-runner pilot.
