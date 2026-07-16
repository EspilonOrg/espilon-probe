# espilon-probe documentation index

`probe` is a generalist physical-layer CLI (RF + buses). It is a TCP tunnel client that speaks one
wire protocol to a **bridge**; the bridge terminates that tunnel into either a simulator (the
virtual lab) or a real medium. Because the client reaches both over the identical wire, a skill
learned against a virtual lab transfers 1:1 to real hardware - fidelity is structural, not
asserted.

The docs are split in two: a lean **user-facing** set here, and internal **design notes** under
[`design/`](design/) for contributors.

## User documentation

- [`cli.md`](cli.md) - the `probe` command surface: backends, core verbs, per-protocol verbs.
- [`wire-protocol.md`](wire-protocol.md) - the wire contract a bridge implements.
- [`protocol-conventions.md`](protocol-conventions.md) - cross-cutting rules (the verb gate, the
  shape taxonomy, the sniff bound, the pcap DLT registry).
- [`protocols/`](protocols/) - one doc per protocol, each a self-contained codec spec with a
  status line: [`ble`](protocols/ble.md), [`can`](protocols/can.md), [`uart`](protocols/uart.md),
  [`jtag`](protocols/jtag.md), [`spi`](protocols/spi.md), [`subghz`](protocols/subghz.md),
  [`zigbee`](protocols/zigbee.md).

For a one-paragraph orientation on the layering, see [`../ARCHITECTURE.md`](../ARCHITECTURE.md).

## Design notes (contributors)

[`design/`](design/) holds the decision records and buildable specs behind the transport, the
bridge contract, the conformance harness, and the detailed protocol pilots. These are background
for contributors, not user documentation - `design/00-architecture.md` is the source of truth for
how the fidelity architecture works.
