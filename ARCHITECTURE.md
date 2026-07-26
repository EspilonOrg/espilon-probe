# Architecture

This is a short orientation. The authoritative architecture is
[`docs/design/00-architecture.md`](docs/design/00-architecture.md); where this file and the `docs/` corpus
differ, `docs/` wins.

## The one idea

`probe` is a TCP tunnel client. It always speaks one length-prefixed wire protocol to a
**bridge**, and a bridge is what terminates that tunnel into a medium:

- a **virtual** bridge simulates the medium (for offline / training targets);
- a **real** bridge terminates the tunnel at hardware (a CAN interface, a serial line, a BLE
  adapter, ...).

The client cannot tell the two apart, so the *same* verbs and the *same* on-wire frame shapes
drive a virtual target and real hardware; only the backend changes.

## Three layers, cleanly separated

1. **The verb surface** (`src/espilon_probe/cli.py`) - what the operator types. Stable and
   protocol-aware; identical against virtual and real backends.
2. **The protocols** (`src/espilon_probe/protocols/`) - what a frame or transaction *means*
   (BLE GATT, 802.15.4, CAN, UART, JTAG TAP, SPI, sub-GHz). These build and parse real PDUs.
3. **The backend** (`src/espilon_probe/backends/` + `core/backend.py`) - how bytes reach the
   target. Every backend implements the same small contract, so the layers above never know
   which one they are talking to. A local real medium is reached through a `probe-bridge`
   daemon (`src/espilon_probe/bridges/`) that the client auto-spawns on loopback.

Analysis is deliberately out of scope: `probe` emits standard pcap and you run your own stock
tools on it.

## Where to read more

The docs split in two: a lean **user-facing** set and internal **design notes** for contributors.

- [`docs/cli.md`](docs/cli.md) - the CLI surface, and [`docs/protocols/`](docs/protocols/) - the
  per-protocol codec specs.
- [`docs/wire-protocol.md`](docs/wire-protocol.md) - the wire contract a bridge implements.
- [`docs/design/`](docs/design/) - the decision records and buildable pilot specs;
  [`docs/design/00-architecture.md`](docs/design/00-architecture.md) is the source of truth for the
  transport/bridge model, the two payload shapes (FRAMED / RAW-STREAM), and the backend spectrum,
  in full.

This repository is the generalist client and the wire contract only; it carries no
target-specific content.
