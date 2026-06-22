# Changelog

All notable changes to probe. This project adheres to Semantic Versioning.

## [0.1.0] - unreleased

First release. A working generalist CLI and library for the physical layer.

### Added

- `probe` CLI with core verbs `info` / `scan` / `sniff` / `inject` / `replay`, plus protocol
  verbs `gatt` (BLE), `can`, and `uart`.
- Protocols: `ble`, `can`, `zigbee`, `uart`.
- Backends:
  - `virtual` - talks a small length-prefixed wire protocol over TCP to a target server
    (for training targets); forwards a client config (including `--baud`) in the handshake.
  - `socketcan` - real CAN over Linux SocketCAN (raw PF_CAN, no third-party dependency).
  - `serial` - real UART over termios, with `--baud` (no third-party dependency).
- Standard pcap capture (`sniff` / `can dump`), so captures open in tshark / wireshark.
- Importable library API (`espilon_probe.backends`, `espilon_probe.protocols`,
  `espilon_probe.core`).
- The wire protocol is documented as a public contract (`docs/wire-protocol.md`).
- GPL-3.0-or-later.

### Changed

- Renamed the link-layer abstraction `medium` to `protocol` everywhere: the
  `espilon_probe.protocols` package (was `mediums`), `Capabilities.protocol`,
  `Frame.protocol`, and the `probe info` output field (`protocol:`). The wire JSON key
  `"medium"` is now `"protocol"` in the FRAME and WELCOME-capabilities messages; this is a
  wire-shape change. `PROTO_VERSION` is not bumped (client and bridge are re-vendored in
  lockstep, so no mixed-version peers exist). The wire framing in `core/wire.py`
  (`PROTO_VERSION`, `ProtocolError`) is unchanged and is referred to as "the wire".

### Notes

- Hardware backends `hci` / `killerbee` / `sdr` / `openocd` / `ftdi` are declared but not yet
  implemented; selecting one reports that clearly.
