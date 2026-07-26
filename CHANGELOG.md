# Changelog

All notable changes to probe. This project adheres to Semantic Versioning.

## [Unreleased]

### Added

- `probe demo`: a zero-setup onboarding tour. It spins a bundled, flag-free toy target on
  loopback and runs a short scripted example against it (info -> scan -> a read/write story),
  then prints the equivalent real-hardware commands, so `pip install espilon-probe && probe demo`
  produces output with no endpoint to configure and no hardware. Stdlib only.
- UART interactive console: `probe uart console` is a `screen`/`picocom`-grade terminal on the
  raw byte pipe (raw-mode tty, `Ctrl-]` to detach, `--local-echo`, `--eol cr|lf|crlf`), and
  `probe uart send <text>` is its scriptable one-shot sibling (atomic send-then-drain, with
  `--expect`). Both work identically against a virtual target and a real serial line.
- UART is served as a real bidirectional byte stream (RAW-STREAM) end to end, not
  request/response ops carrying hex; `uart read` takes a `-t/--timeout`.
- `hci` backend: real BLE GATT (`gatt enum/read/write`) over BlueZ, via a local `probe-bridge`
  daemon. It needs the optional `[hci]` extra (`pip install espilon-probe[hci]`, pulling
  `bleak`); the dependency loads lazily in the bridge, never in the client core.
- `scan` window tuning on packet backends: `-t/--seconds` sets how long to listen, `-c/--count`
  stops early once that many devices are seen, and `ESP_PROBE_SCAN_SECS` sets a default; the
  bus-enumerate scans (`jtag scan-chain`, `spi id`) are instantaneous and ignore the window.
- `probe use` persists defaults (backend / target / baud / scan-secs) to a config file, and a
  bare `probe` (or `probe wizard`) launches an interactive guided menu. Both are pure client-side
  layers with no new dependency and no wire change; a config-sourced backend/target is announced
  on stderr before a backend opens.

## [0.1.0] - 2026-07-05

First public release. A working generalist CLI and library for the physical layer.

### Added

- `probe` CLI with core verbs `info` / `scan` / `sniff` / `inject` / `replay`, plus protocol
  verbs `gatt` (BLE), `can`, `uart`, `jtag`, `spi`, and `subghz`.
- Protocols: `ble`, `can`, `zigbee`, `uart`, `jtag`, `spi`, `subghz`.
- Transaction protocols `jtag` and `spi`: scan-chain / JEDEC-ID enumeration, halt/resume,
  memory and register read/write, and bounded firmware/flash `dump` to a raw image (with an
  optional transaction pcap under a documented DLT_USER linktype).
- sub-GHz radio: band scan, bounded `sniff`, `inject`/`replay` on `--freq`/`--mod`/`--rate`,
  and a `subghz demod` modulation/bitrate hint. Captures self-describe their radio params via
  an 8-byte pseudo-header.
- Backends:
  - `virtual` - talks a small length-prefixed wire protocol over TCP to a target server
    (for training targets); forwards a client config (including `--baud`) in the handshake.
  - `socketcan` - real CAN over Linux SocketCAN (raw PF_CAN, no third-party dependency).
  - `serial` - real UART over termios, with `--baud` (no third-party dependency).
- Standard pcap capture (`sniff` / `can dump`), so captures open in tshark / wireshark.
- Importable library API (`espilon_probe.backends`, `espilon_probe.protocols`,
  `espilon_probe.core`).
- The wire protocol is documented as a public contract (`docs/wire-protocol.md`).
- `Capabilities.shape` (`"packet"` | `"stream"` | `"transaction"`, default `"packet"`),
  surfaced by `probe info`, so the CLI can reason about a protocol generically.
- `inject --channel` to transmit on a specific channel where the protocol supports it.
- GPL-3.0-or-later.

### Changed

- `sniff` is now always bounded client-side: it stops at `-c`/`-t` and at a hard wall-clock
  timeout, and applies a default 30s ceiling when neither is given (no more unbounded capture
  that trusts the target to end the stream).
- `replay` validates the input pcap's link type against the active protocol and refuses a
  cross-protocol capture instead of transmitting foreign bytes.
- Unsupported verbs and other expected failures now exit cleanly as `probe: <msg>` with a
  nonzero status (never a traceback); a verb a protocol does not advertise is refused by the
  capability gate before it is routed.
- CAN frame decoding rejects an illegal data length (DLC > 8) and a wrong-sized buffer rather
  than silently clamping or truncating.
- BLE capture frames now carry the full LE_LL_WITH_PHDR layering for their declared link type
  (256), so they dissect as `btatt.opcode` in stock tools.

- Renamed the link-layer abstraction `medium` to `protocol` everywhere: the
  `espilon_probe.protocols` package (was `mediums`), `Capabilities.protocol`,
  `Frame.protocol`, and the `probe info` output field (`protocol:`). The wire JSON key
  `"medium"` is now `"protocol"` in the FRAME and WELCOME-capabilities messages; this is a
  wire-shape change. `PROTO_VERSION` is not bumped (client and target are re-vendored in
  lockstep, so no mixed-version peers exist). The wire framing in `core/wire.py`
  (`PROTO_VERSION`, `ProtocolError`) is unchanged and is referred to as "the wire".

### Notes

- The `hci` backend (real BLE GATT over BlueZ) is implemented and working behind the optional
  `[hci]` extra; see the Unreleased entry above.
- Hardware backends `killerbee` / `sdr` / `openocd` / `ftdi` are declared but not yet
  implemented; selecting one reports that clearly.
