# Roadmap

`probe` is a small, deliberately lean physical-layer tool. The roadmap below tracks the tool
itself: protocols, backends, and packaging. Dates are intentionally omitted; items ship when
they are correct and tested.

## Now (0.1.x)

- Seven protocols on the virtual backend: `ble`, `can`, `uart`, `zigbee`, `jtag`, `spi`,
  `subghz`.
- Real backends: `socketcan` (Linux SocketCAN, raw `PF_CAN`) and `serial` (UART over
  termios), both provable locally with no special hardware.
- Standard pcap capture (`sniff` / `can dump`) and a documented DLT_USER allocation for the
  transaction/radio protocols.
- Stdlib-only core, clean operator-facing errors, capability-gated verbs.
- Packaging (`pip install espilon-probe`), GitHub Actions CI, GPLv3+.

## Next

- Additional real backends behind optional extras (each a thin adapter over a mature native
  library):
  - `hci` - BLE via BlueZ / bleak.
  - `killerbee` - 802.15.4 / Zigbee.
  - `sdr` - sub-GHz via SoapySDR (the one backend with genuine low-level demod/mod work).
  - `openocd` - JTAG / SWD.
  - `ftdi` - SPI / I2C via pyftdi.
- More protocol coverage where it stays honest to the model (e.g. I2C as another
  transaction/register protocol).
- A trivial reference dissector (Lua / scapy) for the DLT_USER captures.

## Principles that will not change

- Stdlib only in the client core. Real-hardware dependencies live behind optional extras,
  never in the core import path.
- The client stays generalist: it speaks the wire protocol and drives backends, nothing
  more. No target-specific content ships in this repo.
- Same verbs, swap the backend: a workflow validated against a virtual target transfers to
  real hardware unchanged.
- Analysis stays in stock tools. `probe` does live I/O and normalized capture, not
  dissection.
