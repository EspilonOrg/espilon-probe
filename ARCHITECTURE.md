# Architecture

## Principle

`probe` separates three concerns that are usually tangled together in radio/hardware tools:

1. **The verb surface** (what the operator types) - stable, protocol-aware, the same in lab
   and on real hardware.
2. **The protocol semantics** (what a frame/operation means) - BLE GATT, 802.15.4, JTAG TAP,
   SPI transaction, etc.
3. **The backend** (how bytes actually reach the target) - a virtual lab over TCP, or a
   real adapter (HCI, KillerBee, SDR, OpenOCD, pyserial, socketcan).

Analysis is deliberately out of scope: `probe` emits standard pcap and the operator runs
their own stock tools on it. We do live I/O and normalized capture, not dissection.

## The three layers

```
   operator
      |  verbs:  scan / sniff / inject / replay  (+ protocol verbs: gatt, jtag, spi, ...)
      v
+-------------------+
|       CLI         |  src/espilon_probe/cli.py      parse, dispatch
+-------------------+
|     protocols/    |  ble.py, zigbee.py, ...        meaning of frames + protocol verbs
+-------------------+
|   core.Backend    |  core/backend.py               the contract every backend implements
+-------------------+
|     backends/     |  virtual.py | hci.py | killerbee.py | sdr.py | serial.py | openocd.py
+-------------------+
      |                         |
   TCP wire protocol         real hardware (USB adapter / probe / SDR)
      |
+-------------------+
|   lab bridge      |  (separate private repo) serves a simulated protocol over the wire
+-------------------+
|    device.py      |  the lab author's scenario (the ONLY per-lab custom code)
+-------------------+
```

## The Backend contract

Every backend (virtual or real) implements the same small interface so the layers above
never know which one they are talking to. See `core/backend.py`. Core verbs:

- `open()` / `close()` - bind the protocol (TCP session for virtual; USB device for real).
- `capabilities()` - protocol, channels, what verbs are supported (drives `probe info`).
- `scan()` - enumerate what is on the protocol (advertisers / PANs / nodes / bus devices).
- `sniff(out_pcap, count, seconds, channel)` - stream frames, written as standard pcap.
- `inject(frame)` - transmit one raw frame.
- `replay(in_pcap, filter)` - re-transmit captured frames.

Connection-oriented and bus-specific operations are exposed as **protocol verbs** layered on
top (e.g. BLE `gatt enum/read/write`, JTAG `halt/dump`, SPI `dump`) and are only offered
when `capabilities()` advertises them.

## The wire protocol (virtual backend <-> lab bridge)

A framed TCP protocol carrying a generic radio/bus envelope, agnostic at the
transport so one bridge core serves every protocol. Conceptually:

- a control channel: `hello/capabilities`, `scan`, `inject`, protocol verbs, responses.
- a packet stream: frames the simulated protocol emits (what `sniff` captures) and
  acknowledgements for injected/replayed frames.

The envelope is roughly `{ts, channel, direction, protocol, raw_pdu, meta}`. Protocol meaning
lives in the client `protocols/`, not in the bridge - the bridge just moves frames. Full
spec: `docs/wire-protocol.md`.

## Backend matrix

| Protocol | Backend | Real hardware | Drives underneath |
|---|---|---|---|
| (lab, any) | `virtual` | none | probe wire protocol over TCP |
| BLE | `hci` | BT adapter / Ubertooth / nRF | BlueZ raw HCI / bleak |
| Zigbee 802.15.4 | `killerbee` | RZUSBstick, ApiMote, nRF | KillerBee |
| sub-GHz / LoRa | `sdr` | HackRF, RTL-SDR | SoapySDR |
| NFC / RFID | `nfc` | Proxmark3, PN532 | pcsc / proxmark |
| UART | `serial` | USB-UART adapter | pyserial |
| JTAG / SWD | `openocd` | J-Link, FT2232, ST-Link | OpenOCD |
| SPI / I2C | `ftdi` | Bus Pirate, FT2232 | pyftdi |
| CAN | `socketcan` | CAN interface | python-can (or socketcand) |

Most real backends are thin adapters over a mature native library. The value is the
unified surface, the normalized pcap, and the lab-to-real continuity, not reinventing the
driver. The one backend with genuine low-level work is `sdr` (sub-GHz demod/mod).

## Lab side (separate private repo)

The target/content side is NOT in this repo. It lives in a separate private repo
(`espilon-probe-labs`): the bridge server, the `Device` authoring SDK, example devices and
the probe-backed labs. It depends on this repo only for the wire protocol
(`pip install espilon-probe`). The boundary is deliberate: this repo is the generalist
client and the wire; it contains no challenge, flag, device or course code.

A lab author there writes only a `device.py` (a few hooks: what `scan` sees, what frames the
protocol emits, how an injected/replayed frame mutates state, where the flag is staged over the
wire). The wire protocol below is the public contract that side implements.
