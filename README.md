# probe

One CLI (and Python library) for the physical layer. `probe` is a single, consistent
interface to media that do not travel over IP - radio (BLE, Zigbee, sub-GHz, ...) and wired
hardware buses (CAN, UART, JTAG, SPI, ...). The same commands drive a virtual training
target and real hardware; only the backend changes.

```
# real CAN bus (Linux SocketCAN: vcan0, can0, ...)
probe --backend socketcan --target vcan0 scan
probe --backend socketcan --target vcan0 can send 0x7df 1003
probe --backend socketcan --target vcan0 can dump -w cap.pcap -c 20

# real UART line
probe --backend serial --target /dev/ttyUSB0 --baud 115200 uart read

# a virtual training target over TCP (set ESP_PROBE to the endpoint)
export ESP_PROBE=tcp://host:port
probe scan ; probe gatt enum ; probe sniff -w cap.pcap -c 10
```

Captures are written as standard pcap, so you analyse them with the tools you already use
(tshark, wireshark, zbdsniff, crackle). `probe` does live I/O and normalized capture; it is
not an analysis tool and it is not for IP protocols (those have their own mature clients).

## Why

The gap `probe` fills is everything below IP: radio and hardware buses, where the real tool
binds to a USB adapter or a probe, and a training target has no radio to bind to. One
unified client with a swappable backend covers both: learn on the virtual backend, then run
the exact same commands against real silicon.

## Install

```
pip install espilon-probe        # (PyPI publication pending; for now install from source)
# from source:
git clone <repo> && cd espilon-probe
pip install -e ".[dev]"
python -m pytest tests/ -q
```

It is both a CLI (`probe`) and an importable library:

```python
from espilon_probe.backends.socketcan import SocketCanBackend
from espilon_probe.protocols import can
b = SocketCanBackend("vcan0"); b.open()
can.send(b, 0x123, "deadbeef")
```

## Backends

| Backend | Protocol | Status |
|---|---|---|
| `virtual` | any (over the wire protocol, for training targets) | working |
| `socketcan` | CAN (Linux SocketCAN) | working, no third-party dep |
| `serial` | UART (termios) | working, no third-party dep |
| `hci` | BLE (BlueZ) | planned |
| `killerbee` | 802.15.4 / Zigbee | planned |
| `sdr` | sub-GHz (SoapySDR) | planned |
| `openocd` / `ftdi` | JTAG / SPI | planned |

Protocols implemented today: `ble`, `can`, `zigbee`, `uart`.

## How it works

Three layers: the CLI dispatches to a protocol (frame meaning + protocol verbs), which talks to
a `Backend` (the one interface every backend implements). The `virtual` backend speaks a
small length-prefixed wire protocol over TCP to a target server; the real backends drive the
native interface. See `ARCHITECTURE.md` and `docs/wire-protocol.md` (the public contract any
target server implements).

This repo is the generalist client only. It contains no challenge, flag, device or course
code.

## Contributing

See `CONTRIBUTING.md`. Short version: stdlib only in the core, keep the suite green, match
the surrounding style.

## License

GPL-3.0-or-later. See `LICENSE`.
