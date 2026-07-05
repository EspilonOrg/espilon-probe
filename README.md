# espilon-probe

**One CLI for the physical layer.** `probe` is a single, consistent interface to everything
below IP: radio (BLE, Zigbee, sub-GHz) and wired hardware buses (CAN, UART, JTAG, SPI). The
*same commands* drive a virtual target and real hardware; only the backend changes. Zero
third-party dependencies: the client core is pure Python standard library.

[![CI](https://img.shields.io/github/actions/workflow/status/EspilonOrg/espilon-probe/ci.yml?branch=main&label=CI)](https://github.com/EspilonOrg/espilon-probe/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/espilon-probe.svg)](https://pypi.org/project/espilon-probe/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)

`probe` does live I/O and normalized capture. Captures are written as standard pcap, so you
analyse them with the tools you already use (tshark, wireshark, zbdsniff, crackle, rtl_433).
It is not an analysis tool, and it is not for IP protocols, those have their own mature
clients.

## Install

```
pip install espilon-probe
```

This installs the `probe` console command and the importable `espilon_probe` library.

From source (for development):

```
git clone https://github.com/EspilonOrg/espilon-probe
cd espilon-probe
pip install -e ".[dev]"
python -m pytest tests/ -q
```

## Quickstart

Point `probe` at a virtual target over TCP and go:

```
export ESP_PROBE=tcp://host:port     # virtual backend endpoint (default backend)

probe info                           # backend, protocol, shape, channels, capabilities
probe scan                           # enumerate what is on the protocol
```

A few real command lines (each verb is offered only when the backend advertises it):

```
# BLE GATT
probe gatt enum
probe gatt read  0x0011
probe gatt write 0x0014 01

# CAN
probe can send 0x7df 0201
probe can dump -w cap.pcap -c 20

# UART
probe uart write "printenv"
probe uart read

# JTAG
probe jtag scan-chain
probe jtag dump --addr 0x08000000 --len 0x1000 -w fw.bin

# SPI NOR flash
probe spi id
probe spi read --addr 0 --len 256
probe spi dump --len 0x100000 -w flash.bin

# sub-GHz (radio params extend the core verbs)
probe subghz bands
probe sniff  -w cap.pcap --freq 433.92M --mod ook -t 30
probe replay -r cap.pcap
```

`sniff` is always bounded client-side: pass `-c`/`-t`, or a default 30s ceiling applies (no
capture that trusts the target to end the stream). `replay` refuses a pcap whose link type
does not match the active protocol.

## Protocols

| Protocol | What `probe` does |
|---|---|
| `ble` | BLE GATT: enumerate services/characteristics, read/write handles, sniff/replay ATT frames |
| `can` | CAN bus: send frames, dump traffic to pcap |
| `uart` | UART console: read/write a serial line |
| `zigbee` | 802.15.4 / Zigbee: scan, sniff, inject, replay packets |
| `jtag` | JTAG TAP: scan the chain, halt/resume, read/write memory and registers, dump firmware |
| `spi` | SPI master: JEDEC ID, read/write, register access, raw transfer, dump NOR flash |
| `subghz` | sub-GHz radio: scan bands, sniff/inject/replay OOK/ASK/2-FSK packets, demod hint |

Each protocol declares a *shape* (packet / stream / transaction) and only advertises the
verbs that make sense for it. Asking for an unsupported verb is a clean error, never a
traceback.

## The backend model

Same verbs, swap the backend. The CLI and protocol codecs never know which backend they are
talking to.

| Backend | Reaches | Status |
|---|---|---|
| `virtual` | a target server over a small TCP wire protocol | working |
| `socketcan` | a real CAN interface (Linux SocketCAN, raw `PF_CAN`) | working, stdlib only |
| `serial` | a real UART line (termios), with `--baud` | working, stdlib only |
| `hci` / `killerbee` / `sdr` / `openocd` / `ftdi` | real BLE / Zigbee / SDR / JTAG / SPI adapters | planned, behind optional extras |

```
probe --backend socketcan --target vcan0 can send 0x7df 1003
probe --backend serial --target /dev/ttyUSB0 --baud 115200 uart read
```

A workflow validated against the virtual backend transfers to real hardware unchanged: the
verbs and the on-wire frame shapes are identical, only the backend adapter differs. Real
backends stay thin adapters over mature native libraries and load only when selected, so the
core install remains dependency-free.

## Architecture

Three layers, cleanly separated: the **CLI** (the verb surface), the **protocol** modules
(what a frame or transaction means), and the **backend** (how bytes reach the target). The
`virtual` backend speaks a small length-prefixed wire protocol over TCP; real backends drive
the native interface. See [`ARCHITECTURE.md`](ARCHITECTURE.md) and [`docs/`](docs/) (the
`wire-protocol.md` contract and per-protocol specs).

This repository is the generalist client only. It contains no target-specific content.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Short version: stdlib only in the core, keep the
test suite green, match the surrounding style. Real-hardware dependencies live behind optional
extras, never in the core.

## License

GPL-3.0-or-later. See [`LICENSE`](LICENSE).
