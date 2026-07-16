# espilon-probe

**One CLI for the physical layer.** `probe` is a single, consistent interface to everything
below IP: radio (BLE, Zigbee, sub-GHz) and wired hardware buses (CAN, UART, JTAG, SPI). The
*same commands* drive a virtual target and real hardware; only the backend changes. The client
core is pure Python standard library.

[![CI](https://img.shields.io/github/actions/workflow/status/EspilonOrg/espilon-probe/ci.yml?branch=main&label=CI)](https://github.com/EspilonOrg/espilon-probe/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)

<p align="center">
  <img src="assets/demo.gif" alt="probe demo: a zero-setup tour against a bundled toy target" width="720">
</p>

<p align="center"><em><code>probe demo</code> drives a simulated BLE lock with the shipped client; the <em>same commands</em> drive real hardware, only the backend changes.</em></p>

## Contents

- [Try it in 30 seconds](#try-it-in-30-seconds)
- [Examples](#examples)
- [Protocols](#protocols)
- [Install](#install)
- [The backend model](#the-backend-model)
- [Why not just use bluetoothctl / gatttool / can-utils / openocd?](#why-not-just-use-bluetoothctl--gatttool--can-utils--openocd)

`probe` does live I/O and normalized capture. Captures are written as standard pcap, so you
analyse them with the tools you already use (tshark, wireshark, zbdsniff, crackle, rtl_433).
It is not an analysis tool, and it is not for IP protocols, those have their own mature
clients.

## Try it in 30 seconds

```
pip install git+https://github.com/EspilonOrg/espilon-probe
probe demo
```

`probe demo` spins a bundled, flag-free toy target on loopback and runs a short scripted example
against it: real output, zero setup, no hardware and no endpoint to configure. (A PyPI package
is planned; until then, install from git as above.)

## Examples

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
| `zigbee` | 802.15.4 / Zigbee: driven through the core verbs (`scan`/`sniff`/`inject`/`replay`) against a Zigbee target; there is no separate `zigbee` subcommand |
| `jtag` | JTAG TAP: scan the chain, halt/resume, read/write memory and registers, dump firmware |
| `spi` | SPI master: JEDEC ID, read/write, register access, raw transfer, dump NOR flash |
| `subghz` | sub-GHz radio: scan bands, sniff/inject/replay OOK/ASK/2-FSK packets, demod hint |

Each protocol declares a *shape* (packet / stream / transaction) and only advertises the
verbs that make sense for it. Asking for an unsupported verb is a clean error, never a
traceback.

## Install

Install straight from the git source:

```
pip install git+https://github.com/EspilonOrg/espilon-probe
```

This installs the `probe` console command and the importable `espilon_probe` library.
(A PyPI package is planned; until then, install from git.)

From source (for development):

```
git clone https://github.com/EspilonOrg/espilon-probe
cd espilon-probe
pip install -e ".[dev]"
python -m pytest tests/ -q
```

### Quickstart

Point `probe` at a virtual target over TCP and go:

```
export ESP_PROBE=tcp://host:port     # virtual backend endpoint (default backend)

probe info                           # backend, protocol, shape, channels, capabilities
probe scan                           # enumerate what is on the protocol
```

Every request/response verb is bounded by a client-side read timeout (default 30s), so a
silent or wedged target fails with a clean error instead of hanging. Override it with
`ESP_PROBE_TIMEOUT=<seconds>` (a value <= 0 disables the bound).

## The backend model

Same verbs, swap the backend. The CLI and protocol codecs never know which backend they are
talking to.

| Backend | Reaches | Status |
|---|---|---|
| `virtual` | a target server over a small TCP wire protocol | working |
| `socketcan` | a real CAN interface (Linux SocketCAN, raw `PF_CAN`) | working, stdlib only |
| `serial` | a real UART line via a local `probe-bridge` daemon (stdlib termios), with `--baud` | working, stdlib only |
| `hci` | real BLE GATT via a local `probe-bridge` daemon over BlueZ (bleak) | working, optional extra `[hci]` |
| `killerbee` / `sdr` / `openocd` / `ftdi` | real Zigbee / SDR / JTAG / SPI adapters | planned, behind optional extras |

```
probe --backend socketcan --target vcan0 can send 0x7df 1003
probe --backend serial --target /dev/ttyUSB0 --baud 115200 uart read
```

A workflow validated against the virtual backend transfers to real hardware unchanged: the
verbs and the on-wire frame shapes are identical, only the backend adapter differs. Real
backends stay thin adapters over mature native libraries and load only when selected, so the
core install remains dependency-free.

Under the hood the client always speaks the same TCP wire protocol; a backend *is* a bridge to
a medium. The `virtual` bridge is a simulator; a real bridge terminates the tunnel at hardware.
The `serial` backend auto-spawns a persistent local `probe-bridge` daemon that owns the port
(stdlib termios) and streams raw UART bytes back over the wire, so "same tunnel, two
terminations" holds observationally. This transport/bridge model is specified in
[`docs/design/00-architecture.md`](docs/design/00-architecture.md); it is rolling out protocol by
protocol (UART first).

## Why not just use bluetoothctl / gatttool / can-utils / openocd?

Those are excellent, but each is a separate tool with its own flags, its own capture format, and
no path from a virtual target to real hardware. `probe` is *one* verb set across every physical
layer, the *same commands* against a virtual target and real silicon, and standard pcap out. If
you already know the native tools, the mapping is direct:

`bluetoothctl/hcitool -> probe scan`, `gatttool -> probe gatt`, `btmon/zbdump -> probe sniff
-w`, `zbdsniff/crackle/tshark -> stock on the pcap`, `zbreplay/scapy sendp -> probe
replay/inject`.

`probe` does not replace the analysis tools: it does live I/O and normalized capture, then you
run tshark / wireshark / zbdsniff / crackle / rtl_433 on the pcap it writes.

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
