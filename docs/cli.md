# probe CLI surface

One verb set, every protocol, virtual and real. The backend is the only thing that changes.

## Selecting a backend

```
export ESP_PROBE=tcp://host:port         # virtual target (default backend = virtual)
probe scan

probe --backend socketcan --target vcan0 can send 0x7df 1003   # real CAN (working)
probe --backend serial --target /dev/ttyUSB0 uart read         # real UART (working)
probe --backend hci --target my-lock gatt read 0x0011          # real BLE   (working, extra [hci])
```

The `hci` backend drives real BLE GATT over BlueZ and needs the optional `[hci]` extra
(`pip install espilon-probe[hci]`, which pulls `bleak`); the dependency loads lazily in the
bridge, never in the client core.

Planned / not yet implemented (running one today prints `backend '...' is not implemented
yet`); listed so the intended shape is clear:

```
probe --backend killerbee sniff -w z.pcap  #               (planned)
probe --backend openocd   jtag halt      #                 (planned)
```

## Core verbs (every protocol)

```
probe info                               # backend, protocol, shape, channels, capabilities
probe scan [-t S] [-c N]                 # what is on the protocol (S = seconds to listen)
probe sniff -w cap.pcap [-c N] [-t S] [--channel C]   # capture to standard pcap
probe inject --hex DEADBEEF | -r frame.bin [--channel C]
probe replay -r cap.pcap
```

`sniff` is always bounded client-side: pass `-c`/`-t` to set the bound; if you give neither,
a default ceiling (30s) applies rather than capturing forever. `replay` refuses a pcap whose
link type does not match the active protocol (no cross-protocol replay). A verb a protocol
does not advertise (see `info`) is refused cleanly, not run.

`scan` on a packet protocol (BLE, CAN, ...) listens for a window: `-t/--seconds` sets how long,
`-c/--count` stops early once that many distinct devices are seen. Precedence for the window is
`-t` flag > `ESP_PROBE_SCAN_SECS` env > the protocol's own default. The BLE (`hci`) default is 3s
(long enough for typical 100ms-1s advertising intervals, snappy for a quick look); raise it for a
rotating-address collection run (`probe --backend hci scan -t 15`) or drop it for a peek
(`-t 1`). The transaction bus-enumerate scans (`jtag scan-chain`, `spi id`) are instantaneous and
ignore the window. A malformed or non-positive window value fails loud rather than silently
falling back to the default.

The other verbs (request/response, not `sniff`) are bounded by a client-side read timeout so a
silent or wedged target fails with a clean error rather than hanging. The default is 30s;
override it with `ESP_PROBE_TIMEOUT=<seconds>` (a value <= 0 disables the bound).

## Protocol verbs (offered when the backend advertises them)

```
# BLE
probe gatt enum
probe gatt read  <handle|uuid>
probe gatt write <handle|uuid> <hex>

# CAN
probe can send <id> <hex>
probe can dump -w cap.pcap [-c N] [-t S]

# UART
probe uart read [-t S]
probe uart write <text>
probe uart send  <text> [-t S] [--eol cr|lf|crlf] [--expect REGEX] [--no-read]
probe uart console [--local-echo] [--eol cr|lf|crlf] [--replay-buffer]

# JTAG
probe jtag scan-chain
probe jtag idcode [--tap N]
probe jtag halt | resume [--tap N]
probe jtag read  --addr A [--words N]
probe jtag write --addr A --word V
probe jtag reg   [--name R]
probe jtag dump  --addr A --len L -w out.bin [--pcap session.pcap]

# SPI
probe spi id [--cs N]
probe spi read  --addr A --len N [--cs N]
probe spi write --addr A --hex ... [--cs N]
probe spi reg   <name> [--read | --write HEX] [--cs N]
probe spi xfer  --hex <mosi> [--cs N]
probe spi dump  --len L [--addr A] -w out.bin [--pcap session.pcap]

# ESP32 eFuse / secure-boot / flash-encryption (keys/images built off-device, Model B)
probe esp summary                                   # eFuses, key blocks, flash/secure-boot state
probe esp burn-key <key0..key5> <purpose> --data <hex>
probe esp burn-efuse <FIELD> <value>                # monotonic, write-once (a bit only 0 -> 1)
probe esp read-protect <key0..key5>                 # set RD_DIS (redacts the block)
probe esp write-flash [--encrypt] <region> <hex>    # region = bootloader | app | nvs | ...
probe esp read-flash <region>                       # plaintext, or [opaque ...] when encrypted
probe esp reboot                                    # recompute the boot verdict + rewrite banner
probe uart read                                     # read the boot banner (the reveal stream)

# sub-GHz (radio params extend the core verbs)
probe subghz bands
probe subghz demod -r cap.pcap
probe scan   [--band 433|868|915]
probe sniff  -w cap.pcap --freq 433.92M --mod ook [--rate R] [-c N] [-t S]
probe inject --hex AABBCC --freq 433.92M --mod ook [--rate R]
probe replay -r cap.pcap
```

## Analysis stays in stock tools

`probe` writes standard pcap; you analyse with what you already use:

```
probe sniff -w zb.pcap -t 60
zbdsniff zb.pcap                         # recover key (stock)
tshark -r zb.pcap ...                    # dissect / decrypt (stock)
tshark -r zb.pcap -Y 'zbee_aps.cluster==0x0006' -w filtered.pcap   # pre-filter (stock)
probe replay -r filtered.pcap            # replay the filtered capture
```

## Translation from native tools

`bluetoothctl/hcitool -> probe scan`, `gatttool -> probe gatt`, `btmon/zbdump -> probe
sniff -w`, `zbdsniff/crackle/tshark -> stock on the pcap`, `zbreplay/scapy sendp -> probe
replay/inject`.
