# probe CLI surface

One verb set, every protocol, lab and real. The backend is the only thing that changes.

## Selecting a backend

```
export ESP_PROBE=tcp://lab-host:port     # lab (default backend = virtual)
probe scan

probe --backend hci       scan           # real BLE
probe --backend killerbee sniff -w z.pcap
probe --backend openocd   jtag halt
```

## Core verbs (every protocol)

```
probe info                               # backend, protocol, channels, capabilities
probe scan                               # what is on the protocol
probe sniff -w cap.pcap [-c N] [-t S] [--channel C]   # capture to standard pcap
probe inject --hex DEADBEEF | -r frame.bin
probe replay -r cap.pcap [--filter '...']
```

## Protocol verbs (offered when the backend advertises them)

```
# BLE
probe gatt enum
probe gatt read  <handle|uuid>
probe gatt write <handle|uuid> <hex>
probe gatt notify <handle>

# wired buses (later)
probe jtag halt | dump ...
probe spi  dump ...
probe uart open ...
```

## Analysis stays in stock tools

`probe` writes standard pcap; you analyse with what you already use:

```
probe sniff -w zb.pcap -t 60
zbdsniff zb.pcap                         # recover key (stock)
tshark -r zb.pcap ...                    # dissect / decrypt (stock)
probe replay -r zb.pcap --filter 'zbee_aps.cluster==0x0006'
```

## Translation from native tools

`bluetoothctl/hcitool -> probe scan`, `gatttool -> probe gatt`, `btmon/zbdump -> probe
sniff -w`, `zbdsniff/crackle/tshark -> stock on the pcap`, `zbreplay/scapy sendp -> probe
replay/inject`.
