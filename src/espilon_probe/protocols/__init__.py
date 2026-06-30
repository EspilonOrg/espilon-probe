"""Protocols: the meaning of frames and the protocol-specific verbs.

Backend-agnostic: a protocol module turns operator intent (e.g. `gatt write 0x14 01`) into
the right frame/op for whatever backend is selected, and knows the pcap DLT to use. Phase
1 = ble; Phase 2 = zigbee; then uart, can; sprint 2 = jtag, spi, subghz; later = i2c, swd, ...
"""
