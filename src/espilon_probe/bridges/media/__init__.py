"""Bridge media: one module per real medium (serial/pty for the UART pilot).

A medium opens the device/interface named by `--endpoint`, advertises truthful capabilities, and
moves bytes at its spectrum position (a raw byte pump for the stream media, a frame relay for the
packet media, later). Stdlib media (serial, socketcan) carry no dependency; hardware media (ftdi,
openocd, hci, sdr, killerbee) will import their dependency LAZILY inside their own module so the
client core stays stdlib-only (docs/design/02-bridge-contract.md section 4).
"""
