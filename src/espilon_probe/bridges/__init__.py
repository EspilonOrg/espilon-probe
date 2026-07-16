"""espilon_probe.bridges - the generic real/loopback bridge (docs/design/02-bridge-contract.md).

A bridge terminates the wire tunnel (`core/wire.py`) into a real medium (serial/pty for the UART
pilot; CAN, SPI, ... later). It is generalist infrastructure: NO flag, NO device model, NO course
content - it opens a medium and moves bytes.

CRITICAL BOUNDARY (docs/design/00 decision 8, docs/design/02 section 4): this is a SEPARATE import surface. The
client core (`espilon_probe.cli`, `espilon_probe.core`, `espilon_probe.protocols`) never imports
this package; the loopback launcher spawns `probe-bridge` as a SUBPROCESS, it does not import
bridge code in-process. That is what keeps the client core stdlib-only while a medium here is free
to carry an optional third-party dependency (imported lazily inside that one medium module). The
serial/pty medium of this pilot is pure stdlib, so `probe --backend serial` works out of the box.

It imports the same `core/wire.py` the client does, so the two sides can never drift.
"""
