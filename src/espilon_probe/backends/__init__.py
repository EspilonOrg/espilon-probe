"""Backends: the only layer that knows HOW bytes reach the target.

Phase 1 ships `virtual` (lab over TCP). Real adapters (hci, killerbee, sdr, serial,
openocd, ftdi, socketcan) land one at a time, each validated on real hardware. They all
implement core.Backend so the layers above are identical lab vs real.
"""
