"""Backends: the only layer that knows HOW bytes reach the target.

Ships `virtual` (a target server over TCP), plus real adapters (hci, killerbee, sdr, serial,
openocd, ftdi, socketcan) that land one at a time, each validated on real hardware. They all
implement core.Backend so the layers above are identical virtual vs real.
"""
