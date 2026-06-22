"""socketcan unit tests that need no interface (the guards from the review)."""

import pytest

from espilon_probe.backends.socketcan import SocketCanBackend
from espilon_probe.protocols import can


def test_methods_require_open():
    b = SocketCanBackend("vcan0")     # not opened
    for call in (lambda: b.inject(can.encode_frame(0x1, b"")),
                 lambda: b.scan(),
                 lambda: b.sniff("/tmp/should-not-write.pcap", count=1)):
        with pytest.raises(RuntimeError):
            call()


def test_decode_short_frame_raises_valueerror():
    with pytest.raises(ValueError):
        can.decode_frame(b"\x01\x02\x03")
