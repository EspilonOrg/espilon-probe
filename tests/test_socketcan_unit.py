"""socketcan medium unit tests that need no interface (the guards from the review).

After the FRAMED migration (docs/protocols/can-framed.md section 7) the PF_CAN I/O lives in the
bridge's CanMedium, not a direct client backend, so the not-open guards are asserted there.
"""

import pytest

from espilon_probe.bridges.media.socketcan import CanMedium
from espilon_probe.protocols import can


def test_methods_require_open():
    m = CanMedium("vcan0")            # not opened
    for call in (lambda: m.inject(can.encode_frame(0x1, b"")),
                 lambda: m.scan()):
        with pytest.raises(RuntimeError):
            call()


def test_take_frames_without_open_is_empty_not_hang():
    # take_frames is called by the server post-open; a not-open call returns [] at once rather than
    # busy-waiting to its deadline, so it can never wedge.
    import time
    m = CanMedium("vcan0")
    assert m.take_frames(1, time.monotonic() + 5.0) == []


def test_medium_advertises_packet_shape_and_dlt():
    caps = CanMedium("vcan0").caps()
    assert caps["shape"] == "packet"
    assert caps["protocol"] == "can"
    assert caps["pcap_dlt"] == can.PCAP_DLT
    assert "inject" in caps["verbs"] and "sniff" in caps["verbs"]


def test_decode_short_frame_raises_valueerror():
    with pytest.raises(ValueError):
        can.decode_frame(b"\x01\x02\x03")


def test_rx_fifo_is_bounded_and_counts_drops(monkeypatch):
    # The background reader appends frames independent of any client; flooding an un-drained FIFO
    # past its cap must NOT grow without bound. Drop-OLDEST keeps the newest cap frames and bumps an
    # observable counter (surfaced in caps meta), never a silent unbounded buffer.
    from espilon_probe.bridges.media import socketcan as sc
    monkeypatch.setattr(sc, "_FIFO_MAXLEN", 4)
    m = sc.CanMedium("vcan0")
    for i in range(10):
        m._push(bytes([i]))
    assert len(m._fifo) == 4                       # bounded at the cap, not 10
    assert list(m._fifo) == [bytes([i]) for i in range(6, 10)]   # newest 4 retained (drop-oldest)
    assert m._dropped == 6                         # the 6 oldest were dropped and counted
    assert m.caps()["meta"]["rx_dropped"] == 6     # and the loss is observable to a client
