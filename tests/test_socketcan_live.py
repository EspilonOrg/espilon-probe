"""Live socketcan loopback on the migrated CanMedium: the medium's PF_CAN I/O on a real interface.

Auto-skips unless a vcan0 exists. Enable it with:
    sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0
Then the SAME 16-byte SocketCAN codec (protocols/can.py) that drives the virtual bridge drives a
real bus. After the FRAMED migration (docs/protocols/can-framed.md section 6) the low-level PF_CAN
socket + background frame FIFO live in CanMedium; the end-to-end tunnel path is owned by
tests/test_conformance_can.py.
"""

import socket
import time

import pytest

from espilon_probe.bridges.media.socketcan import CanMedium
from espilon_probe.protocols import can


def _has_vcan(name="vcan0") -> bool:
    try:
        s = socket.socket(socket.PF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
        s.bind((name,))
        s.close()
        return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not _has_vcan(),
    reason="no vcan0 (run: sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0)")


def test_canmedium_loopback():
    sender = CanMedium("vcan0")
    reader = CanMedium("vcan0")
    sender.open()
    reader.open()
    try:
        sender.inject(can.encode_frame(0x123, bytes.fromhex("deadbeef")))
        frames = reader.take_frames(count=1, deadline=time.monotonic() + 2.0)
        assert len(frames) >= 1
        cid, data, _ = can.decode_frame(frames[0])
        assert cid == 0x123 and data == bytes.fromhex("deadbeef")
    finally:
        sender.close()
        reader.close()


def test_canmedium_does_not_receive_own_frames():
    # RECV_OWN_MSGS is off: a socket must NOT read back its own injected frame. This is the
    # fidelity invariant the virtual CanFrameMedium mirrors (queue responses only, never the
    # request echo) - see docs/protocols/can-framed.md section 4.2.
    m = CanMedium("vcan0")
    m.open()
    try:
        m.inject(can.encode_frame(0x321, b"\x01\x02"))
        own = m.take_frames(count=1, deadline=time.monotonic() + 0.3)
        assert own == []
    finally:
        m.close()
