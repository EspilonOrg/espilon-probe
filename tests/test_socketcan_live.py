"""Live socketcan loopback: the dual-purpose proof on a real SocketCAN interface.

Auto-skips unless a vcan0 exists. Enable it with:
    sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0
Then the SAME protocol codec and verbs that drive the virtual lab drive a real bus.
"""

import socket
import threading
import time

import pytest

from espilon_probe.backends.socketcan import SocketCanBackend
from espilon_probe.core.frame import read_pcap
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


def test_socketcan_loopback(tmp_path):
    sender = SocketCanBackend("vcan0")
    reader = SocketCanBackend("vcan0")
    sender.open()
    reader.open()
    try:
        captured = {}

        def grab():
            captured["n"] = reader.sniff(str(tmp_path / "live.pcap"), count=1, seconds=2)

        t = threading.Thread(target=grab)
        t.start()
        time.sleep(0.1)
        can.send(sender, 0x123, "deadbeef")     # same call as in the virtual lab
        t.join(3)

        assert captured.get("n", 0) >= 1
        _d, frames = read_pcap(str(tmp_path / "live.pcap"))
        cid, data, _ = can.decode_frame(frames[0])
        assert cid == 0x123 and data == bytes.fromhex("deadbeef")
    finally:
        sender.close()
        reader.close()
