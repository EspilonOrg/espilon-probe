"""CAN protocol: SocketCAN frame codec + `can send`/`can dump` sugar over the core verbs.

A CAN frame is injected/sniffed like any packet protocol, so the SAME commands drive the
virtual bridge and the real socketcan backend. The on-wire/pcap representation is the
classic 16-byte SocketCAN frame, and captures use DLT_CAN_SOCKETCAN (227) so tshark
dissects them as CAN. This is the codec shared by both backends - the heart of the
dual-purpose proof.
"""

from __future__ import annotations

import struct

from ..core.backend import Backend
from ..core.errors import ProbeError

PROTOCOL = "can"
PCAP_DLT = 227                      # LINKTYPE_CAN_SOCKETCAN
FRAME_SIZE = 16                     # classic SocketCAN struct can_frame

_CAN = struct.Struct("<IB3x8s")     # can_id|flags, dlc, 3 pad, data[8]
CAN_EFF_FLAG = 0x80000000
CAN_RTR_FLAG = 0x40000000
CAN_SFF_MASK = 0x000007FF
CAN_EFF_MASK = 0x1FFFFFFF


def encode_frame(can_id: int, data: bytes, extended: bool = False) -> bytes:
    extended = extended or can_id > CAN_SFF_MASK
    raw_id = (can_id & (CAN_EFF_MASK if extended else CAN_SFF_MASK)) | (CAN_EFF_FLAG if extended else 0)
    data = bytes(data)[:8]
    return _CAN.pack(raw_id, len(data), data.ljust(8, b"\x00"))


def decode_frame(raw: bytes) -> tuple[int, bytes, bool]:
    # A classic SocketCAN frame is exactly FRAME_SIZE bytes. Accept a single frame of the
    # right length; reject anything shorter, and reject a buffer that is not a whole number
    # of frames rather than silently truncating trailing bytes.
    if len(raw) < FRAME_SIZE:
        raise ValueError(f"CAN frame too short: {len(raw)} bytes (need {FRAME_SIZE})")
    if len(raw) != FRAME_SIZE:
        raise ValueError(
            f"CAN frame wrong size: {len(raw)} bytes (a classic SocketCAN frame is {FRAME_SIZE})")
    raw_id, dlc, data = _CAN.unpack(raw)
    # DLC is the 4-bit data length; for classic CAN it must be 0..8. A larger value is an
    # illegal/corrupt frame, not something to silently clamp.
    if dlc > 8:
        raise ValueError(f"illegal CAN DLC {dlc} (classic CAN data length must be 0..8)")
    extended = bool(raw_id & CAN_EFF_FLAG)
    can_id = raw_id & (CAN_EFF_MASK if extended else CAN_SFF_MASK)
    return can_id, data[:dlc], extended


def ids_seen(frames: list[bytes]) -> list[int]:
    out: list[int] = []
    for f in frames:
        cid, _, _ = decode_frame(f)
        if cid not in out:
            out.append(cid)
    return out


# sugar over the core verbs (identical against virtual and socketcan)
def send(backend: Backend, can_id: int, data_hex: str, extended: bool = False) -> None:
    # `data_hex` is operator input (the CLI already validates it at source); guard here too so a
    # direct library caller cannot leak `bytes.fromhex`'s `non-hexadecimal number found` text.
    try:
        data = bytes.fromhex(data_hex)
    except (ValueError, TypeError):
        raise ProbeError(
            f"invalid CAN payload hex {data_hex!r} (expected hex bytes, e.g. deadbeef)")
    backend.inject(encode_frame(can_id, data, extended))


def dump(backend: Backend, out_pcap: str, count=None, seconds=None) -> int:
    return backend.sniff(out_pcap, count=count, seconds=seconds)
