"""ISO-TP single-frame (SF) wrap/unwrap + the classic 11-bit UDS id map - the ONE adapter both
terminations use (docs/design/can-framed.md sections 3.2, 4.1).

Single-frame ONLY: every pilot PDU is <= 7 bytes so it fits one SF. Layout is
    [PCI = 0x0<len>][pdu bytes...]
right-padded with 0x00 to the fixed 8-byte CAN payload (DLC 8). Both sides use this identical wrap,
so padding and DLC are equal by construction and the captured frames are byte-for-byte comparable.
Multi-frame ISO-TP (FF/CF/FlowControl/STmin) is the kit follow-up, deliberately out of the pilot.
"""

from __future__ import annotations

from espilon_probe.protocols import can

REQ_ID = 0x7E0    # tester -> ECU (physical request)
RESP_ID = 0x7E8   # ECU -> tester (physical response)

SF_MAX = 7        # a single frame carries at most 7 payload bytes


class IsoTpError(ValueError):
    """A CAN payload that is not a well-formed single frame. A ValueError subclass so callers that
    already catch decode errors (can.decode_frame) catch this too."""


def sf_wrap(pdu: bytes) -> bytes:
    """Wrap a UDS PDU into an 8-byte single-frame CAN payload (PCI + pdu, 0x00-padded)."""
    pdu = bytes(pdu)
    if len(pdu) > SF_MAX:
        raise IsoTpError(f"pdu too long for a single frame: {len(pdu)} > {SF_MAX}")
    return (bytes([len(pdu)]) + pdu).ljust(8, b"\x00")


def sf_unwrap(data: bytes) -> bytes:
    """Recover the UDS PDU from an SF CAN payload. Refuses anything that is not a single frame
    rather than guessing (a multi-frame PCI, a truncated frame): this parser faces bus input, so it
    fails loud instead of returning a best-effort payload."""
    data = bytes(data)
    if not data:
        raise IsoTpError("empty CAN payload: not a single frame")
    pci = data[0]
    if pci >> 4 != 0x0:
        raise IsoTpError(f"not a single frame (PCI type nibble {pci >> 4:#x}, expected 0)")
    length = pci & 0x0F
    if length > SF_MAX:
        raise IsoTpError(f"illegal SF length {length}")
    if len(data) < 1 + length:
        raise IsoTpError(f"truncated single frame: need {1 + length} bytes, have {len(data)}")
    return data[1:1 + length]


def encode_request(pdu: bytes) -> bytes:
    """A 16-byte SocketCAN request frame (0x7E0) carrying `pdu` as a single frame."""
    return can.encode_frame(REQ_ID, sf_wrap(pdu))


def encode_response(pdu: bytes) -> bytes:
    """A 16-byte SocketCAN response frame (0x7E8) carrying `pdu` as a single frame."""
    return can.encode_frame(RESP_ID, sf_wrap(pdu))


def decode(raw: bytes) -> tuple[int, bytes]:
    """Decode a 16-byte SocketCAN frame to (can_id, uds_pdu). Raises on a non-SF payload."""
    can_id, payload, _ext = can.decode_frame(raw)
    return can_id, sf_unwrap(payload)
