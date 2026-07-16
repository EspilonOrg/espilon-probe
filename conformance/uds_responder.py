"""A standalone UDS responder bound to a SocketCAN interface - the ECU on the bus for the real leg.

On vcan0 there are TWO independent PF_CAN sockets (docs/design/can-framed.md section 4.2): the
generalist socketcan probe-bridge (the operator's interface, model-free) and THIS responder (the
content side). It binds its OWN CAN_RAW socket, reads request frames (0x7E0), runs the SAME can_isotp
+ UdsEcu the virtual side runs, and writes response frames (0x7E8). This is "an ECU on the bus + the
operator's interface" made literal, and the bridge stays model-free.

RECV_OWN_MSGS is left off, so the responder never reads its own responses (and the bridge never reads
the request it injected): the bridge captures only the 0x7E8, matching the virtual medium exactly.

Run as:  python -m conformance.uds_responder --iface vcan0
It prints a READY line once bound so the harness can order bring-up (responder up BEFORE the first
request is injected, so no request is missed).
"""

from __future__ import annotations

import argparse
import socket
import sys

from espilon_probe.protocols import can

from . import can_isotp
from .uds_ecu import UdsEcu

READY_PREFIX = "UDS_RESPONDER_READY"


def serve(iface: str, stop=None) -> None:
    """Bind `iface`, print the READY line, then answer UDS requests until `stop()` is true / the
    socket dies. `stop` defaults to running forever (the harness kills the process on teardown)."""
    s = socket.socket(socket.PF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
    s.bind((iface,))
    s.settimeout(0.2)
    print(f"{READY_PREFIX} {iface}", flush=True)
    ecu = UdsEcu()
    try:
        while stop is None or not stop():
            try:
                raw = s.recv(can.FRAME_SIZE)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                can_id, pdu = can_isotp.decode(raw)
            except ValueError:
                continue                    # not a well-formed SF request: ignore, like a real ECU
            if can_id != can_isotp.REQ_ID:
                continue                    # not our request id
            resp = ecu.request(pdu)
            if resp is None:
                continue
            s.send(can_isotp.encode_response(resp))
    finally:
        s.close()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="conformance.uds_responder",
                                 description="A flag-free UDS ECU bound to a SocketCAN interface.")
    ap.add_argument("--iface", default="vcan0", help="SocketCAN interface (default vcan0)")
    args = ap.parse_args(argv)
    try:
        serve(args.iface)
    except OSError as e:
        print(f"uds_responder: cannot bind {args.iface!r}: {e}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
