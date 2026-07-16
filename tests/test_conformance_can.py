"""The CAN FRAMED conformance gate: virtual == real(vcan0), + a root-free virtual-side proof.

`test_can_virtual_equals_real_over_vcan` is the diff-two-bridges proof; it SKIPS (not fails) when
vcan0 is absent, mirroring tests/test_socketcan_live.py, because vcan needs the `vcan` kernel module
+ a link that generic CI may lack (docs/protocols/can-framed.md sections 4.5, 6).

`test_can_virtual_side_frames_over_shipped_client` needs NO vcan0 / NO root: it plays the smoke tape
against ONLY the virtual bridge through the shipped `probe` client, exercising the generic FRAMED
serve path (INJECT/SNIFF/SNIFF_END) end to end and asserting the model's response frames land in the
captured pcaps. This keeps the FRAMED plumbing under test where the full diff cannot run.
"""

import os

import pytest

from conformance import can_isotp
from conformance.run_can import _has_vcan, run_conformance, run_virtual_only

_TAPE = os.path.join(os.path.dirname(__file__), "..", "conformance", "tapes", "can_uds_smoke.json")


def test_can_virtual_side_frames_over_shipped_client():
    results, captures, steps = run_virtual_only(_TAPE)
    # every step exited cleanly through the shipped client
    assert all(r.exit_code == 0 for r in results), [r.stdout for r in results if r.exit_code]
    # each dump step's declared response PDU is decodable-present in its captured pcap
    for i, step in enumerate(steps):
        want = [str(h).replace(" ", "").lower() for h in step.get("expect", [])]
        if not want:
            continue
        pdus = []
        for h in captures.get(i, []):
            _id, pdu = can_isotp.decode(bytes.fromhex(h))
            pdus.append(pdu.hex())
        for w in want:
            assert w in pdus, f"step {i}: expected PDU {w} not in captured {pdus}"


@pytest.mark.skipif(
    not _has_vcan(),
    reason="no vcan0 (run: sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0)")
def test_can_virtual_equals_real_over_vcan():
    equal, report = run_conformance(_TAPE)
    assert equal, "virtual != real:\n" + report
    assert "RESULT: PASS" in report
