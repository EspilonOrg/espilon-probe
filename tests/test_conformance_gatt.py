"""The BLE GATT TRANSACTION conformance gate: the virtual leg over the SHIPPED client, + the
_serve_op reaping / relay-refusal discipline.

`test_gatt_virtual_leg_over_shipped_client` is the CI gate: it plays the gatt smoke tape against the
virtual GATT bridge (GattServer behind GattOpMedium over BridgeServer._serve_op) through the real
`probe` CLI, one short-lived connection per verb, and asserts the tape's per-step exit / stdout /
stderr oracle. It needs NO bleak, NO BlueZ, NO hardware - BLE has no software loopback, so the real
AX201<->ESP32 diff is a gated spot-check, deliberately NOT run here (docs/protocols/ble-gatt.md
sections 0.3, 4.6).

The reaping tests mirror tests/test_bridge_reaping.py for the new transaction serve path: an op client
that HELLOs then stalls is reaped at the control deadline (it must not wedge the single-serving
daemon), and the relay verbs are refused cleanly on a transaction bridge.
"""

import os
import socket
import threading
import time

import pytest

from conformance.gatt_server import GattServer
from conformance.run_gatt import check_virtual, run_virtual_only
from conformance.virtual_gatt_bridge import GattOpMedium, VirtualGattBridge
from espilon_probe.backends.virtual import VirtualBackend
from espilon_probe.bridges.server import BridgeServer
from espilon_probe.core import wire

_TAPE = os.path.join(os.path.dirname(__file__), "..", "conformance", "tapes", "gatt_smoke.json")


def test_gatt_virtual_leg_over_shipped_client():
    results, steps = run_virtual_only(_TAPE)
    ok, report = check_virtual(results, steps)
    assert ok, "virtual GATT leg failed:\n" + report
    assert "RESULT: PASS" in report


def test_gatt_smoke_tape_exit_codes_and_att_errors():
    # Explicit assertions on the fidelity-bearing steps, independent of the tape oracle: the two
    # static permission errors render to stderr with a nonzero exit, and the unlock gate flips the
    # secret from the locked sentinel to the staged value.
    results, _steps = run_virtual_only(_TAPE)
    # step 2: read the write-only unlock -> ATT 0x02 on stderr, nonzero exit, nothing on stdout
    assert results[2].exit_code != 0
    assert "ATT error 0x02 (Read Not Permitted)" in results[2].stderr
    assert results[2].stdout == ""
    # step 3: write the read-only fw_version -> ATT 0x03
    assert results[3].exit_code != 0
    assert "ATT error 0x03 (Write Not Permitted)" in results[3].stderr
    # step 4: locked secret is the sentinel; step 8: after the correct-key unlock it is the value
    assert "00000000" in results[4].stdout
    assert "pilot-secret" in results[8].stdout
    # step 6 (still locked after the wrong-key write) never leaks the value
    assert "pilot-secret" not in results[6].stdout


def test_gatt_verbs_gate_out_sniff_over_shipped_client():
    # The medium advertises verbs=["scan","gatt"] only; a central is not a sniffer. The client's
    # capability gate must refuse `sniff` cleanly (docs/protocols/ble-gatt.md section 6).
    with VirtualGattBridge(GattServer()) as v:
        with VirtualBackend(v.target) as b:
            caps = b.capabilities()
    assert caps.shape == "transaction"
    assert "sniff" not in caps.verbs and "inject" not in caps.verbs and "replay" not in caps.verbs
    assert caps.verbs == ["scan", "gatt"]


def _serve(medium, control_timeout=0.5, idle_timeout=None):
    server = BridgeServer(medium, host="127.0.0.1", port=0)
    server._control_timeout = control_timeout
    port = server.bind()
    threading.Thread(target=lambda: server.serve_forever(idle_timeout=idle_timeout),
                     daemon=True).start()
    return server, port


def test_op_client_that_stalls_mid_protocol_is_reaped():
    # The transaction twin of test_bridge_reaping.test_packet_client_that_stalls_mid_protocol: an op
    # client that HELLOs then sends no verb must be reaped at the control deadline, not left holding
    # the single-serving daemon.
    server, port = _serve(GattOpMedium(GattServer()), control_timeout=0.5)
    s = socket.create_connection(("127.0.0.1", port))
    try:
        r, w = s.makefile("rb"), s.makefile("wb")
        wire.send(w, wire.hello())
        welcome = wire.decode(r)
        assert welcome and welcome.get("t") == wire.WELCOME
        # Stall: send no OP. The server must close the connection at the deadline.
        s.settimeout(3.0)
        start = time.monotonic()
        assert s.recv(1) == b""                          # reaped and closed
        assert time.monotonic() - start < 2.5
    finally:
        s.close()
        server.close()


def test_serve_op_refuses_relay_verbs_cleanly():
    # Defence in depth: even if the capability gate is bypassed, a SNIFF/INJECT/REPLAY on a
    # transaction bridge is answered with a clean wire ERROR, never a crash or a wedge.
    server, port = _serve(GattOpMedium(GattServer()), control_timeout=1.0)
    s = socket.create_connection(("127.0.0.1", port))
    try:
        r, w = s.makefile("rb"), s.makefile("wb")
        wire.send(w, wire.hello())
        assert wire.decode(r).get("t") == wire.WELCOME
        wire.send(w, {"t": wire.SNIFF, "count": 1})
        reply = wire.decode(r)
        assert reply.get("t") == wire.ERROR
        assert "transaction bridge" in reply.get("msg", "")
    finally:
        s.close()
        server.close()


def test_serve_op_enum_read_write_over_the_wire():
    # Drive the op path directly through the shipped VirtualBackend.op(): enum, the unlock gate, and
    # an ATT error surfaced as {error: code} inside the result (not a wire error).
    with VirtualGattBridge(GattServer()) as v:
        with VirtualBackend(v.target) as b:
            enum = b.op("gatt.enum")
            handles = [c["handle"] for c in enum["characteristics"]]
            assert handles == [0x0003, 0x0006, 0x0008]
            # read the write-only unlock -> {error: 0x02}
            assert b.op("gatt.read", handle=0x0006) == {"error": 0x02}


def test_serve_op_malformed_write_value_fails_loud():
    # A non-hex write value is uninterpretable; the medium coerces authoritatively and _serve_op
    # surfaces the failure as a clean wire ERROR (RuntimeError client-side), never a silent pass.
    with VirtualGattBridge(GattServer()) as v:
        with VirtualBackend(v.target) as b:
            with pytest.raises(RuntimeError):
                b.op("gatt.write", handle=0x0006, value="zz")
