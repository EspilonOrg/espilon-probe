"""Replay and inject over the virtual backend, including the C4 cross-DLT replay refusal.

`replay` must validate the input pcap's DLT against the active protocol's PCAP_DLT and
refuse a cross-protocol capture (convention C4 / rule 5), instead of blasting foreign bytes.
"""

import os

import pytest

from espilon_probe import cli
from espilon_probe.backends.virtual import VirtualBackend
from espilon_probe.core import wire
from espilon_probe.core.errors import ProbeError
from espilon_probe.core.frame import Frame, PcapWriter

from _mock_bridge import serve_mock


def _caps(verbs=("scan", "sniff", "inject", "replay"), protocol="can", dlt=227):
    return {"protocol": protocol, "channels": [], "verbs": list(verbs),
            "pcap_dlt": dlt, "shape": "packet", "meta": {}}


def _packet_respond(captured):
    def respond(msg):
        t = msg.get("t")
        if t == wire.INJECT:
            captured.setdefault("injected", []).append(msg.get("frame"))
            return {"t": wire.ACK}
        if t == wire.REPLAY:
            frames = msg.get("frames", [])
            captured.setdefault("replayed", []).extend(frames)
            return {"t": wire.REPLAYED, "count": len(frames)}
        return wire.error("unhandled")

    return respond


def _write_pcap(path, dlt, payloads):
    with PcapWriter(str(path), dlt) as pw:
        for p in payloads:
            pw.write(Frame(ts=0.0, channel=0, raw=p, direction="tx", protocol="x"))


def test_inject_carries_channel(tmp_path):
    captured = {}
    srv, port = serve_mock(_caps(), _packet_respond(captured))
    try:
        os.environ["ESP_PROBE"] = f"tcp://127.0.0.1:{port}"
        cli.main(["inject", "--hex", "deadbeef", "--channel", "11"])
    finally:
        srv.shutdown()
        srv.server_close()
    assert captured["injected"] == ["deadbeef"]


def test_replay_matching_dlt_replays_all(tmp_path):
    captured = {}
    pcap = tmp_path / "can.pcap"
    _write_pcap(pcap, 227, [b"\x00" * 16, b"\x11" * 16])   # DLT matches caps (227)
    srv, port = serve_mock(_caps(dlt=227), _packet_respond(captured))
    try:
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            n = b.replay(str(pcap))
        assert n == 2
        assert len(captured["replayed"]) == 2
    finally:
        srv.shutdown()
        srv.server_close()


def test_replay_cross_dlt_is_refused(tmp_path):
    captured = {}
    # Active protocol declares CAN (227); the pcap is a BLE capture (256). Must refuse.
    pcap = tmp_path / "ble.pcap"
    _write_pcap(pcap, 256, [b"\x12\x14\x00\x01"])
    srv, port = serve_mock(_caps(dlt=227), _packet_respond(captured))
    try:
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            with pytest.raises(ProbeError) as ei:
                b.replay(str(pcap))
        assert "does not match the active protocol" in str(ei.value)
        assert "replayed" not in captured            # nothing was sent
    finally:
        srv.shutdown()
        srv.server_close()


def test_replay_refused_when_protocol_declares_no_dlt(tmp_path):
    # Conservative C4: if the active protocol declares no DLT we cannot validate, so refuse.
    captured = {}
    pcap = tmp_path / "x.pcap"
    _write_pcap(pcap, 227, [b"\x00" * 16])
    caps = _caps(dlt=227)
    del caps["pcap_dlt"]                              # no declared DLT
    srv, port = serve_mock(caps, _packet_respond(captured))
    try:
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            with pytest.raises(ProbeError) as ei:
                b.replay(str(pcap))
        assert "declares no pcap DLT" in str(ei.value)
    finally:
        srv.shutdown()
        srv.server_close()
