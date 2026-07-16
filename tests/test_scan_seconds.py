"""The scan listen window is operator-controllable and plumbed CLI/env -> bridge -> medium.

`probe scan` used to listen for a fixed window baked into the medium. It now carries an OPTIONAL,
additive `seconds` (listen window) and `count` (distinct-device early-stop) on the SCAN wire message.
These tests pin:

  - precedence: the `-t/--seconds` flag beats `$ESP_PROBE_SCAN_SECS`, which beats the medium default
    (no field on the wire); a malformed / non-positive value from either source fails loud;
  - end-to-end plumbing: the value the operator asks for is the value the MEDIUM's `scan()` receives,
    through a real BridgeServer (so the server's off-the-wire coercion + hard-ceiling clamp are
    exercised, not mocked);
  - backward compatibility: a scan with no window looks exactly like the historical bare SCAN.
"""

import argparse
import os
import socket
import threading

import pytest

from espilon_probe import cli
from espilon_probe.backends.virtual import VirtualBackend
from espilon_probe.bridges.server import BridgeServer, _SCAN_COUNT_MAX, _SCAN_MAX
from espilon_probe.core import wire

from _mock_bridge import serve_mock

SCAN_CAPS = {"protocol": "ble", "channels": [], "verbs": ["scan"],
             "shape": "transaction", "meta": {}}


# --- precedence + validation of _scan_seconds ---------------------------------------------------

def _args(seconds=None):
    return argparse.Namespace(seconds=seconds, count=None)


def test_flag_beats_env(monkeypatch):
    monkeypatch.setenv("ESP_PROBE_SCAN_SECS", "9")
    assert cli._scan_seconds(_args(seconds=2.0)) == 2.0


def test_env_used_when_flag_absent(monkeypatch):
    monkeypatch.setenv("ESP_PROBE_SCAN_SECS", "7.5")
    assert cli._scan_seconds(_args(seconds=None)) == 7.5


def test_default_is_none_when_neither(monkeypatch):
    monkeypatch.delenv("ESP_PROBE_SCAN_SECS", raising=False)
    assert cli._scan_seconds(_args(seconds=None)) is None


def test_empty_env_is_treated_as_unset(monkeypatch):
    monkeypatch.setenv("ESP_PROBE_SCAN_SECS", "")
    assert cli._scan_seconds(_args(seconds=None)) is None


def test_malformed_env_fails_loud(monkeypatch):
    monkeypatch.setenv("ESP_PROBE_SCAN_SECS", "soon")
    with pytest.raises(cli.ProbeError):
        cli._scan_seconds(_args(seconds=None))


def test_non_positive_flag_fails_loud(monkeypatch):
    monkeypatch.delenv("ESP_PROBE_SCAN_SECS", raising=False)
    with pytest.raises(cli.ProbeError):
        cli._scan_seconds(_args(seconds=0.0))
    with pytest.raises(cli.ProbeError):
        cli._scan_seconds(_args(seconds=-3.0))


def test_non_positive_env_fails_loud(monkeypatch):
    monkeypatch.setenv("ESP_PROBE_SCAN_SECS", "-1")
    with pytest.raises(cli.ProbeError):
        cli._scan_seconds(_args(seconds=None))


# --- wire: the SCAN message carries seconds/count only when requested ----------------------------

def _captured_scan(argv, monkeypatch):
    """Run `probe <argv>` against a mock bridge and return the SCAN message it received."""
    box = {}

    def respond(msg):
        if msg.get("t") == wire.SCAN:
            box["scan"] = msg
            return {"t": wire.SCAN_RESULT, "items": []}
        return wire.error("unhandled")

    srv, port = serve_mock(SCAN_CAPS, respond)
    try:
        monkeypatch.setenv("ESP_PROBE", f"tcp://127.0.0.1:{port}")
        cli.main(argv)
    finally:
        srv.shutdown()
        srv.server_close()
    return box["scan"]


def test_bare_scan_omits_the_optional_fields(monkeypatch):
    monkeypatch.delenv("ESP_PROBE_SCAN_SECS", raising=False)
    msg = _captured_scan(["scan"], monkeypatch)
    assert msg == {"t": wire.SCAN}          # identical to the historical bare SCAN (backward-compat)


def test_flag_seconds_ride_the_wire(monkeypatch):
    monkeypatch.delenv("ESP_PROBE_SCAN_SECS", raising=False)
    msg = _captured_scan(["scan", "-t", "4"], monkeypatch)
    assert msg["seconds"] == 4.0


def test_env_seconds_ride_the_wire(monkeypatch):
    monkeypatch.setenv("ESP_PROBE_SCAN_SECS", "6")
    msg = _captured_scan(["scan"], monkeypatch)
    assert msg["seconds"] == 6.0


def test_count_rides_the_wire(monkeypatch):
    monkeypatch.delenv("ESP_PROBE_SCAN_SECS", raising=False)
    msg = _captured_scan(["scan", "-c", "3"], monkeypatch)
    assert msg["count"] == 3


# --- end-to-end: the value reaches the MEDIUM through a real bridge ------------------------------

class _RecordingMedium:
    """A transaction medium that records the seconds/count its scan() is handed and returns []."""

    shape = "transaction"

    def __init__(self):
        self.calls = []

    def apply_config(self, config):
        pass

    def caps(self):
        return {"protocol": "ble", "channels": [], "verbs": ["scan"],
                "shape": "transaction", "meta": {}}

    def scan(self, seconds=None, count=None):
        self.calls.append((seconds, count))
        return []

    def op(self, verb, args):
        return {}


def _serve(medium):
    server = BridgeServer(medium, host="127.0.0.1", port=0)
    port = server.bind()
    threading.Thread(target=lambda: server.serve_forever(), daemon=True).start()
    return server, port


def _client_scan(port, **kw):
    b = VirtualBackend(f"tcp://127.0.0.1:{port}")
    b.open()
    try:
        b.scan(**kw)
    finally:
        b.close()


def test_medium_receives_flag_seconds():
    med = _RecordingMedium()
    server, port = _serve(med)
    try:
        _client_scan(port, seconds=5.0)
    finally:
        server.close()
    assert med.calls == [(5.0, None)]


def test_medium_receives_count():
    med = _RecordingMedium()
    server, port = _serve(med)
    try:
        _client_scan(port, seconds=None, count=4)
    finally:
        server.close()
    assert med.calls == [(None, 4)]


def test_medium_default_when_no_window():
    med = _RecordingMedium()
    server, port = _serve(med)
    try:
        _client_scan(port)          # neither: the medium must see its default (None), not a guess
    finally:
        server.close()
    assert med.calls == [(None, None)]


def test_server_clamps_hostile_seconds():
    # `seconds` is off-the-wire (attacker-influenced): a huge value must be clamped to the hard
    # ceiling so it can never pin the medium and wedge the single-serving daemon.
    med = _RecordingMedium()
    server, port = _serve(med)
    try:
        _client_scan(port, seconds=1e9)
    finally:
        server.close()
    (seconds, _), = med.calls
    assert seconds == _SCAN_MAX


def test_server_clamps_hostile_count():
    # `count` is off-the-wire too: clamp it to a hard ceiling for symmetry with `seconds`, so a
    # buggy/hostile value can never make the medium track an absurd number of distinct rows.
    med = _RecordingMedium()
    server, port = _serve(med)
    try:
        b = VirtualBackend(f"tcp://127.0.0.1:{port}")
        b.open()
        try:
            b._txn({"t": wire.SCAN, "count": 10 ** 12})
        finally:
            b.close()
    finally:
        server.close()
    (_, count), = med.calls
    assert count == _SCAN_COUNT_MAX


def test_server_ignores_non_numeric_seconds():
    # A non-numeric `seconds` on the wire is not interpretable as a window: it falls to the medium
    # default (None), never a guessed number.
    med = _RecordingMedium()
    server, port = _serve(med)
    try:
        b = VirtualBackend(f"tcp://127.0.0.1:{port}")
        b.open()
        try:
            # Hand-build a SCAN with a hostile seconds the client would never send.
            b._txn({"t": wire.SCAN, "seconds": "forever"})
        finally:
            b.close()
    finally:
        server.close()
    assert med.calls == [(None, None)]
