"""The sniff loop must be bounded entirely client-side.

A bridge that streams frames forever and never sends SNIFF_END must NOT hang the client:
the tool enforces `count`, `seconds`, and a hard wall-clock timeout itself, plus a per-recv
socket timeout, and stops on its own (convention rule 4 - the tool bounds every receive).
"""

import socketserver
import threading
import time

import pytest

from espilon_probe.backends import virtual as vmod
from espilon_probe.backends.virtual import VirtualBackend
from espilon_probe.core import wire


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _serve_never_ending(caps, host="127.0.0.1", silent_after_sniff=False):
    """A bridge that, on SNIFF, streams FRAME forever (or goes silent) and never ends it."""

    class _Handler(socketserver.StreamRequestHandler):
        def handle(self):
            r, w = self.rfile, self.wfile
            hello = wire.decode(r)
            if not hello or hello.get("t") != wire.HELLO:
                return
            wire.send(w, wire.welcome(caps))
            msg = wire.decode(r)
            if not msg or msg.get("t") != wire.SNIFF:
                return
            if silent_after_sniff:
                # Never send anything: the client must time out on its own.
                while True:
                    time.sleep(0.05)
            else:
                f = wire.Frame(ts=0.0, channel=0, raw=b"\x01\x02", protocol="x")
                try:
                    while True:
                        wire.send(w, f.to_msg())
                except OSError:
                    return   # client closed; flood stops

    srv = _Server((host, 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


_CAPS = {"protocol": "x", "channels": [], "verbs": ["scan", "sniff", "inject", "replay"],
         "shape": "packet", "pcap_dlt": 147, "meta": {}}


def test_count_bounds_a_never_ending_stream(tmp_path):
    srv, port = _serve_never_ending(_CAPS)
    try:
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            n = b.sniff(str(tmp_path / "c.pcap"), count=5)
        assert n == 5         # stopped exactly at the count, did not run forever
    finally:
        srv.shutdown()
        srv.server_close()


def test_seconds_bounds_a_never_ending_stream(tmp_path):
    srv, port = _serve_never_ending(_CAPS)
    try:
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            start = time.monotonic()
            n = b.sniff(str(tmp_path / "s.pcap"), seconds=0.3)
            elapsed = time.monotonic() - start
        assert elapsed < 5.0          # bounded, nowhere near hanging
        assert n >= 1                 # captured at least something in the window
    finally:
        srv.shutdown()
        srv.server_close()


def test_silent_bridge_times_out_per_recv(tmp_path):
    # The bridge sends nothing after SNIFF: the per-recv socket timeout derived from
    # `seconds` must stop the client rather than block forever on the read.
    srv, port = _serve_never_ending(_CAPS, silent_after_sniff=True)
    try:
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            start = time.monotonic()
            n = b.sniff(str(tmp_path / "q.pcap"), seconds=0.3)
            elapsed = time.monotonic() - start
        assert elapsed < 5.0
        assert n == 0
    finally:
        srv.shutdown()
        srv.server_close()


def _serve_older_bridge(caps, host="127.0.0.1"):
    """A PERSISTENT bridge that models an OLDER packaged bridge: it streams a count-bounded
    capture terminated by its own SNIFF_END, serves an op, and REJECTS any inbound `sniff_end`
    with an error (the older bridges predate the client sending that courtesy message). It records
    every message type it saw so a test can assert the client never sent `sniff_end`.
    """
    seen = {"types": []}

    class _Handler(socketserver.StreamRequestHandler):
        def handle(self):
            r, w = self.rfile, self.wfile
            hello = wire.decode(r)
            if not hello or hello.get("t") != wire.HELLO:
                return
            wire.send(w, wire.welcome(caps))
            while True:
                msg = wire.decode(r)
                if msg is None:
                    return
                t = msg.get("t")
                seen["types"].append(t)
                if t == wire.SNIFF:
                    # Stream exactly `count` frames then the terminating SNIFF_END, all in one
                    # burst, exactly as the real bridge does.
                    want = msg.get("count") or 0
                    f = wire.Frame(ts=0.0, channel=0, raw=b"\xaa\xbb", protocol="x")
                    for _ in range(want):
                        wire.send(w, f.to_msg())
                    wire.send(w, {"t": wire.SNIFF_END, "count": want})
                elif t == wire.OP:
                    wire.send(w, {"t": wire.OP_RESULT, "result": {"echo": msg.get("verb")}})
                elif t == wire.SNIFF_END:
                    # The older bridge does not know this inbound type and rejects it. If the
                    # client (wrongly) sends it, this stray error frame desyncs the next op.
                    wire.send(w, wire.error("unknown message type: sniff_end"))
                else:
                    wire.send(w, wire.error(f"unknown message type: {t}"))

    srv = _Server((host, 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1], seen


def test_sniff_then_op_on_persistent_connection_does_not_desync(tmp_path):
    # QA repro: a sniff followed by another op on a PERSISTENT connection must not desync against a
    # bridge that does not understand an inbound `sniff_end`. The client must (a) NOT send that
    # courtesy message (older bridges reject it, leaving a stray error frame), and (b) drain the
    # bridge's OWN terminating SNIFF_END so the following op reads its real reply, not the marker.
    srv, port, seen = _serve_older_bridge(_CAPS)
    try:
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            n = b.sniff(str(tmp_path / "p.pcap"), count=3)
            assert n == 3
            # The next op on the SAME connection must return ITS OWN result, not a stale SNIFF_END
            # or an "unknown message type" error left in the stream.
            res = b.op("uart.read")
            assert res == {"echo": "uart.read"}
        # The client must never have put an inbound sniff_end on the wire.
        assert wire.SNIFF_END not in seen["types"]
    finally:
        srv.shutdown()
        srv.server_close()


def test_default_ceiling_applies_when_unbounded(monkeypatch, tmp_path):
    # Neither count nor seconds given: a default ceiling must apply (not unbounded capture).
    # Shrink the ceiling so the test is fast, and prove the client stops on it.
    monkeypatch.setattr(vmod, "SNIFF_DEFAULT_SECONDS", 0.3)
    srv, port = _serve_never_ending(_CAPS, silent_after_sniff=True)
    try:
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            start = time.monotonic()
            b.sniff(str(tmp_path / "d.pcap"))
            elapsed = time.monotonic() - start
        assert elapsed < 5.0          # the default ceiling fired
    finally:
        srv.shutdown()
        srv.server_close()
