"""Regression tests for the adversarial audit findings.

Each test replays a specific hostile input the auditor used against the client through the mock
wire bridge, and asserts the client now fails clean (a one-line `probe:`/ProbeError) or, for a
capture, drops-and-counts the bad frame instead of tracebacking or hanging. The bar: none of
these may crash (traceback) or hold the client past its advertised bound.
"""

import socketserver
import threading
import time

import pytest

from espilon_probe import cli
from espilon_probe.backends.virtual import VirtualBackend
from espilon_probe.core import frame as pframe
from espilon_probe.core import wire
from espilon_probe.core.errors import ProbeError
from espilon_probe.core.fields import as_float, hex_bytes

from _mock_bridge import serve_mock

_SNIFF_CAPS = {"protocol": "x", "channels": [], "verbs": ["scan", "sniff", "inject", "replay"],
               "shape": "packet", "pcap_dlt": 147, "meta": {}}


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _serve_scripted_sniff(caps, frame_msgs, host="127.0.0.1"):
    """A bridge that, on SNIFF, sends a scripted list of raw FRAME message dicts then a
    terminating SNIFF_END, then keeps serving so a persistent connection stays usable."""

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
            for fm in frame_msgs:
                wire.send(w, fm)
            wire.send(w, {"t": wire.SNIFF_END, "count": len(frame_msgs)})
            try:
                while wire.decode(r) is not None:
                    pass
            except OSError:
                return

    srv = _Server((host, 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _framed(body: bytes) -> bytes:
    """Wrap a raw body in the wire length prefix (bypassing wire.encode's dict/type checks)."""
    return wire._LEN.pack(len(body)) + body


def _serve_raw_sniff(caps, blobs, host="127.0.0.1"):
    """A bridge that, on SNIFF, writes a scripted list of RAW pre-framed message blobs (so a test
    can inject non-object / malformed-JSON / non-UTF-8 / null bodies straight onto the wire) then
    a terminating SNIFF_END, then keeps serving the persistent connection."""

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
            for blob in blobs:
                w.write(blob)
            w.flush()
            wire.send(w, {"t": wire.SNIFF_END, "count": 0})
            try:
                while wire.decode(r) is not None:
                    pass
            except OSError:
                return

    srv = _Server((host, 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _serve_no_end_sniff(caps, blobs, host="127.0.0.1"):
    """A malicious/never-ending bridge that, on SNIFF, writes `blobs` and NEVER sends SNIFF_END,
    then stays quiet. Because it omits SNIFF_END the client always runs `_drain_sniff_end` after
    its own bound trips, so a junk blob at the tail lands squarely in the drain window."""

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
            for blob in blobs:
                w.write(blob)
            w.flush()
            while True:                       # never send SNIFF_END; hold the connection open
                time.sleep(0.05)

    srv = _Server((host, 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _serve_dribble(caps, reply_msg, per_byte=0.3, host="127.0.0.1"):
    """A bridge that WELCOMEs normally, then answers the first request by dribbling the reply one
    byte at a time with `per_byte` seconds between bytes. Each individual byte arrives well inside
    a per-recv timeout; only a TOTAL deadline can bound the client here."""

    class _Handler(socketserver.StreamRequestHandler):
        def handle(self):
            r, w = self.rfile, self.wfile
            hello = wire.decode(r)
            if not hello or hello.get("t") != wire.HELLO:
                return
            wire.send(w, wire.welcome(caps))     # welcome sent in full, so open() is fast
            msg = wire.decode(r)
            if msg is None:
                return
            for byte in wire.encode(reply_msg):
                try:
                    w.write(bytes([byte]))
                    w.flush()
                except OSError:
                    return
                time.sleep(per_byte)

    srv = _Server((host, 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


# --- Finding 1: hostile FRAME ts (1e300 / -1) must not raise struct.error during sniff ---

def test_hostile_ts_does_not_crash_capture(tmp_path):
    # The exact auditor repro: a FRAME whose ts is 1e300 (and one with ts=-1) used to reach
    # struct.pack and raise an uncaught struct.error mid-capture. The ts is numeric, so it is
    # clamped to a representable pcap timestamp and the frame is still captured.
    frames = [
        {"t": wire.FRAME, "ts": 1e300, "channel": 0, "raw": "aabb"},
        {"t": wire.FRAME, "ts": -1, "channel": 0, "raw": "ccdd"},
        {"t": wire.FRAME, "ts": 1.5, "channel": 0, "raw": "eeff"},
    ]
    srv, port = _serve_scripted_sniff(_SNIFF_CAPS, frames)
    try:
        out = str(tmp_path / "hostile_ts.pcap")
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            n = b.sniff(out, count=3)
            assert n == 3                 # all three captured, none dropped, no traceback
            assert b.dropped_frames == 0
        dlt, got = pframe.read_pcap(out)  # the capture is a valid, readable pcap
        assert dlt == 147 and len(got) == 3
    finally:
        srv.shutdown()
        srv.server_close()


def test_pcap_writer_clamps_hostile_ts(tmp_path):
    # Unit: even a directly-constructed Frame with a wild ts (defense in depth) must never make
    # PcapWriter.write raise struct.error.
    out = str(tmp_path / "clamp.pcap")
    with pframe.PcapWriter(out, 147) as pw:
        for ts in (1e300, -1, float("inf"), float("nan"), 10 ** 40, 1.5):
            pw.write(wire.Frame(ts=ts, channel=0, raw=b"\x01\x02"))
    dlt, got = pframe.read_pcap(out)
    assert dlt == 147 and len(got) == 6


def test_pcap_writer_survives_huge_int_ts(tmp_path):
    # Re-audit finding 2: a Python int so large it cannot convert to float (10**400) used to
    # raise OverflowError inside _pcap_ts. PcapWriter must clamp it, never raise.
    out = str(tmp_path / "bigint.pcap")
    with pframe.PcapWriter(out, 147) as pw:
        pw.write(wire.Frame(ts=10 ** 400, channel=0, raw=b"\xaa"))
    dlt, got = pframe.read_pcap(out)
    assert dlt == 147 and got == [b"\xaa"]


# --- Finding 2: malformed FRAME fields are skip-and-count, one bad frame never kills a capture ---

def test_malformed_frames_are_skipped_and_counted(tmp_path):
    # A stream mixing good frames with every malformed shape the auditor sent: missing ts,
    # raw "zz" (non-hex), raw "abc" (odd length), non-numeric channel, non-numeric ts. Each bad
    # frame is dropped and counted; the good frames are captured; the capture never aborts.
    frames = [
        {"t": wire.FRAME, "ts": 1.0, "channel": 0, "raw": "aa"},           # good
        {"t": wire.FRAME, "channel": 0, "raw": "bb"},                      # missing ts -> drop
        {"t": wire.FRAME, "ts": 1.0, "channel": 0, "raw": "zz"},           # non-hex raw -> drop
        {"t": wire.FRAME, "ts": 1.0, "channel": 0, "raw": "abc"},          # odd-len raw -> drop
        {"t": wire.FRAME, "ts": 1.0, "channel": "zz", "raw": "cc"},        # bad channel -> drop
        {"t": wire.FRAME, "ts": "zz", "channel": 0, "raw": "dd"},          # bad ts -> drop
        {"t": wire.FRAME, "ts": 2.0, "channel": 0, "raw": "ee"},           # good
    ]
    srv, port = _serve_scripted_sniff(_SNIFF_CAPS, frames)
    try:
        out = str(tmp_path / "mixed.pcap")
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            n = b.sniff(out, count=2)     # stop once the 2 good frames are captured
            assert n == 2
            assert b.dropped_frames == 5  # all five malformed frames dropped-and-counted
        dlt, got = pframe.read_pcap(out)
        assert dlt == 147 and got == [b"\xaa", b"\xee"]
    finally:
        srv.shutdown()
        srv.server_close()


def test_cli_sniff_surfaces_dropped_count(tmp_path, capsys, monkeypatch):
    # End-to-end: the CLI capture line surfaces the dropped-frame count, and never tracebacks.
    frames = [
        {"t": wire.FRAME, "ts": 1.0, "channel": 0, "raw": "zz"},           # dropped (first)
        {"t": wire.FRAME, "ts": 1.0, "channel": 0, "raw": "aa"},           # good
    ]
    srv, port = _serve_scripted_sniff(_SNIFF_CAPS, frames)
    monkeypatch.setenv("ESP_PROBE", f"tcp://127.0.0.1:{port}")
    try:
        cli.main(["sniff", "--count", "1", "-w", str(tmp_path / "c.pcap")])
        out = capsys.readouterr().out
        assert "captured 1 frame(s)" in out
        assert "1 malformed frame(s) dropped" in out
    finally:
        srv.shutdown()
        srv.server_close()


# --- Re-audit finding 1: a single non-dict / malformed / null wire message must not truncate a
#     capture nor leak a Python type name; it is dropped-and-counted like a malformed dict-frame.

_GOOD_A = {"t": wire.FRAME, "ts": 1.0, "channel": 0, "raw": "aa"}
_GOOD_B = {"t": wire.FRAME, "ts": 2.0, "channel": 0, "raw": "bb"}


def test_non_object_and_malformed_messages_are_dropped_and_counted(tmp_path):
    # Between two good frames, inject every hostile-but-well-framed message the re-audit used:
    # a JSON string, a number, a list, a malformed-JSON body, a non-UTF-8 body, and a `null`.
    # Each must be dropped-and-counted, the two good frames survive, and the capture completes.
    blobs = [
        wire.encode(_GOOD_A),
        _framed(b'"x"'),          # valid JSON, non-object (string)
        _framed(b'123'),          # valid JSON, non-object (number)
        _framed(b'[1,2]'),        # valid JSON, non-object (list)
        _framed(b'not json{'),    # malformed JSON
        _framed(b'\xff\xfe\xfd'), # non-UTF-8
        _framed(b'null'),         # JSON null -> must NOT be read as clean EOF
        wire.encode(_GOOD_B),
    ]
    srv, port = _serve_raw_sniff(_SNIFF_CAPS, blobs)
    try:
        out = str(tmp_path / "raw.pcap")
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            n = b.sniff(out, count=2)     # stop once both good frames are captured
            assert n == 2
            assert b.dropped_frames == 6  # all six hostile messages dropped-and-counted
        dlt, got = pframe.read_pcap(out)
        assert dlt == 147 and got == [b"\xaa", b"\xbb"]
    finally:
        srv.shutdown()
        srv.server_close()


def test_null_message_is_not_treated_as_eof(tmp_path):
    # A JSON `null` mid-capture used to decode to None and be read as clean EOF, ending the
    # capture early. It must now be dropped-and-counted so the frame after it still lands.
    blobs = [wire.encode(_GOOD_A), _framed(b'null'), wire.encode(_GOOD_B)]
    srv, port = _serve_raw_sniff(_SNIFF_CAPS, blobs)
    try:
        out = str(tmp_path / "null.pcap")
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            n = b.sniff(out, count=2)
            assert n == 2                 # the frame AFTER the null survived (null was not EOF)
            assert b.dropped_frames == 1
        dlt, got = pframe.read_pcap(out)
        assert got == [b"\xaa", b"\xbb"]
    finally:
        srv.shutdown()
        srv.server_close()


def test_cli_capture_with_hostile_messages_exits_clean(tmp_path, capsys, monkeypatch):
    # End-to-end: a capture peppered with hostile messages exits 0, surfaces the dropped count,
    # and leaks no Python type name (`'str' object has no attribute 'get'`).
    blobs = [_framed(b'"x"'), wire.encode(_GOOD_A)]
    srv, port = _serve_raw_sniff(_SNIFF_CAPS, blobs)
    monkeypatch.setenv("ESP_PROBE", f"tcp://127.0.0.1:{port}")
    try:
        rc = cli.main(["sniff", "--count", "1", "-w", str(tmp_path / "c.pcap")])
        assert rc == 0
        out = capsys.readouterr().out
        assert "captured 1 frame(s)" in out
        assert "1 malformed frame(s) dropped" in out
        assert "has no attribute" not in out
        assert "'str'" not in out
    finally:
        srv.shutdown()
        srv.server_close()


def test_decode_rejects_non_object_body():
    # Unit: wire.decode refuses a non-dict top-level body with the clean wording family, never a
    # Python type name, and (crucially) a `null` body is NOT the None returned for clean EOF.
    import io
    for body in (b'"x"', b'123', b'[1,2]', b'null'):
        try:
            wire.decode(io.BytesIO(_framed(body)))
        except wire.ProtocolError as e:
            assert "malformed message from target" in str(e)
            assert "object has no attribute" not in str(e)
        else:
            raise AssertionError(f"expected ProtocolError for non-object body {body!r}")
    # A truly empty stream (no header) is still a clean EOF -> None, unchanged.
    assert wire.decode(io.BytesIO(b"")) is None


# --- Final re-audit finding: a malformed message in the POST-BOUND drain window (the normal case
#     for a bridge that never sends SNIFF_END) must not abort a capture whose good frames already
#     landed, and must still be reflected in the dropped-note. ---

def test_count_bound_then_malformed_in_drain_does_not_abort(tmp_path):
    # count=2: the loop stops right after the 2nd good frame (leaving the junk buffered for the
    # drain), the bridge never sends SNIFF_END so `_drain_sniff_end` always runs. The junk in the
    # drain window must be drop-and-counted, not raised, and the two good frames must survive.
    blobs = [wire.encode(_GOOD_A), wire.encode(_GOOD_B), _framed(b'not json{')]
    srv, port = _serve_no_end_sniff(_SNIFF_CAPS, blobs)
    try:
        out = str(tmp_path / "drain.pcap")
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            start = time.monotonic()
            n = b.sniff(out, count=2)         # must NOT raise ProtocolError
            elapsed = time.monotonic() - start
        assert n == 2                         # both good frames captured
        assert b.dropped_frames == 1          # the drained junk stayed in the count
        assert elapsed < 5.0                  # drain terminated on its own grace, did not spin/hang
        dlt, got = pframe.read_pcap(out)
        assert dlt == 147 and got == [b"\xaa", b"\xbb"]
    finally:
        srv.shutdown()
        srv.server_close()


def test_seconds_bound_then_malformed_in_drain_does_not_abort(tmp_path):
    # seconds=0 makes the top-of-loop bound trip immediately (bound_reached, nothing read in-loop),
    # so the first buffered message lands in the drain window. A junk message there must be
    # drop-and-counted on the seconds-bound path too, never raised.
    blobs = [_framed(b'"x"')]
    srv, port = _serve_no_end_sniff(_SNIFF_CAPS, blobs)
    try:
        out = str(tmp_path / "drain_s.pcap")
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            start = time.monotonic()
            n = b.sniff(out, seconds=0)       # must NOT raise
            elapsed = time.monotonic() - start
        assert n == 0
        assert b.dropped_frames == 1          # the drain-window junk was counted
        assert elapsed < 5.0
    finally:
        srv.shutdown()
        srv.server_close()


def test_cli_capture_junk_in_drain_reports_captured_and_dropped(tmp_path, capsys, monkeypatch):
    # End-to-end deterministic repro: count=2 with junk in the drain window must exit 0, print the
    # `captured 2 frame(s)` line AND the dropped-note (the operator must not see a failed capture
    # that actually succeeded), and leak no Python type name.
    blobs = [wire.encode(_GOOD_A), wire.encode(_GOOD_B), _framed(b'not json{')]
    srv, port = _serve_no_end_sniff(_SNIFF_CAPS, blobs)
    monkeypatch.setenv("ESP_PROBE", f"tcp://127.0.0.1:{port}")
    try:
        rc = cli.main(["sniff", "--count", "2", "-w", str(tmp_path / "c.pcap")])
        assert rc == 0
        out = capsys.readouterr().out
        assert "captured 2 frame(s)" in out
        assert "1 malformed frame(s) dropped" in out
        assert "malformed frame from target" not in out    # not surfaced as a failure line
        assert "has no attribute" not in out
    finally:
        srv.shutdown()
        srv.server_close()


# --- Finding 3: gatt display / uart bypassed the coercion contract ---

def test_gatt_enum_stringy_handle_renders_clean(capsys, monkeypatch):
    # gatt.enum returns handle:"0x11" (a string); the display must coerce it via as_int and render
    # 0x0011, never leak a format/`int()` error.
    caps = {"protocol": "ble", "channels": [], "verbs": ["scan", "gatt"], "pcap_dlt": 256,
            "meta": {}}

    def respond(msg):
        if msg.get("t") == wire.OP and msg.get("verb") == "gatt.enum":
            return {"t": wire.OP_RESULT,
                    "result": {"characteristics": [{"handle": "0x11", "uuid": "fff1",
                                                    "props": "read"}]}}
        return wire.error("unhandled")

    srv, port = serve_mock(caps, respond)
    monkeypatch.setenv("ESP_PROBE", f"tcp://127.0.0.1:{port}")
    try:
        cli.main(["gatt", "enum"])
        out = capsys.readouterr().out
        assert "0x0011" in out and "fff1" in out
    finally:
        srv.shutdown()
        srv.server_close()


def test_gatt_enum_null_result_is_clean(capsys, monkeypatch):
    # gatt.enum returns an explicit null result; it must be a clean ProbeError, not an
    # AttributeError from `.get()` on None.
    caps = {"protocol": "ble", "channels": [], "verbs": ["scan", "gatt"], "pcap_dlt": 256,
            "meta": {}}

    def respond(msg):
        if msg.get("t") == wire.OP and msg.get("verb") == "gatt.enum":
            return {"t": wire.OP_RESULT, "result": None}
        return wire.error("unhandled")

    srv, port = serve_mock(caps, respond)
    monkeypatch.setenv("ESP_PROBE", f"tcp://127.0.0.1:{port}")
    try:
        with pytest.raises(SystemExit) as ei:
            cli.main(["gatt", "enum"])
        msg = str(ei.value)
        assert "null result for gatt.enum" in msg
        assert "has no attribute" not in msg
    finally:
        srv.shutdown()
        srv.server_close()


def test_uart_stream_upgrade_refused_is_clean(capsys, monkeypatch):
    # UART is RAW-STREAM: `uart read`/`uart write` no longer travel as hex-in-JSON `op()` results
    # (the old malformed-hex/null-result surfaces are gone with the transaction path). The
    # attacker surface is now the upgrade handshake: a bridge that answers STREAM_ATTACH with
    # anything but STREAM_READY must fail clean, not hang or traceback.
    from _mock_bridge import serve_stream_mock
    caps = {"protocol": "uart", "channels": [], "verbs": ["uart"], "shape": "stream", "meta": {}}
    srv, port, _ = serve_stream_mock(caps, ready=False)     # refuses the raw upgrade
    monkeypatch.setenv("ESP_PROBE", f"tcp://127.0.0.1:{port}")
    try:
        with pytest.raises(SystemExit) as ei:
            cli.main(["uart", "read", "-t", "1"])
        assert "stream upgrade refused" in str(ei.value)
    finally:
        srv.shutdown()
        srv.server_close()


def test_stream_verb_on_framed_backend_is_clean():
    # A FRAMED backend inherits Backend's clean refusal for the stream data path, so a stream verb
    # routed at the wrong protocol is a one-line ProbeError, never an AttributeError/traceback.
    from espilon_probe.core.backend import Backend

    class _Framed(Backend):
        def open(self): ...
        def close(self): ...
        def capabilities(self): ...
        def scan(self): return []
        def sniff(self, *a, **k): return 0
        def inject(self, *a, **k): ...
        def replay(self, *a, **k): return 0
        def op(self, verb, **kw): return {}

    b = _Framed()
    with pytest.raises(ProbeError) as ei_r:
        b.stream_read(1.0)
    assert "not a byte stream" in str(ei_r.value)
    with pytest.raises(ProbeError) as ei_w:
        b.stream_write(b"x")
    assert "not a byte stream" in str(ei_w.value)


# --- Finding 4: a byte-dribbling target must not exceed the advertised TOTAL deadline ---

def test_dribbling_target_control_path_is_total_bounded(monkeypatch):
    # A target that dribbles the reply one byte every 0.3s used to hold the client for
    # (reply_bytes * 0.3)s because the timeout was per-recv. With a TOTAL deadline it must give up
    # within ~ESP_PROBE_TIMEOUT, well under the un-bounded time.
    monkeypatch.setenv("ESP_PROBE_TIMEOUT", "0.5")
    reply = {"t": wire.SCAN_RESULT, "items": [{"name": "X" * 40, "addr": "AA:BB", "rssi": -40}]}
    srv, port = _serve_dribble(_SNIFF_CAPS, reply, per_byte=0.3)
    try:
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            start = time.monotonic()
            with pytest.raises(ProbeError) as ei:
                b.scan()
            elapsed = time.monotonic() - start
        assert elapsed < 3.0             # bounded by the 0.5s total deadline, not ~15s of dribble
        assert "silent" in str(ei.value).lower()
    finally:
        srv.shutdown()
        srv.server_close()


def test_dribbling_target_sniff_is_total_bounded(tmp_path, monkeypatch):
    # Same dribble against a sniff: a frame that arrives one byte at a time must not hold the
    # capture past its wall-clock bound.
    frame = {"t": wire.FRAME, "ts": 1.0, "channel": 0, "raw": "aa" * 40}
    srv, port = _serve_dribble(_SNIFF_CAPS, frame, per_byte=0.3)
    try:
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            start = time.monotonic()
            n = b.sniff(str(tmp_path / "d.pcap"), seconds=0.4)
            elapsed = time.monotonic() - start
        assert elapsed < 3.0             # the seconds bound tripped, dribble did not hold it
        assert n == 0                    # the frame never completed within the window
    finally:
        srv.shutdown()
        srv.server_close()


# --- Finding 5: replay count / endpoint port coercion ---

def test_replay_stringy_count_is_clean(tmp_path, monkeypatch):
    # The backend returns a non-numeric replay `count`; it must be coerced (clean ProbeError),
    # never printed verbatim as `replayed <junk> frame(s)`.
    caps = {"protocol": "x", "channels": [], "verbs": ["scan", "replay"], "shape": "packet",
            "pcap_dlt": 147, "meta": {}}

    def respond(msg):
        if msg.get("t") == wire.REPLAY:
            return {"t": wire.REPLAYED, "count": "lots"}
        return wire.error("unhandled")

    # a minimal valid DLT-147 pcap to replay
    p = tmp_path / "in.pcap"
    with pframe.PcapWriter(str(p), 147) as pw:
        pw.write(wire.Frame(ts=1.0, channel=0, raw=b"\x01"))

    srv, port = serve_mock(caps, respond)
    try:
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            with pytest.raises(ProbeError) as ei:
                b.replay(str(p))
            assert "non-numeric replay count" in str(ei.value)
    finally:
        srv.shutdown()
        srv.server_close()


def test_can_send_bad_hex_is_clean():
    # `can.send` re-parsed operator hex with a bare `bytes.fromhex`; a direct library caller with
    # bad hex must get a clean ProbeError, not the leaked `non-hexadecimal ...` text.
    from espilon_probe.protocols import can

    class _NoInject:
        def inject(self, *a, **k):
            raise AssertionError("must not reach inject on bad hex")

    with pytest.raises(ProbeError) as ei:
        can.send(_NoInject(), 0x123, "zz")
    msg = str(ei.value)
    assert "invalid CAN payload hex" in msg
    assert "fromhex" not in msg and "non-hexadecimal" not in msg


def test_non_numeric_port_is_clean_message():
    b = VirtualBackend("tcp://127.0.0.1:notaport")
    with pytest.raises(RuntimeError) as ei:
        b.open()
    msg = str(ei.value)
    assert "not a number" in msg
    assert "invalid literal" not in msg   # no leaked int() text


def test_out_of_range_port_is_clean_message():
    b = VirtualBackend("tcp://127.0.0.1:99999")
    with pytest.raises(RuntimeError) as ei:
        b.open()
    assert "out of range" in str(ei.value)


# --- unit coverage for the new coercion helpers ---

def test_as_float_accepts_numbers_rejects_junk():
    assert as_float(1, "x") == 1.0
    assert as_float(1.5, "x") == 1.5
    assert as_float("2.5", "x") == 2.5
    for bad in (None, True, "zz", 10 ** 400):
        with pytest.raises(ProbeError):
            as_float(bad, "x")


def test_hex_bytes_rejects_non_string_and_bad_hex():
    assert hex_bytes("aabb", "x") == b"\xaa\xbb"
    with pytest.raises(ProbeError):
        hex_bytes(123, "x")
    with pytest.raises(ProbeError):
        hex_bytes("zz", "x")
    with pytest.raises(ProbeError):
        hex_bytes("abc", "x")     # odd length
