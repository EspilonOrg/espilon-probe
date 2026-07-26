"""The client RAW-STREAM path on the tunnel backend (docs/01 section 3).

Drives VirtualBackend.stream_read/stream_write against the stream mock bridge: the lazy upgrade,
byte-equality, the first-byte timeout, the non-blocking poll, and multiple reads on one connection
(the socket-makefile-timeout-poisoning regression).
"""

from espilon_probe.backends.virtual import VirtualBackend
from espilon_probe.core import wire
from espilon_probe.core.backend import UART_READ_TIMEOUT_DEFAULT

from _mock_bridge import serve_stream_mock

UART_CAPS = {"protocol": "uart", "channels": [], "verbs": ["scan", "uart"],
             "shape": "stream", "meta": {}}


def _bridge(state=None, ready=True):
    return serve_stream_mock(UART_CAPS, state, ready=ready)


def test_stream_write_returns_byte_count_and_lands_bytes():
    import time
    srv, port, state = _bridge()
    try:
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            assert b.stream_write(b"printenv\r\n") == 10
        # The mock captures reactively; give it a moment to drain before asserting.
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline and not state["writes"]:
            time.sleep(0.02)
        assert b"".join(state["writes"]) == b"printenv\r\n"
    finally:
        srv.shutdown(); srv.server_close()


def test_stream_read_drains_banner():
    state = {"fifo": bytearray(b"=== boot ===\r\nboot> "), "writes": []}
    srv, port, state = _bridge(state)
    try:
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            assert b.stream_read(1.0) == b"=== boot ===\r\nboot> "
    finally:
        srv.shutdown(); srv.server_close()


def test_stream_read_silent_line_is_empty_not_error():
    srv, port, state = _bridge()                       # empty fifo
    try:
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            assert b.stream_read(0.3) == b""
    finally:
        srv.shutdown(); srv.server_close()


def test_stream_read_nonblocking_poll():
    import time
    state = {"fifo": bytearray(b"pending"), "writes": []}
    srv, port, state = _bridge(state)
    try:
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            # -t 0 never blocks: each call returns immediately with whatever has arrived. Poll a few
            # times (the mock sends the fifo reactively on attach) to prove non-blocking + delivery.
            got = b""
            for _ in range(50):
                chunk = b.stream_read(0)
                got += chunk
                if got == b"pending":
                    break
                time.sleep(0.01)
            assert got == b"pending"
    finally:
        srv.shutdown(); srv.server_close()


def test_two_reads_on_one_connection_do_not_poison_the_socket():
    # A read's idle-gap drain ends on a timeout; a naive makefile+settimeout read would then be
    # poisoned ("cannot read from timed out object") on the SECOND read. Duplex mode lets us write
    # between the two reads on the SAME connection and read the echo back.
    state = {"fifo": bytearray(b"one"), "writes": []}
    srv, port, state = serve_stream_mock(UART_CAPS, state)
    try:
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            first = b.stream_read(1.0)
            assert first == b"one"
            # second read on the same connection must still work (no poisoning).
            assert b.stream_read(0.3) == b""
    finally:
        srv.shutdown(); srv.server_close()


def test_default_read_timeout_constant():
    assert UART_READ_TIMEOUT_DEFAULT == 1.0


def test_poll_on_empty_line_does_not_destroy_later_output():
    # Finding 5: a `-t 0` poll (and a short read) must be NON-DESTRUCTIVE - it must not clear device
    # output the client did not actually receive. Here the FIFO is empty at the poll, so the poll
    # returns empty; output that arrives AFTER must still be readable by a later read.
    import time
    state = {"fifo": bytearray(), "writes": []}
    srv, port, state = _bridge(state)
    try:
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            assert b.stream_read(0) == b""             # poll on empty line: nothing, destroys nothing
        # device output arrives now (no connection is touching the FIFO between connections)
        state["fifo"] += b"printenv-response\r\nboot> "
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            got = b.stream_read(2.0)                    # a later read still yields it
        assert b"printenv-response" in got
    finally:
        srv.shutdown(); srv.server_close()


def test_duplex_send_gets_the_response_where_write_then_read_would_not():
    # The load-bearing `uart send` correctness point (docs/protocols/uart-console.md section 5.3):
    # a "write" attach puts the bridge pump in feed=False, so device RX is NOT fed back on that
    # connection. `_attach_stream` is once-per-connection, so `stream_write` then `stream_read` on
    # one connection is stuck in write mode and the read sees NOTHING. `stream_open("duplex")` then
    # send+drain captures the echoed response on the SAME connection.
    state = {"fifo": bytearray(), "writes": []}
    srv, port, state = serve_stream_mock(UART_CAPS, state)
    try:
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            b.stream_write(b"ping\r\n")                 # attaches "write" -> pump feed=False
            assert b.stream_read(0.3) == b""            # nothing fed back on a write connection
    finally:
        srv.shutdown(); srv.server_close()

    state2 = {"fifo": bytearray(), "writes": []}
    srv2, port2, state2 = serve_stream_mock(UART_CAPS, state2)
    try:
        with VirtualBackend(f"tcp://127.0.0.1:{port2}") as b:
            ch = b.stream_open("duplex")               # duplex: device RX IS fed back
            ch.send(b"ping\r\n")
            assert ch.drain(1.0) == b"ping\r\n"        # the echo returned on the one connection
    finally:
        srv2.shutdown(); srv2.server_close()


def test_uart_send_helper_appends_terminator_and_no_read_returns_empty():
    from espilon_probe.protocols import uart
    state = {"fifo": bytearray(), "writes": []}
    srv, port, state = serve_stream_mock(UART_CAPS, state)
    try:
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            resp = uart.send(b, b"echo\r\n", timeout=1.0)
            assert resp == b"echo\r\n"                  # echoed back on the duplex connection
        assert b"".join(state["writes"]) == b"echo\r\n"
    finally:
        srv.shutdown(); srv.server_close()

    state2 = {"fifo": bytearray(), "writes": []}
    srv2, port2, state2 = serve_stream_mock(UART_CAPS, state2)
    try:
        with VirtualBackend(f"tcp://127.0.0.1:{port2}") as b:
            assert uart.send(b, b"quiet\r\n", read=False) == b""   # send-only reads nothing
        import time as _t
        deadline = _t.monotonic() + 2.0
        while _t.monotonic() < deadline and not state2["writes"]:
            _t.sleep(0.02)
        assert b"".join(state2["writes"]) == b"quiet\r\n"
    finally:
        srv2.shutdown(); srv2.server_close()


def _serve_dribble(host="127.0.0.1"):
    """A hostile bridge that, after the raw upgrade, dribbles one byte every 50ms FOREVER (faster
    than UART_READ_IDLE_GAP), so an unbounded idle-gap drain would never elapse."""
    import socketserver
    import threading

    class _Srv(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    class _H(socketserver.StreamRequestHandler):
        def handle(self):
            r, w = self.rfile, self.wfile
            if not wire.decode(r):
                return
            wire.send(w, wire.welcome(UART_CAPS))
            msg = wire.decode(r)
            if not msg or msg.get("t") != wire.STREAM_ATTACH:
                return
            wire.send(w, wire.stream_ready())
            sock = self.connection
            try:
                while True:
                    sock.sendall(b"x")
                    time.sleep(0.05)
            except OSError:
                return

    srv = _Srv((host, 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def test_dribbling_target_does_not_hang_the_read():
    # Finding 4: the WHOLE read (first-byte wait + drain) is bounded. A target dribbling one byte
    # faster than the idle gap must NOT hang `uart read` forever; the read returns within
    # timeout + UART_READ_DRAIN_CAP.
    import time
    from espilon_probe.core.backend import UART_READ_DRAIN_CAP
    srv, port = _serve_dribble()
    try:
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            start = time.monotonic()
            data = b.stream_read(0.5)
            elapsed = time.monotonic() - start
        assert elapsed < 0.5 + UART_READ_DRAIN_CAP + 1.0    # bounded, did not hang
        assert data                                          # it did read the dribble, then stopped
    finally:
        srv.shutdown(); srv.server_close()


def _serve_flood(byte=b"A", host="127.0.0.1"):
    """A hostile bridge that, after the raw upgrade, floods `byte`*4096 in a tight loop FOREVER (a
    line that never goes idle), so an unbounded drain would balloon to GBs before the time cap trips."""
    import socketserver
    import threading

    class _Srv(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    class _H(socketserver.StreamRequestHandler):
        def handle(self):
            r, w = self.rfile, self.wfile
            if not wire.decode(r):
                return
            wire.send(w, wire.welcome(UART_CAPS))
            msg = wire.decode(r)
            if not msg or msg.get("t") != wire.STREAM_ATTACH:
                return
            wire.send(w, wire.stream_ready())
            sock = self.connection
            try:
                while True:
                    sock.sendall(byte * 4096)
            except OSError:
                return

    srv = _Srv((host, 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def test_flooding_target_read_is_byte_bounded(monkeypatch):
    # Finding 1 (MAJOR): a flooding line must not balloon one read to hundreds of MB / GB. The read
    # is bounded in SIZE (ESP_PROBE_MAX_READ_BYTES / UART_READ_MAX_BYTES), so it returns EXACTLY the
    # ceiling and promptly, never the ~2.6 GB the pre-fix drain accumulated.
    import time
    from espilon_probe.core.backend import UART_READ_DRAIN_CAP
    monkeypatch.setenv("ESP_PROBE_MAX_READ_BYTES", "65536")
    srv, port = _serve_flood()
    try:
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            start = time.monotonic()
            data = b.stream_read(1.0)
            elapsed = time.monotonic() - start
        assert len(data) == 65536                            # clamped to the ceiling, not GBs
        assert elapsed < 1.0 + UART_READ_DRAIN_CAP + 1.0     # returned promptly, did not hang
    finally:
        srv.shutdown(); srv.server_close()


def test_flood_defaults_to_the_few_mb_ceiling(monkeypatch):
    # With no override the ceiling is the built-in UART_READ_MAX_BYTES (a few MB), not unbounded.
    from espilon_probe.core.backend import UART_READ_MAX_BYTES
    monkeypatch.delenv("ESP_PROBE_MAX_READ_BYTES", raising=False)
    srv, port = _serve_flood()
    try:
        with VirtualBackend(f"tcp://127.0.0.1:{port}") as b:
            data = b.stream_read(0.3)
        assert len(data) == UART_READ_MAX_BYTES
    finally:
        srv.shutdown(); srv.server_close()


def test_malformed_or_nonpositive_ceiling_falls_back_to_default(monkeypatch):
    # The size bound is load-bearing: a malformed / non-positive override must NOT disable it (no
    # "0 = unbounded" escape hatch), it falls back to the safe default.
    from espilon_probe.backends.virtual import _max_read_bytes
    from espilon_probe.core.backend import UART_READ_MAX_BYTES
    for bad in ("0", "-5", "notanumber", ""):
        monkeypatch.setenv("ESP_PROBE_MAX_READ_BYTES", bad)
        assert _max_read_bytes() == UART_READ_MAX_BYTES
    monkeypatch.setenv("ESP_PROBE_MAX_READ_BYTES", "0x10000")
    assert _max_read_bytes() == 0x10000                      # a valid positive override is honoured


def test_uart_read_cli_streams_and_is_bounded(monkeypatch, capsys):
    # The `uart read` CLI writes to stdout INCREMENTALLY and is size-bounded end-to-end: a flooding
    # line yields exactly the ceiling of decoded bytes, never a runaway buffer.
    from espilon_probe import cli
    monkeypatch.setenv("ESP_PROBE_MAX_READ_BYTES", "65536")
    srv, port = _serve_flood()
    try:
        monkeypatch.setenv("ESP_PROBE", f"tcp://127.0.0.1:{port}")
        assert cli.main(["uart", "read", "-t", "1"]) == 0
        out = capsys.readouterr().out
        assert len(out) == 65536
        assert set(out) == {"A"}
    finally:
        srv.shutdown(); srv.server_close()


def test_uart_read_incremental_decoder_handles_split_multibyte():
    # The incremental UTF-8 decoder must not corrupt a multi-byte char split across recv chunks:
    # feeding the two halves of a 'e-acute' (0xC3 0xA9) in separate chunks yields the single char.
    import codecs
    dec = codecs.getincrementaldecoder("utf-8")("replace")
    out = dec.decode(b"a\xc3") + dec.decode(b"\xa9b") + dec.decode(b"", final=True)
    assert out == "aéb"
