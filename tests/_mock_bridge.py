"""A tiny wire-protocol server for testing the generalist client in isolation.

This is a ~40-line test fixture that speaks core/wire.py: handshake then a caller-supplied
`respond(msg)->reply`. It lets us test the virtual backend and the CLI against the protocol
without any real target server in the tool repo.
"""

from __future__ import annotations

import select
import socketserver
import threading

from espilon_probe.core import wire


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve_mock(caps: dict, respond, host: str = "127.0.0.1", captured: dict | None = None):
    """Start a mock wire server. `caps` is sent in WELCOME; `respond(msg)` returns a reply
    dict (or None to send nothing). If `captured` is given, the client's HELLO message is
    stored under captured["hello"] (so a test can assert what config the client sent).
    Returns (server, port); call server.shutdown()/.server_close()."""

    class _Handler(socketserver.StreamRequestHandler):
        def handle(self):
            r, w = self.rfile, self.wfile
            hello = wire.decode(r)
            if not hello or hello.get("t") != wire.HELLO:
                return
            if captured is not None:
                captured["hello"] = hello
            wire.send(w, wire.welcome(caps))
            while True:
                msg = wire.decode(r)
                if msg is None:
                    break
                reply = respond(msg)
                if reply is not None:
                    wire.send(w, reply)

    srv = _Server((host, 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def serve_stream_mock(caps: dict, state: dict | None = None, host: str = "127.0.0.1",
                      ready: bool = True):
    """A minimal RAW-STREAM bridge for stream-path tests (the STREAM_ATTACH/READY upgrade).

    `state` (shared across connections) drives a tiny half-duplex console:
      state["fifo"]:   bytearray of pending device->client bytes (seed a banner if wanted);
      state["writes"]: list, each write connection's bytes appended (and echoed into `fifo`).
    A read attach drains `fifo` to the client; a write attach captures the client's bytes and echoes
    them into `fifo` for the next read - so the same write-then-read persistence the real bridges
    have is reproduced here without a pty. When `ready=False` the bridge REFUSES the upgrade (replies
    ERROR instead of STREAM_READY) so a test can assert the client fails clean.

    Returns (server, port); call server.shutdown()/.server_close()."""
    if state is None:
        state = {"fifo": bytearray(), "writes": []}
    state.setdefault("fifo", bytearray())
    state.setdefault("writes", [])
    lock = threading.Lock()

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
                if t == wire.STREAM_ATTACH:
                    if not ready:
                        wire.send(w, wire.error("stream upgrade not available"))
                        return
                    wire.send(w, wire.stream_ready())
                    self._pump(msg.get("mode", "duplex"))
                    return
                if t == wire.SCAN:
                    wire.send(w, {"t": wire.SCAN_RESULT, "items": []})
                else:
                    wire.send(w, wire.error("unhandled"))

        def _pump(self, mode):
            sock = self.connection
            sock.setblocking(True)
            feed = mode in ("read", "duplex")
            while True:
                if feed:
                    with lock:
                        data = bytes(state["fifo"])
                    if data:
                        try:
                            sent = sock.send(data)         # non-destructive: consume only what sent
                        except OSError:
                            return
                        if sent > 0:
                            with lock:
                                del state["fifo"][:sent]
                        if sent < len(data):
                            continue
                rd, _, _ = select.select([sock], [], [], 0.02)
                if not rd:
                    continue
                chunk = sock.recv(4096)
                if not chunk:
                    return
                if mode in ("write", "duplex"):
                    with lock:
                        state["writes"].append(chunk)
                        state["fifo"] += chunk

    srv = _Server((host, 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1], state


def gatt_respond(state: dict):
    """A scripted GATT device for CLI/client tests: write flips state['value'] to the secret."""
    chars = [{"handle": 0x0011, "uuid": "fff1", "props": "read,notify"},
             {"handle": 0x0014, "uuid": "fff2", "props": "write"}]

    def respond(msg):
        t = msg.get("t")
        if t == wire.SCAN:
            return {"t": wire.SCAN_RESULT, "items": [{"name": "MOCK-DEV", "addr": "AA:BB", "rssi": -40}]}
        if t == wire.OP:
            verb = msg.get("verb")
            if verb == "gatt.enum":
                return {"t": wire.OP_RESULT, "result": {"characteristics": chars}}
            if verb == "gatt.read":
                return {"t": wire.OP_RESULT, "result": {"value": state["value"].encode().hex()}}
            if verb == "gatt.write":
                state["value"] = state.get("after", "OPEN")
                return {"t": wire.OP_RESULT, "result": {"ok": True}}
        return wire.error("unhandled")

    return respond


GATT_CAPS = {"protocol": "ble", "channels": [37, 38, 39],
             "verbs": ["scan", "sniff", "inject", "replay", "gatt"], "pcap_dlt": 256, "meta": {}}
