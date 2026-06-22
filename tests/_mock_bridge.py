"""A tiny wire-protocol server for testing the generalist client in isolation.

This is NOT the lab bridge (that lives in the private content repo). It is a ~40-line test
fixture that speaks core/wire.py: handshake then a caller-supplied `respond(msg)->reply`.
It lets us test the virtual backend and the CLI against the protocol without any device or
challenge code in the tool repo.
"""

from __future__ import annotations

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


def gatt_respond(state: dict):
    """A scripted GATT device for CLI/client tests: write flips state['value'] to the flag."""
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
