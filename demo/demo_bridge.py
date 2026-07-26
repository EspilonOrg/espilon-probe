#!/usr/bin/env python3
"""A tiny, self-contained demo target for the probe wire protocol.

Stdlib-only (no espilon_probe import): it reimplements the ~15-line framing from
core/wire.py so the demo GIFs record REAL `probe` output against a believable target.

Speaks the same length-prefixed-JSON wire protocol the virtual backend talks:

    [4-byte big-endian length][UTF-8 JSON object]   # {"t": <type>, ...}

Handshake: client sends HELLO, we reply WELCOME with a scenario's capabilities, then we
answer SCAN / OP / SNIFF / INJECT / REPLAY. Each `--scenario` scripts one demo:

    info          a BLE-ish target for the `probe info` capability line
    zigbee        a packet target: scan a mesh, sniff 802.15.4 frames to a pcap
    gatt          a BLE smart-lock: gatt enum/read/write, state flips on unlock
    spi           a SPI flash (Winbond W25Q128): JEDEC id, read, dump
    solve         a BLE vault: unlock over the protocol, secret handle returns a flag

Run:  python3 demo_bridge.py --scenario gatt --port 5553
Stop: the process is killed by the tape (pkill -f demo_bridge.py). Bind is 127.0.0.1 only.
"""

from __future__ import annotations

import argparse
import json
import socketserver
import struct
import threading
import time

# --- wire framing (mirrors core/wire.py, kept stdlib-only so the demo has no deps) ---
HELLO = "hello"
WELCOME = "welcome"
SCAN = "scan"
SCAN_RESULT = "scan_result"
OP = "op"
OP_RESULT = "op_result"
INJECT = "inject"
ACK = "ack"
REPLAY = "replay"
REPLAYED = "replayed"
SNIFF = "sniff"
FRAME = "frame"
SNIFF_END = "sniff_end"
ERROR = "error"
PROTO_VERSION = 1
_LEN = struct.Struct(">I")


def _read_exactly(stream, n):
    chunks = []
    got = 0
    while got < n:
        chunk = stream.read(n - got)
        if not chunk:
            return b""
        chunks.append(chunk)
        got += len(chunk)
    return b"".join(chunks)


def decode(stream):
    header = _read_exactly(stream, _LEN.size)
    if not header:
        return None
    (length,) = _LEN.unpack(header)
    body = _read_exactly(stream, length)
    if not body:
        return None
    return json.loads(body.decode("utf-8"))


def send(stream, msg):
    body = json.dumps(msg, separators=(",", ":")).encode("utf-8")
    stream.write(_LEN.pack(len(body)) + body)
    stream.flush()


def welcome(caps):
    return {"t": WELCOME, "version": PROTO_VERSION, "capabilities": caps}


def error(msg):
    return {"t": ERROR, "msg": msg}


# --------------------------------------------------------------------------------------
# Scenarios. Each returns (caps, respond, on_sniff). `respond(msg)` answers a single
# request (or None). `on_sniff(msg, send_fn)` streams FRAME messages then SNIFF_END.
# --------------------------------------------------------------------------------------

def _frame(ts, channel, protocol, raw_hex, direction="rx", meta=None):
    return {"t": FRAME, "ts": ts, "channel": channel, "direction": direction,
            "protocol": protocol, "raw": raw_hex, "meta": meta or {}}


def scenario_info():
    caps = {"protocol": "ble", "channels": [37, 38, 39],
            "verbs": ["scan", "sniff", "inject", "replay", "gatt"],
            "shape": "packet", "pcap_dlt": 256, "meta": {}}

    def respond(msg):
        if msg.get("t") == SCAN:
            return {"t": SCAN_RESULT, "items": []}
        return error("info target: nothing to do")

    return caps, respond, None


def scenario_zigbee():
    caps = {"protocol": "zigbee", "channels": list(range(11, 27)),
            "verbs": ["scan", "sniff", "inject", "replay"],
            "shape": "packet", "pcap_dlt": 195, "meta": {}}  # 195 = IEEE802_15_4_WITHFCS

    nodes = [
        {"name": "Coordinator", "addr": "0x0000", "rssi": -41, "pan": "0x1A62"},
        {"name": "Router-Kitchen", "addr": "0x1F3A", "rssi": -58, "pan": "0x1A62"},
        {"name": "Router-Garage", "addr": "0x4C09", "rssi": -66, "pan": "0x1A62"},
        {"name": "Sensor-Door", "addr": "0x8B04", "rssi": -73, "pan": "0x1A62"},
    ]
    # A handful of believable 802.15.4 data frames (FCF=data, dst/src PAN 0x1A62).
    _raws = [
        "6188" + "%02x" % (0x10 + i) + "621a" + "0000" + "3a1f"
        + "48656c6c6f2d5a4947" + "%04x" % (0xC1A0 + i)
        for i in range(24)
    ]

    def respond(msg):
        if msg.get("t") == SCAN:
            return {"t": SCAN_RESULT, "items": nodes}
        if msg.get("t") == INJECT:
            return {"t": ACK}
        if msg.get("t") == REPLAY:
            return {"t": REPLAYED, "count": len(msg.get("frames", []))}
        return error("zigbee target: unhandled")

    def on_sniff(msg, send_fn):
        count = msg.get("count") or 8
        t0 = time.time()
        for i in range(count):
            send_fn(_frame(round(t0 + i * 0.031, 6), 15, "zigbee", _raws[i % len(_raws)],
                           meta={"lqi": 210 - i * 3, "fcs_ok": True}))
        send_fn({"t": SNIFF_END, "count": count})

    return caps, respond, on_sniff


def _ble_lock(initial, secret, dev_name, dev_addr):
    """Shared BLE smart-lock/vault behaviour: enum, read a status handle, write to unlock."""
    caps = {"protocol": "ble", "channels": [37, 38, 39],
            "verbs": ["scan", "sniff", "inject", "replay", "gatt"],
            "shape": "packet", "pcap_dlt": 256, "meta": {}}
    chars = [
        {"handle": 0x0011, "uuid": "fff1", "props": "read,notify"},
        {"handle": 0x0014, "uuid": "fff2", "props": "write"},
    ]
    state = {"value": initial}

    def respond(msg):
        t = msg.get("t")
        if t == SCAN:
            return {"t": SCAN_RESULT,
                    "items": [{"name": dev_name, "addr": dev_addr, "rssi": -52}]}
        if t == OP:
            verb = msg.get("verb")
            if verb == "gatt.enum":
                return {"t": OP_RESULT, "result": {"characteristics": chars}}
            if verb == "gatt.read":
                return {"t": OP_RESULT, "result": {"value": state["value"].encode().hex()}}
            if verb == "gatt.write":
                state["value"] = secret
                return {"t": OP_RESULT, "result": {"ok": True}}
        return error("ble target: unhandled")

    return caps, respond, None


def scenario_gatt():
    return _ble_lock("LOCKED", "UNLOCKED", "SmartLock-A4F2", "C4:7C:8D:66:A4:F2")


def scenario_solve():
    # Demo-only sanitized token. This is NOT a real challenge flag: the public demo must never
    # display a real platform flag string. Keep it obviously-fake so a frame grab can never be
    # mistaken for a leak.
    return _ble_lock("LOCKED", "FLAG{demo_target_unlocked}",
                     "VaultBLE-7F3C", "E8:9F:6D:11:7F:3C")


# A small ASCII boot header at flash offset 0, so a `spi read`/`dump` shows recognizable
# firmware bytes rather than noise. Everything past it is a cheap deterministic pattern,
# generated on demand (no multi-MiB precompute) so `spi dump` of any range stays instant.
_FLASH_HEADER = (b"\xe9\x01\x02\x20" + b"ESP-BOOT v2.1.3\x00"
                 + b"espilon-probe demo flash (W25Q128)\x00")


def _flash_read(addr, length):
    """Deterministic flash bytes for [addr, addr+length): header at 0, patterned fill after."""
    out = bytearray(length)
    for i in range(length):
        gi = addr + i
        out[i] = _FLASH_HEADER[gi] if gi < len(_FLASH_HEADER) else (0xA5 ^ (gi & 0xFF))
    return bytes(out)


def scenario_spi():
    caps = {"protocol": "spi", "channels": [], "verbs": ["scan", "spi"],
            "shape": "transaction", "pcap_dlt": 148, "meta": {}}

    def respond(msg):
        if msg.get("t") != OP:
            if msg.get("t") == SCAN:
                return {"t": SCAN_RESULT, "items": []}
            return error("spi target: unhandled")
        verb = msg.get("verb")
        args = msg.get("args", {})
        if verb == "spi.id":
            return {"t": OP_RESULT, "result": {
                "jedec_id": 0xEF4018, "manufacturer": "Winbond",
                "capacity": "16 MiB", "name": "W25Q128JV"}}
        if verb == "spi.read":
            addr = int(args.get("addr", 0))
            length = int(args.get("len", 0))
            return {"t": OP_RESULT, "result": {"data": _flash_read(addr, length).hex()}}
        if verb == "spi.reg":
            return {"t": OP_RESULT, "result": {"name": args.get("name", "status"),
                                               "value": "0x00"}}
        return error(f"spi target: unhandled verb {verb!r}")

    return caps, respond, None


SCENARIOS = {
    "info": scenario_info,
    "zigbee": scenario_zigbee,
    "gatt": scenario_gatt,
    "spi": scenario_spi,
    "solve": scenario_solve,
}


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def make_handler(caps, respond, on_sniff):
    class _Handler(socketserver.StreamRequestHandler):
        def handle(self):
            r, w = self.rfile, self.wfile
            hello = decode(r)
            if not hello or hello.get("t") != HELLO:
                return
            send(w, welcome(caps))
            while True:
                msg = decode(r)
                if msg is None:
                    break
                if msg.get("t") == SNIFF and on_sniff is not None:
                    on_sniff(msg, lambda m: send(w, m))
                    continue
                reply = respond(msg)
                if reply is not None:
                    send(w, reply)

    return _Handler


def main():
    ap = argparse.ArgumentParser(description="probe demo target")
    ap.add_argument("--scenario", required=True, choices=sorted(SCENARIOS))
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()

    caps, respond, on_sniff = SCENARIOS[args.scenario]()
    srv = _Server((args.host, args.port), make_handler(caps, respond, on_sniff))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    # Block forever; the tape kills the process when the demo is done.
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
