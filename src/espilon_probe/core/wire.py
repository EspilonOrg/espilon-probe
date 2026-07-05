"""probe wire protocol: framed messages between the virtual backend and a target server.

Boring on purpose: length-prefixed JSON. Each message on the wire is

    [4-byte big-endian length][UTF-8 JSON object]

The JSON object always has a "t" (type) field. Raw protocol PDUs travel hex-encoded in the
JSON ("raw" / "frame" fields) so the stream is debuggable; if profiling ever demands it we
can move bytes to a binary side-channel without changing callers.

Shared by both sides (the bridge imports this module) so client and server cannot drift.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field

PROTO_VERSION = 1

# message types
HELLO = "hello"            # client -> server  {t, version, config}
WELCOME = "welcome"        # server -> client  {t, version, capabilities}
SCAN = "scan"              # client -> server  {t}
SCAN_RESULT = "scan_result"  # server -> client {t, items:[...]}
OP = "op"                  # client -> server  {t, verb, args}
OP_RESULT = "op_result"    # server -> client  {t, result}
INJECT = "inject"          # client -> server  {t, frame, channel}
ACK = "ack"                # server -> client  {t}
REPLAY = "replay"          # client -> server  {t, frames:[hex], filter}
REPLAYED = "replayed"      # server -> client  {t, count}
SNIFF = "sniff"            # client -> server  {t, count, seconds, channel}
FRAME = "frame"            # server -> client  {t, ts, channel, direction, protocol, raw, meta}
SNIFF_END = "sniff_end"    # server -> client  {t, count}
ERROR = "error"            # either direction  {t, msg}

_LEN = struct.Struct(">I")
MAX_MSG = 8 * 1024 * 1024   # 8 MiB ceiling, refuse anything larger


class ProtocolError(Exception):
    pass


@dataclass
class Frame:
    """A normalized protocol frame as carried on the wire."""

    ts: float
    channel: int
    raw: bytes
    direction: str = "rx"          # "rx" sniffed | "tx" injected/replayed
    protocol: str = ""
    meta: dict = field(default_factory=dict)

    def to_msg(self) -> dict:
        return {
            "t": FRAME, "ts": self.ts, "channel": self.channel,
            "direction": self.direction, "protocol": self.protocol,
            "raw": self.raw.hex(), "meta": self.meta,
        }

    @classmethod
    def from_msg(cls, m: dict) -> "Frame":
        return cls(
            ts=m["ts"], channel=m["channel"], raw=bytes.fromhex(m.get("raw", "")),
            direction=m.get("direction", "rx"), protocol=m.get("protocol", ""),
            meta=m.get("meta", {}) or {},
        )


def encode(msg: dict) -> bytes:
    """Serialize a message dict to a length-prefixed frame."""
    if "t" not in msg:
        raise ProtocolError("message missing type field 't'")
    body = json.dumps(msg, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_MSG:
        raise ProtocolError(f"message too large: {len(body)} > {MAX_MSG}")
    return _LEN.pack(len(body)) + body


def _read_exactly(stream, n: int) -> bytes:
    """Read exactly n bytes from a binary file-like / socket-makefile stream, or b'' at EOF."""
    chunks = []
    got = 0
    while got < n:
        chunk = stream.read(n - got)
        if not chunk:
            if got == 0:
                return b""          # clean EOF on a message boundary
            raise ProtocolError("unexpected EOF mid-message")
        chunks.append(chunk)
        got += len(chunk)
    return b"".join(chunks)


def decode(stream) -> dict | None:
    """Read one message from a blocking binary stream. Returns None on clean EOF."""
    header = _read_exactly(stream, _LEN.size)
    if not header:
        return None
    (length,) = _LEN.unpack(header)
    if length > MAX_MSG:
        raise ProtocolError(f"declared message too large: {length}")
    if length == 0:
        # A length prefix that declares an empty body: there is no JSON object to parse and
        # every message must at least carry a type field. This is a malformed frame, not EOF.
        raise ProtocolError("malformed frame: declared body length is zero")
    body = _read_exactly(stream, length)
    if not body:
        raise ProtocolError("unexpected EOF reading body")
    return json.loads(body.decode("utf-8"))


def send(stream, msg: dict) -> None:
    stream.write(encode(msg))
    flush = getattr(stream, "flush", None)
    if flush:
        flush()


def recv(stream) -> dict | None:
    return decode(stream)


# small constructors so callers do not hand-build dicts
def hello(config: dict | None = None) -> dict:
    """Client greeting. `config` carries client-side link settings the bridge may honour
    (e.g. {"baud": 57600}); it defaults to {} so old callers - and the bridge - keep working.
    """
    return {"t": HELLO, "version": PROTO_VERSION, "config": config or {}}


def welcome(capabilities: dict) -> dict:
    return {"t": WELCOME, "version": PROTO_VERSION, "capabilities": capabilities}


def error(message: str) -> dict:
    return {"t": ERROR, "msg": message}
