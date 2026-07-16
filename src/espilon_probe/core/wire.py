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
SCAN = "scan"              # client -> server  {t, seconds?, count?}  (seconds/count OPTIONAL, additive)
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

# RAW-STREAM upgrade (docs/design/01-transport.md section 3). A stream protocol (UART) is established
# framed (HELLO/WELCOME, so info/scan/caps still work), then upgraded ONCE, lazily, when the
# first stream DATA verb runs: the client sends STREAM_ATTACH, the bridge replies STREAM_READY,
# and FROM THE BYTE AFTER STREAM_READY BOTH DIRECTIONS ARE RAW BYTES on that connection - no
# length prefix, no JSON, no Frame ever again on that socket. The length-prefix codec below
# (encode/decode/Frame) does NOT apply once STREAM_READY has been sent; it is the whole framed
# wire delta the raw regime introduces. The upgrade is one-way and per-connection (each probe
# invocation is one short-lived connection running one verb).
#
# STREAM_ATTACH carries an optional `mode` in {"read","write","duplex"} - a half-duplex hint the
# bridge uses to pick the pump direction (a `uart read` only reads, a `uart write` only writes),
# so a write connection never has device output pushed at it (which a non-reading client would
# drop) and a read connection is never asked to source data. It defaults to "duplex" so a bridge
# that ignores it, or a future full-duplex console session, still works. The hint is control-only
# and carries no data.
STREAM_ATTACH = "stream_attach"   # client -> bridge   {t, mode}   control-only, no data
STREAM_READY = "stream_ready"     # bridge -> client   {t}         after this: raw bytes

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
        """Build a Frame from an on-wire FRAME message, coercing every field authoritatively.

        A FRAME is attacker-influenced: `ts`/`channel`/`raw` are whatever the target sent. This
        is the one Frame path that used to skip the fields.py discipline (bare `m["ts"]`, bare
        `bytes.fromhex`), so a hostile frame leaked a `KeyError`/`struct.error`/`ValueError`. Now
        `ts` goes through `as_float`, `channel` through `as_int`, and `raw` through the guarded
        `hex_bytes`; any field that cannot be interpreted as its type raises a clean `ProbeError`.
        Callers that capture a stream (see `sniff`) catch that and drop-and-count the bad frame so
        a single hostile frame never aborts a capture.
        """
        from .fields import as_float, as_int, hex_bytes   # local: keep wire import-light for the bridge

        if not isinstance(m, dict):
            from .errors import ProbeError
            raise ProbeError(f"frame is not an object: {m!r}")
        return cls(
            ts=as_float(m.get("ts"), "frame ts"),
            channel=as_int(m.get("channel", 0), "frame channel"),
            raw=hex_bytes(m.get("raw", ""), "frame raw"),
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


def _read_exactly(stream, n: int, before_read=None) -> bytes:
    """Read exactly n bytes from a binary file-like / socket-makefile stream, or b'' at EOF.

    `before_read`, when given, is called immediately before each underlying read. It is the hook
    a bounded caller uses to enforce a TOTAL deadline: it recomputes the remaining budget and
    either shrinks the socket timeout to it or raises `socket.timeout` once the deadline passes.
    Because that hook must run before every socket `recv` (not once per message), the bounded
    path uses `read1`, which issues at most one underlying read per call; a target that dribbles
    one byte at a time therefore cannot hold the stream past the deadline. The unbounded path
    (`before_read is None`) keeps the original `read` behaviour untouched.
    """
    chunks = []
    got = 0
    while got < n:
        if before_read is not None:
            before_read()
            chunk = stream.read1(n - got)
        else:
            chunk = stream.read(n - got)
        if not chunk:
            if got == 0:
                return b""          # clean EOF on a message boundary
            raise ProtocolError("unexpected EOF mid-message")
        chunks.append(chunk)
        got += len(chunk)
    return b"".join(chunks)


def decode(stream, before_read=None) -> dict | None:
    """Read one message from a blocking binary stream. Returns None on clean EOF.

    `before_read` is forwarded to `_read_exactly` so a caller can bound the whole message read by
    a total deadline (see `_read_exactly`)."""
    header = _read_exactly(stream, _LEN.size, before_read)
    if not header:
        return None
    (length,) = _LEN.unpack(header)
    if length > MAX_MSG:
        raise ProtocolError(f"declared message too large: {length}")
    if length == 0:
        # A length prefix that declares an empty body: there is no JSON object to parse and
        # every message must at least carry a type field. This is a malformed frame, not EOF.
        raise ProtocolError("malformed frame: declared body length is zero")
    body = _read_exactly(stream, length, before_read)
    if not body:
        raise ProtocolError("unexpected EOF reading body")
    # A well-framed body can still be junk: non-UTF-8 bytes or non-JSON text. Surface both as a
    # clean ProtocolError, consistent with the other codec faults above (zero-length, over-MAX,
    # EOF-mid-message) rather than leaking the raw stdlib decoder text ("Expecting value: line 1
    # column 1", "'utf-8' codec can't decode byte 0xff...") as the user-facing message.
    try:
        obj = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProtocolError("malformed frame from target") from None
    # A well-framed, valid-JSON body can still be a non-object value: a bare string / number /
    # list, or `null`. Every protocol message is an object carrying a type field, so a non-dict
    # top-level body is malformed. Reject it here rather than let it flow to a caller's
    # `m.get("t")` (which would leak `'str' object has no attribute 'get'`) or - for `null`,
    # which `json.loads` turns into None - be misread as a clean end-of-stream by `recv`.
    if not isinstance(obj, dict):
        raise ProtocolError("malformed message from target")
    return obj


def send(stream, msg: dict) -> None:
    stream.write(encode(msg))
    flush = getattr(stream, "flush", None)
    if flush:
        flush()


def recv(stream, before_read=None) -> dict | None:
    return decode(stream, before_read)


# small constructors so callers do not hand-build dicts
def hello(config: dict | None = None) -> dict:
    """Client greeting. `config` carries client-side link settings the bridge may honour
    (e.g. {"baud": 57600}); it defaults to {} so old callers - and the bridge - keep working.
    """
    return {"t": HELLO, "version": PROTO_VERSION, "config": config or {}}


def welcome(capabilities: dict) -> dict:
    return {"t": WELCOME, "version": PROTO_VERSION, "capabilities": capabilities}


def stream_attach(mode: str = "duplex") -> dict:
    """Client -> bridge: upgrade this connection to a raw byte pipe (docs/design/01 section 3).

    `mode` is the half-duplex direction hint {"read","write","duplex"}; see STREAM_ATTACH above.
    """
    return {"t": STREAM_ATTACH, "mode": mode}


def stream_ready() -> dict:
    """Bridge -> client: the connection is now a raw byte pipe. AFTER this message the socket
    carries raw bytes; the length-prefix codec no longer applies to that connection."""
    return {"t": STREAM_READY}


def error(message: str) -> dict:
    return {"t": ERROR, "msg": message}
