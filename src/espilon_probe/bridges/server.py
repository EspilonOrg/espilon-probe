"""The generic bridge server: speaks core/wire.py, terminates the tunnel into a medium.

It is medium-agnostic - the same server serves any medium, dispatching on the medium's `shape`:

  - a STREAM medium (a real serial port, a pty, a console) answers the framed handshake, then
    upgrades a connection to a raw byte pipe on STREAM_ATTACH and pumps bytes per the half-duplex
    mode hint (docs/design/01 section 3, docs/design/02 sections 1-2);
  - a PACKET medium (a CAN bus, and later sub-GHz / Zigbee capture-replay / the BLE relay) stays
    FRAMED end to end: each verb is a self-contained length-prefixed-JSON transaction over the
    ORIGINAL wire - INJECT/ACK, SNIFF/FRAME/SNIFF_END, REPLAY/REPLAYED, SCAN. There is no
    STREAM_ATTACH analogue and ZERO core/wire.py change (docs/design/can-framed.md sections 0-1).
  - a TRANSACTION medium (BLE GATT, and later SPI / JTAG) also stays FRAMED end to end, but each
    verb is a semantic OP the medium RUNS against a stateful peer: the client sends OP{verb,args},
    the medium performs it (drives the virtual GattServer model, or the real OS stack) and returns
    a result the server echoes back as OP_RESULT. No relay surface (sniff/inject/replay) - those are
    refused. Same ORIGINAL wire, ZERO core/wire.py change (docs/design/ble-gatt.md section 1).

The server keeps ONE medium open and serves connections against it in a loop, so a persistent
bridge accumulates device RX (a stream's OS buffer, a packet medium's frame FIFO) across the
per-verb connections (docs/design/01 section 4). A short-lived auto-spawned bridge just serves one
connection before its parent tears it down.
"""

from __future__ import annotations

import select
import socket
import time

from ..core import wire
from ..core.fields import hex_bytes

# Server-side default capture window for a PACKET sniff that gives count-only / neither bound. The
# client carries its own (larger) wall-clock guard; this only stops take_frames blocking forever, so
# a `dump -c 1` returns the moment its frame is buffered and can never wedge the daemon.
_PACKET_SNIFF_WINDOW = 2.0

# Hard server-side ceiling on a SNIFF `seconds`, whatever the wire value. `seconds` is
# attacker-influenced (it arrives off the wire), so an unbounded value would pin the medium in a
# take_frames wait for effectively forever and wedge the single-serving daemon. The client keeps its
# own (smaller) wall-clock bound; this only caps a hostile/buggy request. 300s is far longer than any
# legitimate interactive capture window yet can never wedge the daemon indefinitely.
_PACKET_SNIFF_MAX = 300.0

# Hard server-side ceiling on a SCAN `seconds` listen window, whatever the wire value. Like the sniff
# ceiling, `seconds` is attacker-influenced (off the wire), so an unbounded value would pin the medium
# in a scan for effectively forever and wedge the single-serving daemon. The client keeps its own
# window; this only caps a hostile/buggy request. Same 300s as the sniff cap.
_SCAN_MAX = 300.0

# Hard server-side ceiling on a SCAN `count` distinct-device early-stop, whatever the wire value.
# Like `seconds`, `count` is attacker-influenced (off the wire); a hostile value cannot pin the
# medium (the listen window still bounds it) but is clamped anyway for symmetry, so a buggy/hostile
# request can never make the medium allocate/track an absurd number of distinct advertisements.
_SCAN_COUNT_MAX = 100000

# Poll cadence for the raw pump: how often we re-check the medium for new RX and the client socket
# for EOF. Well below the client's inter-byte idle gap (UART_READ_IDLE_GAP) so a burst is forwarded
# inside the client's drain window. A wall-clock cadence the fidelity contract lets differ.
_PUMP_POLL = 0.02

# Deadline for a FRAMED control read (the HELLO handshake, and every INJECT/SNIFF/REPLAY/SCAN/
# STREAM_ATTACH request read). The daemon serves ONE connection at a time, so a connection that
# connects and then never makes protocol progress - never sends a valid HELLO, or stalls mid-verb -
# would otherwise wedge the accept loop forever and starve every other client (and stop idle_timeout
# from ever firing). A control read that does not complete within this budget is a dead/silent
# connection: we reap it and return to the accept loop. This bounds ONLY the framed control phase;
# the raw stream pump (an attached interactive console) is deliberately exempt - it can legitimately
# sit with no bytes for minutes and is instead ended by client EOF, not by inactivity. 10s is well
# above any real client's back-to-back HELLO->request latency yet reaps a dead peer promptly.
_CONTROL_READ_TIMEOUT = 10.0

# Listen backlog. The daemon serves one connection at a time and `_pump` holds that connection for
# the whole read, so while a read is in flight the accept() loop is busy - but the KERNEL still
# completes the TCP handshake for new connections into this backlog without the app calling
# accept(). A client's reachability probe (connect + close) therefore succeeds as long as the
# backlog is not full. It must be well above the expected concurrent fan-out (reachability + real
# connects from many first-touches) so a burst never overflows it and makes a probe spuriously fail
# -> which used to be misread as "no daemon" and spawn a second one. 8 was too small.
_LISTEN_BACKLOG = 256


class BridgeServer:
    def __init__(self, medium, host: str = "127.0.0.1", port: int = 0):
        self.medium = medium
        self.host = host
        self.port = port
        self._srv: socket.socket | None = None
        # Per-connection framed-control read deadline (see _CONTROL_READ_TIMEOUT). serve_forever may
        # lower it toward a small idle_timeout; a test can also set it directly for a fast reap.
        self._control_timeout = _CONTROL_READ_TIMEOUT

    def bind(self) -> int:
        """Bind + listen; return the chosen port (so an auto-spawn launcher can read it back)."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(_LISTEN_BACKLOG)
        self._srv = srv
        return srv.getsockname()[1]

    def serve_forever(self, idle_timeout: float | None = None, liveness=None) -> None:
        """Serve connections against the one open medium, one at a time, until asked to stop.

        This is the PERSISTENT-daemon loop (docs/design/00 decision 5, docs/design/02): the bridge holds the
        medium open and its RX FIFO across the discrete per-verb `probe` connections, which is what
        makes a `probe uart write` then a separate `probe uart read` preserve the device's async
        output. Lifetime is bounded so a daemon can never leak:
          - `idle_timeout`: exit after this many seconds with no client connection;
          - `liveness()`: exit when it returns False (the medium hit EOF / went away)."""
        srv = self._srv
        assert srv is not None, "call bind() first"
        # A short idle_timeout also caps the control-read reap, so a daemon that retires quickly
        # never waits the full default control budget on a dead peer first (never lengthen it).
        if idle_timeout is not None:
            self._control_timeout = min(self._control_timeout, idle_timeout)
        # settimeout lets the accept loop wake periodically to check idle-timeout / liveness; a
        # concurrent close() (which clears self._srv and shuts the socket) makes accept raise
        # OSError, ending the loop cleanly rather than tripping an AttributeError on None.
        srv.settimeout(0.5)
        last_active = time.monotonic()
        while True:
            if liveness is not None and not liveness():
                return                          # the medium died: nothing left to serve
            if idle_timeout is not None and (time.monotonic() - last_active) > idle_timeout:
                return                          # idle long enough: retire the daemon
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                self._handle(conn)
            except (OSError, wire.ProtocolError):
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass
            last_active = time.monotonic()

    def close(self) -> None:
        if self._srv is not None:
            try:
                self._srv.close()
            except OSError:
                pass
            self._srv = None

    def _scan_args(self, msg: dict) -> dict:
        """Parse the OPTIONAL listen window / device-count early-stop off a SCAN message into the
        keyword args for `medium.scan(seconds=, count=)`.

        Both fields are attacker-influenced (they arrive off the wire), so each is coerced
        AUTHORITATIVELY and an uninterpretable value falls to None (the medium's own default), NEVER a
        guess. `seconds` and `count` are each clamped to a hard ceiling so a hostile value (e.g. 1e9)
        cannot pin the medium and wedge the single-serving daemon. A field that is absent, the wrong
        type, a bool, or non-positive is treated as "not requested". This is additive: a message with
        neither field is
        the historical bare SCAN and yields `{}` (the medium's default window)."""
        kwargs: dict = {}
        seconds = msg.get("seconds")
        if isinstance(seconds, (int, float)) and not isinstance(seconds, bool) and seconds > 0:
            kwargs["seconds"] = min(float(seconds), _SCAN_MAX)
        count = msg.get("count")
        if isinstance(count, int) and not isinstance(count, bool) and count > 0:
            kwargs["count"] = min(count, _SCAN_COUNT_MAX)
        return kwargs

    def _deadline_before_read(self, conn: socket.socket, deadline: float):
        """A `before_read` hook (see wire._read_exactly) that bounds a framed control read by an
        absolute monotonic deadline: it shrinks the socket timeout to the remaining budget before
        each underlying recv and raises `socket.timeout` once the deadline passes. Because the hook
        runs before EVERY recv (wire uses read1 on the bounded path), a peer that dribbles one byte
        at a time cannot hold the read past the deadline."""
        def before_read() -> None:
            remaining = deadline - time.monotonic()
            if remaining <= 0.0:
                raise socket.timeout("control read deadline exceeded")
            conn.settimeout(remaining)
        return before_read

    def _read_control(self, conn: socket.socket, r) -> dict | None:
        """Read one framed control message under the per-connection deadline. Returns the message,
        or None on a clean client disconnect OR a blown deadline - both mean "stop serving this
        connection" (the caller returns and the accept loop frees up). The socket is reset to
        blocking on the way out so a following send/pump is not left with a stale timeout; on a
        deadline we abandon the connection anyway, so the buffered reader is never reused."""
        deadline = time.monotonic() + self._control_timeout
        try:
            return wire.decode(r, before_read=self._deadline_before_read(conn, deadline))
        except socket.timeout:
            return None
        finally:
            try:
                conn.settimeout(None)
            except OSError:
                pass

    def _handle(self, conn: socket.socket) -> None:
        r = conn.makefile("rb")
        w = conn.makefile("wb")
        # The HELLO handshake read is bounded: a connection that connects and never sends a valid
        # HELLO within the deadline is reaped here rather than wedging the single-serving daemon.
        hello = self._read_control(conn, r)
        if not hello or hello.get("t") != wire.HELLO:
            return
        self.medium.apply_config(hello.get("config") or {})
        wire.send(w, wire.welcome(self.medium.caps()))
        # Dispatch on the medium's shape: a packet medium stays framed (self-contained relay verb
        # transactions), a transaction medium stays framed (semantic OPs the medium runs), a stream
        # medium can upgrade to a raw byte pipe.
        shape = getattr(self.medium, "shape", "stream")
        if shape == "packet":
            self._serve_packet(conn, r, w)
        elif shape == "transaction":
            self._serve_op(conn, r, w)
        else:
            self._serve_stream(conn, r, w)

    def _serve_stream(self, conn: socket.socket, r, w) -> None:
        # Framed control phase. `info` reads WELCOME and closes; `scan` sends SCAN; a stream data
        # verb sends STREAM_ATTACH, after which the socket is raw and we pump. The pre-attach
        # control reads are deadline-bounded (a client that HELLOs then goes silent WITHOUT
        # attaching is reaped); once attached, `_pump` is the exempt long-lived interactive path.
        while True:
            msg = self._read_control(conn, r)
            if msg is None:
                return
            t = msg.get("t")
            if t == wire.STREAM_ATTACH:
                mode = msg.get("mode", "duplex")
                wire.send(w, wire.stream_ready())
                self._pump(conn, mode)
                return
            if t == wire.SCAN:
                wire.send(w, {"t": wire.SCAN_RESULT,
                              "items": self.medium.scan(**self._scan_args(msg))})
            else:
                wire.send(w, wire.error(
                    f"unsupported control message {t!r} on a stream bridge"))

    def _serve_packet(self, conn: socket.socket, r, w) -> None:
        """The generic FRAMED serve path for a shape=="packet" medium (docs/protocols/
        can-framed.md section 4). Every verb is a self-contained length-prefixed-JSON transaction
        on the ORIGINAL wire - the model-free relay a CAN bus (and every future capture/replay
        protocol) reuses. It parses NOTHING protocol-specific: it moves whole frames between the
        wire and the medium's inject()/take_frames() surface. Each verb read is deadline-bounded so
        a packet client that stalls mid-protocol is reaped instead of wedging the daemon."""
        while True:
            msg = self._read_control(conn, r)
            if msg is None:
                return
            t = msg.get("t")
            if t == wire.INJECT:
                self._packet_inject(w, msg)
            elif t == wire.SNIFF:
                self._packet_sniff(w, msg)
            elif t == wire.REPLAY:
                self._packet_replay(w, msg)
            elif t == wire.SCAN:
                wire.send(w, {"t": wire.SCAN_RESULT,
                              "items": self.medium.scan(**self._scan_args(msg))})
            elif t == wire.OP:
                # A packet bus has no connection-oriented op group; refuse clean (the client's
                # capability gate already refuses first, this is defence in depth).
                wire.send(w, wire.error("op group is not supported on a packet bridge"))
            else:
                wire.send(w, wire.error(
                    f"unsupported control message {t!r} on a packet bridge"))

    def _serve_op(self, conn: socket.socket, r, w) -> None:
        """The generic FRAMED serve path for a shape=="transaction" medium (docs/protocols/
        ble-gatt.md section 1). Every verb is a self-contained OP{verb,args} the medium RUNS against
        its stateful peer (the virtual GattServer model, or the real OS stack), returning a result
        the server echoes as OP_RESULT. It parses NOTHING protocol-specific: the medium owns the
        semantics of `verb`/`args`. This is the transaction twin of `_serve_packet`, and the reusable
        serve path SPI and JTAG (also shape=="transaction") inherit later.

        Each OP read is deadline-bounded through the SAME `_read_control` the stream/packet paths use,
        so a transaction client that HELLOs then stalls mid-verb is reaped instead of wedging the
        single-serving daemon. The relay verbs (SNIFF/INJECT/REPLAY) are refused cleanly: a
        transaction peer has no capture/replay surface, and the client's capability gate already
        refuses them first - this is defence in depth (docs/design/ble-gatt.md section 6).

        `medium.op` owns its own authoritative coercion of the untrusted `args`; if it cannot
        interpret an argument it raises, and we surface that as a clean wire ERROR (a loud failure the
        client renders as a nonzero-exit error) rather than guessing a value or wedging the daemon.
        Normal protocol-level errors (e.g. an ATT permission error) are NOT exceptions: the medium
        returns them inside the result dict as `{error: <code>}`, which travels as an ordinary
        OP_RESULT and the client renders deterministically."""
        while True:
            msg = self._read_control(conn, r)
            if msg is None:
                return
            t = msg.get("t")
            if t == wire.OP:
                verb = msg.get("verb")
                args = msg.get("args")
                if not isinstance(args, dict):
                    args = {}
                try:
                    result = self.medium.op(verb, args)
                except Exception as e:
                    # Uninterpretable args / a medium fault: fail loud with a clean wire ERROR so the
                    # client exits nonzero, never a silent pass and never a wedged daemon.
                    wire.send(w, wire.error(f"op {verb!r} failed: {e}"))
                    continue
                wire.send(w, {"t": wire.OP_RESULT, "result": result})
            elif t == wire.SCAN:
                wire.send(w, {"t": wire.SCAN_RESULT,
                              "items": self.medium.scan(**self._scan_args(msg))})
            elif t in (wire.SNIFF, wire.INJECT, wire.REPLAY):
                wire.send(w, wire.error(
                    f"relay verb {t!r} is not supported on a transaction bridge"))
            else:
                wire.send(w, wire.error(
                    f"unsupported control message {t!r} on a transaction bridge"))

    def _packet_inject(self, w, msg: dict) -> None:
        # `frame` is attacker-influenced (it arrives off the wire): coerce it authoritatively and
        # refuse a malformed hex payload instead of leaking a bare fromhex error or transmitting
        # guessed bytes onto the bus.
        try:
            frame = hex_bytes(msg.get("frame", ""), "inject frame")
        except Exception:
            wire.send(w, wire.error("malformed inject frame"))
            return
        self.medium.inject(frame)
        wire.send(w, {"t": wire.ACK})

    def _packet_sniff(self, w, msg: dict) -> None:
        count = msg.get("count")
        if not isinstance(count, int) or isinstance(count, bool):
            count = None
        seconds = msg.get("seconds")
        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
            seconds = None
        channel = msg.get("channel")
        if seconds is not None and seconds > 0:
            # Clamp the attacker-supplied window to a hard ceiling so a huge `seconds` (e.g. 1e9)
            # cannot pin the medium for effectively forever and wedge the single-serving daemon.
            deadline = time.monotonic() + min(float(seconds), _PACKET_SNIFF_MAX)
        else:
            deadline = time.monotonic() + _PACKET_SNIFF_WINDOW
        frames = self.medium.take_frames(count, deadline)
        for raw in frames:
            wire.send(w, wire.Frame(ts=0.0, channel=channel or 0, raw=raw,
                                    direction="rx", protocol="").to_msg())
        wire.send(w, {"t": wire.SNIFF_END, "count": len(frames)})

    def _packet_replay(self, w, msg: dict) -> None:
        frames = msg.get("frames") or []
        if not isinstance(frames, list):
            wire.send(w, wire.error("replay frames is not a list"))
            return
        n = 0
        for hexed in frames:
            try:
                raw = hex_bytes(hexed, "replay frame")
            except Exception:
                wire.send(w, wire.error("malformed replay frame"))
                return
            self.medium.inject(raw)
            n += 1
        wire.send(w, {"t": wire.REPLAYED, "count": n})

    def _pump(self, conn: socket.socket, mode: str) -> None:
        """Raw byte pump after STREAM_READY. The mode hint (docs/design/01 section 3) makes it half-duplex
        and race-free: a read connection is only fed device RX (the client sends nothing), a write
        connection only forwards client bytes to the medium (its device RX is captured by the
        medium's background reader for the NEXT read, never pushed at a non-reading client). Duplex
        forwards both ways for a future full-duplex console session.

        Non-destructive feed (docs/design/02, and the -t0/short-read fix): the RX FIFO is PEEKed and only
        the bytes `send()` actually accepts are `consume`d. So device output the client did not
        receive stays buffered for the next read rather than being cleared into a socket the client
        may close before draining."""
        conn.setblocking(True)
        feed = mode in ("read", "duplex")
        sink = mode in ("write", "duplex")
        while True:
            if feed:
                data = self.medium.peek()
                if data:
                    try:
                        sent = conn.send(data)
                    except OSError:
                        return
                    if sent > 0:
                        self.medium.consume(sent)
                    if sent < len(data):
                        continue            # socket buffer full: retry the rest before polling
            try:
                ready, _, _ = select.select([conn], [], [], _PUMP_POLL)
            except (OSError, ValueError):
                return
            if not ready:
                continue
            try:
                chunk = conn.recv(4096)
            except OSError:
                return
            if not chunk:
                return                      # client closed the connection: done
            if sink:
                self.medium.write(chunk)
            # read-mode stray client bytes are ignored: a read verb sends nothing.
