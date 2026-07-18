"""Virtual backend: talks the probe wire protocol over TCP to a target server.

The default backend. Point it at the target endpoint:
    export ESP_PROBE=tcp://host:port
Verbs map straight onto the wire protocol. No analysis here; capture is standard pcap.

Every request/response transaction is bounded by a client-side read timeout (ESP_PROBE_TIMEOUT
seconds, default 30) so a silent or wedged target fails clean instead of hanging; `sniff` keeps
its own separate bounded-capture budget.
"""

from __future__ import annotations

import os
import select
import socket
import struct
import time

from ..core import wire
from ..core.backend import (
    UART_READ_DRAIN_CAP,
    UART_READ_IDLE_GAP,
    UART_READ_MAX_BYTES,
    Backend,
    Capabilities,
)
from ..core.errors import ProbeError

# Client-side ceiling for a single request/response transaction (info/scan/inject/replay and
# every protocol op). A wedged or silent target must never hang the client: every control-path
# recv is bounded by this budget, after which we raise a clean error instead of blocking
# forever. Overridable via ESP_PROBE_TIMEOUT (seconds); a value <= 0 disables the bound and
# restores the historical blocking read. `sniff` is NOT governed by this: it carries its own
# bounded-capture budget (see below).
TXN_DEFAULT_TIMEOUT = 30.0

# Hard client-side ceiling for a sniff when the operator gives neither count nor seconds.
# The tool always stops on its own; it never trusts the bridge to end a capture.
SNIFF_DEFAULT_SECONDS = 30.0
# Wall-clock guard so a wedged/never-ending bridge can never hang the client. It is the
# requested duration plus a small margin, or a fixed ceiling when only `count` was given.
SNIFF_COUNT_ONLY_TIMEOUT = 60.0
SNIFF_TIMEOUT_MARGIN = 5.0
# Grace window to consume the single trailing SNIFF_END a conformant bridge sends to terminate a
# capture, once our own bound has tripped. The bridge sends it in the same burst as the frames, so
# it is already buffered and the wait is effectively zero; this only caps how long we wait for a
# bridge that omits it, so the client can never wedge here.
SNIFF_END_DRAIN_GRACE = 0.5
# Extra head-room over a requested scan listen window before the control-path deadline trips. A
# `scan -t 15` (or a long fob-collection window) legitimately holds the single SCAN transaction open
# for the whole window; without this the default TXN_DEFAULT_TIMEOUT (30s) would cut a longer window
# off mid-listen. It only ever EXTENDS the budget, never shrinks it below the normal txn deadline.
SCAN_TXN_MARGIN = 5.0


def _txn_timeout() -> float | None:
    """The finite control-path read deadline, in seconds, or None if the operator disabled it.

    Reads ESP_PROBE_TIMEOUT when set; a malformed value falls back to the safe default rather
    than silently removing the bound (an unparseable timeout must never leave the client able
    to hang). A value <= 0 explicitly disables the bound (blocking read)."""
    raw = os.environ.get("ESP_PROBE_TIMEOUT")
    if raw is None:
        return TXN_DEFAULT_TIMEOUT
    try:
        val = float(raw)
    except ValueError:
        return TXN_DEFAULT_TIMEOUT
    return val if val > 0 else None


def _as_list(value) -> list:
    """A capabilities field that the contract says is a LIST (verbs / channels), coerced.

    A conformant bridge sends a JSON array. A non-list value - a bare string, an object, null - is
    coerced to the EMPTY list rather than trusted: a lying/sloppy bridge that sends `verbs` as the
    string "uart" would otherwise pass the substring-based capability gate (`"uart" in "scan,uart"`)
    and drive `probe info` char-by-char. Refusing (empty) is the conservative direction: an
    unadvertised verb fails loud instead of being silently granted by a string membership accident."""
    return value if isinstance(value, list) else []


def _max_read_bytes() -> int:
    """The byte ceiling for a single stream read/drain, in bytes.

    Reads ESP_PROBE_MAX_READ_BYTES when set (a positive int, decimal or 0x hex); a malformed or
    non-positive override falls back to UART_READ_MAX_BYTES rather than silently removing the
    ceiling. The size bound is load-bearing against a flooding line (a memory-DoS) and must never be
    disabled by a typo, so - unlike the txn timeout - there is no "value <= 0 means unbounded" escape
    hatch here."""
    raw = os.environ.get("ESP_PROBE_MAX_READ_BYTES")
    if raw is None:
        return UART_READ_MAX_BYTES
    try:
        val = int(raw, 0)
    except (ValueError, TypeError):
        return UART_READ_MAX_BYTES
    return val if val > 0 else UART_READ_MAX_BYTES


class StreamChannel:
    """A thin, stdlib-only duplex wrapper over an attached raw byte pipe.

    It is the one client surface a byte pump (the interactive `uart console`, the atomic
    `uart send`, and `stream_read`) needs: the already-connected raw socket plus the backlog
    `_attach_stream` captured past STREAM_READY. It exposes ONLY fileno/take_backlog/recv/send/
    drain and holds no wire/UART/baud knowledge, so any `shape == "stream"` protocol reuses it.

    `take_backlog()` is load-bearing: after the framed STREAM_READY read, the makefile may have
    already pulled the bridge's first raw bytes (a banner) into a Python buffer; those bytes are
    INVISIBLE to `select()` on the raw socket (they left the socket). A pump MUST consume the
    backlog before selecting on the fd, or those first bytes are lost or delayed. `drain()` is the
    ONE home for the first-byte-wait + idle-gap + UART_READ_DRAIN_CAP read algorithm, so
    `stream_read`, `uart send`, and the console cannot drift on how a read is bounded.
    """

    def __init__(self, sock: socket.socket, backlog: bytes = b""):
        self._sock = sock
        self._backlog = backlog

    def fileno(self) -> int:
        """The raw socket fd, for `select()`."""
        return self._sock.fileno()

    def take_backlog(self) -> bytes:
        """The bytes the makefile buffered past STREAM_READY, returned ONCE (b"" thereafter).

        Invisible to `select()` (they already left the socket), so a pump consumes these before
        entering its select loop or the first device bytes are lost/delayed."""
        b = self._backlog
        self._backlog = b""
        return b

    def recv(self, bufsize: int = 65536) -> bytes:
        """One raw socket recv. b"" means EOF (the bridge / medium closed - remote close). Meant to
        be called only when `select()` reports the fd readable, so it does not block."""
        return self._sock.recv(bufsize)

    def send(self, data: bytes) -> int:
        """Send raw bytes on the pipe (sendall). Returns len(data)."""
        self._sock.sendall(data)
        return len(data)

    def drain(self, timeout: float, max_bytes: int | None = None) -> bytes:
        """Wait up to `timeout` for the first byte, then drain until one UART_READ_IDLE_GAP of idle.
        An empty result on a silent line is not an error.

        A thin buffering front over `drain_into`: accumulate the drained chunks and return them as
        one `bytes`. It carries the same bounds (see `drain_into`); a caller that must not hold the
        whole read in memory (e.g. `uart read` -> stdout) uses `drain_into` with a streaming sink."""
        chunks: list[bytes] = []
        self.drain_into(timeout, chunks.append, max_bytes=max_bytes)
        return b"".join(chunks)

    def drain_into(self, timeout: float, sink, max_bytes: int | None = None) -> int:
        """The ONE drain algorithm: wait up to `timeout` for the first byte, then read until the
        line is idle for one UART_READ_IDLE_GAP, feeding each received chunk to `sink(bytes)` as it
        arrives. Returns the number of bytes drained.

        `-t 0` is a BOUNDED poll, not a zero-wait: it still waits up to one idle gap for the first
        byte. This is deliberate and load-bearing for NON-DESTRUCTIVENESS: a bridge hands device
        output to the OS socket on attach and then removes it from its FIFO, so if the poll returned
        before those in-flight bytes were received they would be lost on close. Waiting one idle gap
        lets the client actually RECEIVE whatever the bridge sent, so a poll/short read can never
        destroy device output (it is delivered to this read, or - if the bridge sent nothing - left
        in the FIFO for the next read). A too-short `-t` is floored to the idle gap for the same
        reason.

        BOUNDED IN TIME: the whole read (first-byte wait + drain) returns within
        `timeout + UART_READ_DRAIN_CAP`. Without the cap a target dribbling one byte faster than the
        idle gap would keep the drain from ever elapsing and hang the read forever.

        BOUNDED IN SIZE: at most `max_bytes` (default `_max_read_bytes()`, override
        ESP_PROBE_MAX_READ_BYTES) are drained. A flooding line that never goes idle would otherwise
        let one read grow without bound (a memory-DoS); once the ceiling is reached the read stops
        and returns, and the last chunk is clamped so the total is EXACTLY the ceiling, never over.

        The drain loop keeps reading until the socket is quiet for one idle gap (or a bound trips),
        so by the time it returns every byte the bridge sent that fits under the ceiling has been
        received (nothing that fits is stranded in the socket buffer for the close to discard).

        Uses `select` + raw recv (never `settimeout` on the makefile, which poisons it after a
        timeout - "cannot read from timed out object" - and would break a second read on one
        connection). Any bytes the framed STREAM_READY recv buffered are consumed first."""
        if max_bytes is None:
            max_bytes = _max_read_bytes()
        start = time.monotonic()
        total_deadline = start + max(0.0, timeout) + UART_READ_DRAIN_CAP
        # First-byte wait is floored to one idle gap so an in-flight byte the bridge already sent is
        # received (not lost) even for `-t 0` / a too-short timeout.
        first_wait = max(max(0.0, timeout), UART_READ_IDLE_GAP)
        total = 0

        def emit(data: bytes) -> bool:
            """Feed `data` to the sink, clamped so the running total never exceeds the byte
            ceiling. Returns True once the ceiling is reached (the caller must then stop reading)."""
            nonlocal total
            room = max_bytes - total
            if len(data) > room:
                data = data[:room]
            if data:
                sink(data)
                total += len(data)
            return total >= max_bytes

        backlog = self.take_backlog()
        if backlog:
            if emit(backlog):
                return total
        else:
            first = self._select_recv(min(first_wait, total_deadline - time.monotonic()))
            if not first:
                return total
            if emit(first):
                return total
        while True:
            remaining = total_deadline - time.monotonic()
            if remaining <= 0:
                break
            more = self._select_recv(min(UART_READ_IDLE_GAP, remaining))
            if not more:
                break
            if emit(more):
                break
        return total

    def _select_recv(self, timeout: float) -> bytes:
        """One bounded raw read: wait up to `timeout` for readability, then a single recv. b"" on
        timeout OR EOF (both stop a drain). `timeout <= 0` polls non-blocking."""
        sock = self._sock
        if sock is None:
            return b""
        try:
            ready, _, _ = select.select([sock], [], [], max(0.0, timeout))
        except (OSError, ValueError):
            return b""
        if not ready:
            return b""
        try:
            return sock.recv(65536)
        except (BlockingIOError, socket.timeout):
            return b""
        except OSError:
            return b""


# The client-side label shown by `probe info` (Capabilities.transport). The tunnel client is
# generic; a loopback launcher (serial, ...) relabels it so `info` names the medium the user
# selected, even though the wire and the client code are identical.
class VirtualBackend(Backend):
    _transport_label = "virtual"

    def __init__(self, target: str | None = None, baud: int = 115200):
        self.target = target or os.environ.get("ESP_PROBE")
        self.baud = baud
        self._sock: socket.socket | None = None
        self._r = None
        self._w = None
        self._caps: dict = {}
        self._stream = False        # True once this connection has upgraded to a raw byte pipe
        self._stream_buf = b""      # raw bytes the makefile buffered past STREAM_READY (see attach)

    def _endpoint(self) -> tuple[str, int]:
        t = self.target
        if not t:
            raise RuntimeError(
                "no target endpoint: set ESP_PROBE=tcp://host:port or pass --target")
        if t.startswith("tcp://"):
            t = t[len("tcp://"):]
        host, _, port = t.partition(":")
        if not port:
            raise RuntimeError(f"bad endpoint {self.target!r}, expected tcp://host:port")
        try:
            port_num = int(port)
        except ValueError:
            raise RuntimeError(
                f"bad endpoint {self.target!r}: port {port!r} is not a number "
                "(expected tcp://host:port)")
        if not 0 < port_num < 65536:
            raise RuntimeError(
                f"bad endpoint {self.target!r}: port {port_num} out of range (1..65535)")
        return host, port_num

    def open(self) -> None:
        host, port = self._endpoint()
        sock = socket.create_connection((host, port), timeout=10)
        try:
            timeout = _txn_timeout()
            r = sock.makefile("rb")
            w = sock.makefile("wb")
            wire.send(w, wire.hello(config={"baud": self.baud}))
            # Bound the WELCOME wait as a TOTAL deadline: a silent OR byte-dribbling target must
            # not hang or slow-walk open() past the budget.
            before = (None if timeout is None
                      else self._deadline_reader(time.monotonic() + timeout, sock=sock))
            try:
                msg = wire.recv(r, before_read=before)
            except socket.timeout:
                raise RuntimeError(
                    f"target went silent during handshake (no welcome within {timeout:g}s)")
            if not msg or msg.get("t") != wire.WELCOME:
                raise RuntimeError("handshake failed (no welcome from target)")
            sock.settimeout(None)            # reads/sniff must not inherit it; each bounds its own recv
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            raise                            # leave _sock None so the backend is not half-open
        self._sock, self._r, self._w = sock, r, w
        self._caps = msg.get("capabilities", {}) or {}

    def close(self) -> None:
        for f in (self._r, self._w):
            try:
                if f:
                    f.close()
            except Exception:
                pass
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass
        self._sock = self._r = self._w = None
        self._stream = False
        self._stream_buf = b""

    def capabilities(self) -> Capabilities:
        c = self._caps
        return Capabilities(protocol=c.get("protocol", ""), transport=self._transport_label,
                            channels=_as_list(c.get("channels")), verbs=_as_list(c.get("verbs")),
                            shape=c.get("shape", "packet"), meta=c.get("meta", {}))

    def _txn(self, msg: dict, min_timeout: float | None = None) -> dict:
        wire.send(self._w, msg)
        r = self._recv_bounded(min_timeout=min_timeout)
        if r is None:
            raise RuntimeError("connection closed by target")
        if r.get("t") == wire.ERROR:
            raise RuntimeError(r.get("msg", "error"))
        return r

    def _deadline_reader(self, deadline: float, sock: socket.socket | None = None):
        """A `before_read` hook (see wire._read_exactly) that enforces a TOTAL wall-clock deadline.

        Called before every underlying socket read, it recomputes the remaining budget and shrinks
        the socket timeout to it, raising `socket.timeout` once the deadline has passed. This is
        what makes a bounded read a TOTAL bound rather than a per-recv one: a target dribbling one
        byte at a time can no longer reset a fresh full timeout on each byte, because each byte's
        read sees a strictly shrinking remaining budget and the deadline eventually trips.

        `sock` defaults to the connected socket; `open()` passes the not-yet-adopted socket so the
        handshake read can be bounded before `self._sock` is set.
        """
        sock = sock or self._sock

        def before_read() -> None:
            remaining = deadline - time.monotonic()
            if remaining <= 0.0:
                raise socket.timeout("read deadline exceeded")
            sock.settimeout(remaining)

        return before_read

    def _recv_bounded(self, min_timeout: float | None = None) -> dict | None:
        """Read one control-path reply under a finite client-side TOTAL deadline.

        A silent, wedged, OR byte-dribbling target must never hold the client past the budget: the
        whole reply read is bounded by ESP_PROBE_TIMEOUT (default TXN_DEFAULT_TIMEOUT seconds) as a
        total deadline, after which we raise a clean ProbeError instead of blocking. The socket
        timeout is restored to None afterwards so it never leaks into a later read or the sniff
        path. A configured value of <= 0 disables the bound, restoring the blocking read.

        `min_timeout`, when given, EXTENDS (never shrinks) the deadline to at least
        `min_timeout + SCAN_TXN_MARGIN` so an operation that legitimately holds the transaction open
        for a known window - a `scan -t 15` listening for the whole window - is not cut off by the
        default control-path bound. It has no effect when the bound is disabled.
        """
        timeout = _txn_timeout()
        if timeout is not None and min_timeout is not None and min_timeout > 0:
            timeout = max(timeout, min_timeout + SCAN_TXN_MARGIN)
        if timeout is None:
            self._sock.settimeout(None)
            return wire.recv(self._r)
        deadline = time.monotonic() + timeout
        try:
            return wire.recv(self._r, before_read=self._deadline_reader(deadline))
        except socket.timeout:
            raise ProbeError(
                f"target went silent (no reply within {timeout:g}s); "
                "raise ESP_PROBE_TIMEOUT or check the target")
        finally:
            try:
                self._sock.settimeout(None)
            except OSError:
                pass

    def scan(self, seconds: float | None = None, count: int | None = None) -> list[dict]:
        # `items` is backend-supplied; a missing key defaults to [], but an explicit non-list
        # (e.g. JSON null or an object) must not flow to the display loop as if it were rows.
        # We hand the raw list to the caller, which normalizes per-row (cli._scan_rows); a
        # non-list is refused loud here rather than guessed at.
        #
        # `seconds`/`count` are OPTIONAL, additive SCAN fields (docs/wire): a listen window and an
        # early-stop the bridge honours on a packet/transaction medium. An older bridge that predates
        # them simply ignores the extra keys and applies its own fixed window, so the wire stays
        # backward-compatible. They are omitted when None so a scan with no window looks exactly like
        # the historical `{"t": scan}` on the wire.
        msg = {"t": wire.SCAN}
        if seconds is not None:
            msg["seconds"] = seconds
        if count is not None:
            msg["count"] = count
        items = self._txn(msg, min_timeout=seconds).get("items", [])
        if items is None:
            return []
        if not isinstance(items, list):
            raise RuntimeError(f"target returned non-list scan items {items!r}")
        return items

    def op(self, verb: str, **kwargs) -> dict:
        return self._txn({"t": wire.OP, "verb": verb, "args": kwargs}).get("result", {})

    # --- RAW-STREAM data path (docs/design/01-transport.md section 3) ------------------------------
    #
    # A stream connection is framed for the handshake (so info/scan/caps still work), then
    # upgraded ONCE, lazily, on the first stream data verb: send STREAM_ATTACH, read STREAM_READY
    # (both framed, bounded by the control-path deadline), and from then on the socket is a raw
    # byte pipe. `uart read`/`uart write` route here, never through `op()`.

    def _attach_stream(self, mode: str) -> None:
        """Upgrade this connection to a raw byte pipe, once. Idempotent: the first verb's `mode`
        wins (one probe process runs one verb, so this is called exactly once per connection).

        After reading the framed STREAM_READY the makefile may have pulled the bridge's first raw
        bytes (a banner) into its buffer; drain them into `_stream_buf` here so the subsequent raw
        recv path (which reads the socket directly, not the makefile) never loses them."""
        if self._stream:
            return
        if self._sock is None:
            raise ProbeError("stream verb on a closed backend")
        wire.send(self._w, wire.stream_attach(mode))
        msg = self._recv_bounded()
        if not msg or msg.get("t") != wire.STREAM_READY:
            raise ProbeError("stream upgrade refused by bridge (no stream_ready)")
        self._sock.setblocking(False)
        try:
            self._stream_buf = self._r.read1(65536) or b""
        except (BlockingIOError, socket.timeout):
            self._stream_buf = b""
        except OSError:
            self._stream_buf = b""
        finally:
            self._sock.setblocking(True)
        self._stream = True

    def stream_write(self, data: bytes) -> int:
        self._attach_stream("write")
        timeout = _txn_timeout()
        try:
            if timeout is not None:
                self._sock.settimeout(timeout)
            self._sock.sendall(data)
        except socket.timeout:
            raise ProbeError(
                f"bridge did not accept the write within {timeout:g}s (line stalled?)")
        finally:
            try:
                self._sock.settimeout(None)
            except OSError:
                pass
        return len(data)

    def stream_open(self, mode: str = "duplex") -> StreamChannel:
        """Attach the raw byte pipe (STREAM_ATTACH{mode} -> STREAM_READY) and return a duplex
        channel for interactive (`uart console`) or atomic (`uart send`) use.

        Attaches ONCE, exactly like the internal `_attach_stream`; the returned StreamChannel owns
        the socket and takes over the backlog `_attach_stream` captured, so the backend no longer
        double-consumes it. `mode` picks the bridge pump direction (docs/design/01 section 3): use
        "duplex" for a write-then-read on ONE connection (a "write" attach sets the pump feed=False,
        so device RX is not fed back and the read sees nothing)."""
        self._attach_stream(mode)
        ch = StreamChannel(self._sock, self._stream_buf)
        self._stream_buf = b""            # ownership handed to the channel; do not re-consume
        return ch

    def stream_read(self, timeout: float) -> bytes:
        """Read from the line: block up to `timeout` for the first byte, then drain until idle.

        A thin front for the ONE drain home: attach in read mode and delegate to
        `StreamChannel.drain`, so `uart read`, `uart send`, and the console share one read
        algorithm and cannot drift on how a read is bounded (see StreamChannel.drain)."""
        return self.stream_open("read").drain(timeout)

    def stream_read_into(self, timeout: float, sink) -> int:
        """Streaming read: attach in read mode and delegate to `StreamChannel.drain_into`, feeding
        each drained chunk to `sink(bytes)` as it arrives rather than materializing the whole read.
        Same time+size bounds as `stream_read` (see StreamChannel.drain_into)."""
        return self.stream_open("read").drain_into(timeout, sink)

    def inject(self, frame: bytes, channel: int | None = None) -> None:
        self._txn({"t": wire.INJECT, "frame": frame.hex(), "channel": channel})

    def replay(self, in_pcap: str, frame_filter: str | None = None) -> int:
        """Re-transmit every frame in a pcap. Filter with stock tools (tshark -w) BEFORE
        replay and pass the filtered pcap; we deliberately do not reimplement a filter.

        The pcap's DLT is validated against the active protocol's DLT (convention C4): a
        cross-protocol capture is refused, not blasted onto the wire."""
        from ..core.fields import as_int
        from ..core.frame import read_pcap_for_replay
        frames = read_pcap_for_replay(in_pcap, self._caps.get("pcap_dlt"))
        r = self._txn({"t": wire.REPLAY, "frames": [f.hex() for f in frames]})
        # `count` is backend-supplied: coerce it so a stringy/None value fails clean here rather
        # than being printed verbatim by the CLI (`replayed <junk> frame(s)`).
        return as_int(r.get("count", 0), "replay count")

    def sniff(self, out_pcap: str, count=None, seconds=None, channel=None) -> int:
        """Capture frames to a pcap, BOUNDED entirely client-side.

        The tool stops on its own and never trusts the bridge to end the capture:
          - if neither `count` nor `seconds` is given, a default ceiling applies
            (`SNIFF_DEFAULT_SECONDS`) instead of capturing unbounded;
          - the read loop stops at `frames_read >= count` OR elapsed >= `seconds` OR
            elapsed >= a hard wall-clock `timeout`, whichever fires first;
          - each recv is bounded by a TOTAL deadline (the remaining wall-clock budget), so a
            bridge that stops sending OR dribbles one byte at a time cannot hold the client past
            the advertised bound.
        After the bound is reached the client stops reading regardless of further frames.

        A single malformed FRAME is skip-and-count: it is dropped, the capture keeps going, and
        the number of dropped frames is recorded in `self.dropped_frames` (surfaced by the CLI).
        A hostile frame therefore never aborts or crashes a capture. Returns the number of good
        frames written.
        """
        from ..core.errors import ProbeError
        from ..core.frame import PcapWriter

        if count is None and seconds is None:
            seconds = SNIFF_DEFAULT_SECONDS
        # Hard wall-clock guard, always finite, even in the count-only case.
        if seconds is not None:
            timeout = seconds + SNIFF_TIMEOUT_MARGIN
        else:
            timeout = SNIFF_COUNT_ONLY_TIMEOUT

        # The capture's DLT must come from the bridge's advertised `pcap_dlt`. A silent
        # fallback here would write a capture under a guessed link type that `replay` (which
        # refuses loud when `pcap_dlt` is absent) would then reject, so a misconfigured bridge
        # produced a capture it could not replay. Refuse loud instead, agreeing with replay.
        dlt = self._caps.get("pcap_dlt")
        if dlt is None:
            from ..core.errors import ProbeError
            raise ProbeError(
                "target did not advertise a pcap link type (pcap_dlt); refusing to write a "
                "capture under a guessed DLT that replay would reject")
        wire.send(self._w, {"t": wire.SNIFF, "count": count, "seconds": seconds,
                            "channel": channel})
        start = time.monotonic()
        n = 0
        dropped = 0              # malformed frames dropped under the skip-and-count policy
        bound_reached = False    # our own count/seconds/timeout tripped (vs a quiet/closed bridge)
        saw_end = False          # the bridge's terminating SNIFF_END was already consumed in-loop
        self.dropped_frames = 0
        with PcapWriter(out_pcap, dlt) as pw:
            while True:
                elapsed = time.monotonic() - start
                if count is not None and n >= count:
                    bound_reached = True
                    break
                if seconds is not None and elapsed >= seconds:
                    bound_reached = True
                    break
                if elapsed >= timeout:
                    bound_reached = True
                    break
                # Bound this single recv by the remaining wall-clock budget, as a TOTAL deadline
                # (see _deadline_reader): a dribbling bridge cannot hold one recv past it.
                recv_deadline = start + timeout
                if seconds is not None:
                    recv_deadline = min(recv_deadline, start + seconds)
                try:
                    m = wire.recv(self._r, before_read=self._deadline_reader(recv_deadline))
                except (socket.timeout, OSError):
                    break            # bridge went quiet/dribbling; nothing left to realign
                except wire.ProtocolError:
                    # A well-framed but malformed message (a non-object body, invalid JSON,
                    # non-UTF-8, or `null`): the whole framed message was already consumed, so the
                    # stream stays aligned at the next boundary. Drop-and-count it exactly like a
                    # malformed dict-frame instead of aborting the capture; a single hostile
                    # message must never truncate a capture or leak a Python-internal error string.
                    dropped += 1
                    continue
                if m is None:
                    break            # clean EOF (empty header): the bridge closed the connection
                t = m.get("t")
                if t == wire.FRAME:
                    # Skip-and-count: a single malformed frame is dropped, never fatal to the
                    # capture. from_msg coerces every field; a value it cannot interpret raises a
                    # ProbeError, and PcapWriter clamps any wild-but-numeric ts, so neither a bad
                    # field nor struct.pack can crash the loop.
                    try:
                        frame = wire.Frame.from_msg(m)
                    except (ProbeError, ValueError, struct.error):
                        dropped += 1
                        continue
                    pw.write(frame)
                    n += 1
                elif t == wire.SNIFF_END:
                    saw_end = True
                    break
                elif t == wire.ERROR:
                    raise RuntimeError(m.get("msg", "error"))
        # A conformant bridge terminates every capture with exactly one inbound SNIFF_END. When our
        # own bound (count/seconds/timeout) tripped first, that marker is still queued on the wire;
        # consume it so the NEXT command on a PERSISTENT connection reads its own reply and not the
        # stale marker. We deliberately do NOT send a SNIFF_END of our own: the bridge does not read
        # while it streams a capture (an outbound stop cannot end one early), and older bridges
        # reject the unknown inbound `sniff_end` type, which desyncs the session. It is inbound-only.
        if bound_reached and not saw_end:
            dropped += self._drain_sniff_end(start, timeout)
        try:
            self._sock.settimeout(None)
        except OSError:
            pass
        self.dropped_frames = dropped
        return n

    def _drain_sniff_end(self, start: float, timeout: float) -> int:
        """Consume the single trailing SNIFF_END that terminates a capture, realigning the stream
        for the next command on a persistent connection.

        A conformant bridge sends the marker in the same burst as the frames (both queued before it
        loops back to read), so it is already buffered and this returns at once. The wait is bounded
        (`SNIFF_END_DRAIN_GRACE`, itself clamped by the capture's remaining wall-clock budget) so a
        bridge that omits the marker cannot wedge the client - it gives up and leaves the stream as
        is. Exactly one message is consumed: the marker for a count-bounded capture, or a stray
        frame from a non-conformant bridge (which we do not chase, so we can never hang here).

        Returns the number of malformed messages drop-and-counted here (0 or 1). A malformed /
        non-object / null message buffered in the drain window is the NORMAL case for a bridge that
        never sends SNIFF_END: it must be dropped-and-counted exactly like the in-loop path, never
        allowed to escape and abort a capture whose good frames are already written to the pcap.
        This consumes at most one message and cannot spin on a malformed flood.
        """
        remaining = timeout - (time.monotonic() - start)
        budget = min(SNIFF_END_DRAIN_GRACE, max(0.0, remaining))
        deadline = time.monotonic() + budget
        try:
            wire.recv(self._r, before_read=self._deadline_reader(deadline))
        except (socket.timeout, OSError):
            return 0
        except wire.ProtocolError:
            # A fully-framed but malformed message in the drain window: the stream stays aligned,
            # so drop-and-count it (keeping the operator's dropped-note truthful) instead of
            # letting it abort the capture. Still exactly one message, so no spin.
            return 1
        return 0
