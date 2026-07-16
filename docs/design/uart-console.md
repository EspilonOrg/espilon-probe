# UART console + one-shot send - interactive terminal on the RAW-STREAM

Internal design note. Governed by `00-architecture.md` and `01-transport.md`; extends
`../protocols/uart.md`. Grounded in `core/wire.py`, `backends/virtual.py`,
`backends/serial.py`, `bridges/server.py`, `bridges/media/serial.py`, and
`conformance/virtual_bridge.py`.

Two new verbs on the existing RAW-STREAM tunnel:

- `probe uart console` - an interactive, screen/picocom-grade terminal on the raw byte pipe.
- `probe uart send` - the scriptable one-shot sibling (atomic send-then-drain, one process).

The thesis: `probe uart console` must feel exactly like `screen /dev/ttyUSB0 115200` against
real silicon **and** work byte-identically against the virtual backend where `screen` cannot
reach. One verb, both backends. This is achievable **today** with no wire or bridge change,
because the duplex pump the console needs already exists on both terminations.

---

## 0. Load-bearing finding: the transport is already sufficient

`STREAM_ATTACH{mode:"duplex"}` -> `STREAM_READY` already exists in `core/wire.py`, and
`BridgeServer._pump` already forwards **both** directions for `mode == "duplex"`
(`feed = mode in ("read","duplex")`, `sink = mode in ("write","duplex")`). The serial medium
and the virtual `ConsoleMedium` expose the identical `peek()/consume()/write()` surface, and the
pump code is shared. So:

- **No `core/wire.py` change.** The duplex control messages are in the contract already.
- **No bridge change.** The duplex pump is built and used by both terminations.
- **No change to `stream_read`/`stream_write` semantics.**

The entire delta is **client-side**: one new backend surface (`stream_open`), one stdlib-only
console loop module, and two CLI verbs. `01` section 4 explicitly reserved this: *"the property
'the OS buffer is the RX/TX buffer' is fully realized only in the future persistent `probe uart
console` session ... the transport is designed so it composes on top with no further wire
change."* This spec is that composition.

---

## 1. Where the mechanism lives (generality)

**Decision: the loop is generic in `core/console.py`; the surfacing is protocol-scoped as
`probe uart console` / `probe uart send`.**

- The interactive loop is pure stream plumbing (`select` over stdin-fd + a channel fd; no UART,
  no baud, no device knowledge). It lives in a new **`src/espilon_probe/core/console.py`**,
  stdlib-only (`termios`, `tty`, `select`, `os`, `sys`, `signal`), operating on a `StreamChannel`
  and two fds. It is therefore **not UART-specific plumbing**: any `shape == "stream"` protocol
  reuses it by wiring a CLI verb to the same function.
- **Surfaced as `probe uart console`, not top-level `probe console`.** Rationale: the CLI verb
  tree is already protocol-scoped (`uart write`/`uart read`), and the gate is
  `caps.shape == "stream"`. A top-level `probe console` would be the only top-level verb that is
  shape-conditional - it would error on every packet/transaction backend - which is a worse
  surface than a verb that only appears under a stream protocol. When a second stream protocol
  arrives, add `probe <proto> console` (a one-line CLI wiring to the same generic loop) or promote
  to top-level then; because the loop is already generic, promotion is a wiring change, not a
  rewrite.

Net: **mechanism generic (core), surface protocol-scoped (uart)** - satisfies "lives on the
RAW-STREAM shape so any stream protocol inherits it" without a shape-conditional top-level verb.

---

## 2. The one new client surface: `StreamChannel`

Add to the tunnel backend (`VirtualBackend`, inherited unchanged by `SerialBackend`):

```python
def stream_open(self, mode: str = "duplex") -> StreamChannel:
    """Attach the raw byte pipe (STREAM_ATTACH{mode} -> STREAM_READY) and return a duplex
    channel for interactive/atomic use. Attaches once, exactly like _attach_stream."""
```

`StreamChannel` is a thin, stdlib-only wrapper over the already-connected raw socket plus the
`_stream_buf` prefix `_attach_stream` captured. It exposes only what a byte pump needs:

```python
class StreamChannel:
    def fileno(self) -> int: ...            # the socket fd, for select()
    def take_backlog(self) -> bytes: ...     # the _stream_buf grabbed during attach, once (b"" after)
    def recv(self, bufsize: int = 65536) -> bytes: ...  # raw socket recv; b"" == EOF (remote close)
    def send(self, data: bytes) -> int: ...  # sendall; returns len(data)
    def drain(self, timeout: float) -> bytes: ...  # the first-byte-wait + idle-gap drain algorithm
```

Notes and rationale:

- **`take_backlog()` is load-bearing.** After the framed `STREAM_READY` read, `_attach_stream`
  pulls whatever the makefile already buffered into `_stream_buf`. Those bytes are **invisible to
  `select()` on the raw socket** (they left the socket, they sit in a Python buffer). The console
  loop MUST consume `take_backlog()` before entering the `select` loop, or the banner/first bytes
  are lost or delayed. This is the same hazard `stream_read` already handles by consuming
  `_stream_buf` first.
- **`drain()` consolidates the existing algorithm.** Lift the first-byte-wait-floored-to-idle-gap
  + drain-until-quiet + `UART_READ_DRAIN_CAP` total bound out of `virtual.stream_read` into
  `StreamChannel.drain`, so `stream_read`, `uart send`, and (optionally) the console's discard
  window share ONE implementation and cannot drift on how a read is bounded.
  - **Recommended but flagged:** this refactors tested code (`stream_read` becomes
    `stream_open("read").drain(timeout)`). Behaviour must stay byte-identical; keep it a pure
    move. If probe-dev wants a smaller diff, `drain` may instead call the existing private helper;
    the requirement is one drain algorithm, not two.

`stream_open`, `take_backlog`, and `drain` are **additive**; existing `stream_read`/`stream_write`
keep their signatures and behaviour.

---

## 3. `probe uart console` (interactive)

### 3.1 CLI

```
probe [--backend ...] [--target ...] [--baud N] uart console
      [--local-echo] [--eol cr|lf|crlf] [--replay-buffer]
```

### 3.2 The loop (`core/console.py`)

1. **Refuse a non-tty stdin up front** (see 3.7).
2. Save `termios.tcgetattr(stdin_fd)`. Enter **raw** mode with `tty.setraw(stdin_fd)`.
   **Decision: full `setraw`, not `cbreak`** - a device console needs Ctrl-C/Ctrl-\ etc. delivered
   as bytes to the device, not turned into local signals; `setraw` disables ISIG/ICANON/ECHO/IEXTEN
   and the CR/LF input maps, which is exactly what `screen`/`picocom` do.
3. `ch = backend.stream_open("duplex")`.
4. **Attach-clean** (3.6): consume `ch.take_backlog()` and drain the pre-attach backlog; discard it
   unless `--replay-buffer`.
5. Print the attach banner to **stderr** (3.8).
6. `select([stdin_fd, ch.fileno()], [], [])` loop:
   - **stdin readable** -> `os.read(stdin_fd, 65536)`:
     - `b""` (stdin EOF, e.g. controlling terminal closed) -> detach (clean exit).
     - scan for the escape byte `0x1d` (3.3): if at index `i`, forward `bytes[:i]` (after EOL
       mapping) to the device, then **detach** - discard `bytes[i:]` including `0x1d`.
     - apply EOL mapping (3.5) to the forwarded slice; `ch.send(mapped)`.
     - if `--local-echo`, also write the mapped slice to stdout (3.4).
   - **channel readable** -> `data = ch.recv()`:
     - `b""` -> remote close: print `[probe] connection closed` to stderr, exit (3.6/3.8).
     - else write `data` **verbatim** to stdout (device output is NEVER rewritten - raw pipe).
7. `finally`: restore `termios.tcsetattr(stdin_fd, TCSADRAIN, saved)` and print `[probe] detached`
   to stderr. This runs on every path (3.6).

Device output is written to `stdout` (fd 1) with an immediate flush / unbuffered `os.write`, so a
redirected `probe uart console > capture.log` gets the exact device bytes and nothing else.

### 3.3 Escape sequence

**Decision: `Ctrl-]` (0x1d, GS) detaches. Single keystroke, position-independent, never
forwarded.**

Rationale (decisive, not a menu):
- Telnet convention; universally recognised as "escape the terminal."
- Position-independent (works mid-line), unlike `~.` which is line-start-only and needs newline
  state-tracking and the "type `~~` to send one `~`" wart - and `~` is a character a hacker types
  constantly (paths, home dir), inviting false detection.
- `screen`/`picocom` default to **Ctrl-A**, which is a terrible default for a *device* console:
  Ctrl-A is beginning-of-line in every readline shell you would want to drive on the target. So we
  deliberately do NOT copy their escape.
- `0x1d` is effectively never sent to a UART device on purpose.

Detection: scan each stdin read for `0x1d`; the byte and everything after it in that read is
consumed by the client and **never written to the channel**. No multi-key menu, no submenus - one
key, one action. If you genuinely must transmit a literal `0x1d`, use `probe uart write` /
`probe uart send`; the console stays single-purpose.

### 3.4 Local echo

**Decision: default OFF; `--local-echo` opt-in for silent devices.**

- Default OFF: the device echoes (a typical MCU console echoes every input byte). We forward
  stdin -> device and the device's echo returns via device -> stdout. **No local echo means no
  possibility of a double echo on an echoing device.**
- `--local-echo`: for a genuinely silent device (no hardware/firmware echo), we additionally write
  the **exact bytes we forward** (post-EOL-mapping) to stdout at forward time. On an echoing device
  this **will** double - that is the operator's explicit choice for a device they know is silent,
  and it is documented as such. There is no auto-detect (guessing echo state is unreliable and
  would itself flicker doubles).

### 3.5 Newline

**Decision: default `--eol cr` (Enter -> CR, 0x0d); pure pass-through by default.**

In raw mode the tty delivers Enter as CR (0x0d) already, so the **default forwards stdin verbatim**
and Enter naturally lands as CR - no rewriting, faithful to "raw pipe." CR is `screen`'s default
and what U-Boot / most embedded consoles expect.

**Device side (validated on silicon):** the reference model (`conformance/console.py`) and the
reference peripheral firmware **dispatch a line on CR** (0x0d), swallow the trailing LF of a CRLF/LFCR pair (one Enter =
one dispatch), and tolerate a bare LF. So `probe uart send "help"` with the default `--eol cr`
delivers `help\r` and the device runs it - the default is correct end to end. (An earlier model
dispatched only on LF, so the CR default returned just the echo and never the command output; fixed
2026-07-12.)

`--eol` maps Enter on the **input path only** (never device output):
- `cr` (default): verbatim (0x0d passes through unchanged).
- `lf`: translate 0x0d -> 0x0a.
- `crlf`: translate 0x0d -> 0x0d 0x0a.

This is the single permitted input rewrite. Device -> stdout is always byte-verbatim; we never
"fix up" what the device emits.

### 3.6 EOF / remote-close / signals

- **Ctrl-D (0x04) and Ctrl-C (0x03)** are ordinary bytes in raw mode and are **forwarded to the
  device** (Ctrl-C interrupts the target's running program; Ctrl-D is a target-shell EOF), exactly
  like `screen`. They do **not** detach and do **not** raise a local signal. Detach is **only**
  Ctrl-]. Call this out prominently in `--help`; it surprises anyone expecting Ctrl-C to quit.
- **stdin EOF** (`os.read` returns `b""`, e.g. the controlling terminal vanished): treat as detach,
  clean exit 0.
- **Remote/stream close** (`ch.recv()` returns `b""`; the bridge or the serial medium hit EOF -
  device unplugged, daemon retired): print `[probe] connection closed` to stderr, exit **nonzero**
  (distinct from an operator-initiated detach).
- **SIGINT** cannot be raised by the keyboard under `setraw` (ISIG off). An external
  `SIGINT`/`SIGTERM`/`SIGHUP` must still restore the terminal: install handlers that raise
  `SystemExit` (or set a flag and close the channel) so the `finally` runs. **Terminal restore is
  guaranteed on every exit path** via the `finally` (TCSADRAIN restore) - the classic footgun is a
  killed console leaving the user's tty in raw mode; the signal handlers exist solely to make the
  `finally` fire on an external kill.
- **SIGWINCH** is ignored: a UART has no window-size channel to negotiate; nothing to forward.

### 3.7 No-tty degradation

**Decision: clean error, exit nonzero. No silent line-buffered fallback.**

If `not sys.stdin.isatty()` (piped / CI), refuse before touching termios:

```
probe: uart console needs an interactive terminal (stdin is not a tty).
       Use 'probe uart send' for scripted send-then-read, or 'probe uart write' / 'uart read'.
```

Rationale: `console` is definitionally interactive - it raw-ifies the tty and its only detach is a
keystroke; a piped stdin has no tty to raw-ify and no way to send Ctrl-]. Silently degrading to a
line-buffered pass-through would be a second, subtly different code path masquerading under the
same verb and would surprise CI. The scriptable path already exists and is named: `uart send`.

### 3.8 Banner (on stderr, never the stream)

- On attach: `[probe] attached to <target> (uart, <baud> baud) - escape: Ctrl-]`
- On detach: `[probe] detached`
- On remote close: `[probe] connection closed`

All to **stderr**, so `probe uart console > capture.log` captures only device bytes.

---

## 4. Attach-clean and the stale-buffer interaction

The persistent serial daemon's background reader accumulates device RX into `_buf` from the moment
it spawns; the duplex pump `peek()`s and sends the **whole** accumulation on attach. The virtual
`ConsoleMedium` similarly holds the boot banner (and any prior write's response) in `_fifo`. A naive
duplex attach therefore dumps a pile of stale/garbled backlog into the fresh terminal - the known
"stale accumulated buffer garble."

**Decision: on attach, discard the pre-attach backlog client-side, then go live. `--replay-buffer`
to keep it.**

- Client-side, **no wire change**: immediately after `STREAM_READY`, consume `take_backlog()` and
  then non-blocking-recv until one `UART_READ_IDLE_GAP` of quiet, discarding everything. The daemon
  emits the accumulated `_buf` as one burst at pump start (it is already in memory), so this window
  captures and drops exactly the backlog, then the loop starts on live bytes.
- This mirrors `screen`/`picocom`: attaching to a live line does **not** replay history. It is also
  faithful to real hardware - a device's **boot banner arrives only after a reset**, i.e. *after*
  attach, so a post-reset banner is preserved (it is not pre-attach backlog). The virtual bridge is
  faithful for the same reason: its boot banner, queued at model construction, is pre-attach backlog
  and is discarded exactly as a real already-booted device shows no banner. To see a banner in
  `console`, reset the device while attached (or use `--replay-buffer` once).
- `--replay-buffer`: write the backlog to stdout before going live (debugging / catching a
  response emitted just before attach).

**Preferred over a bridge-side flush.** A `flush` field on `STREAM_ATTACH` would also work and is
backward-compatible, but it is an avoidable wire addition; the client-side discard needs nothing
new and keeps the "no wire change" property. If a future need makes the client-side race
unacceptable, add the field then.

**Exclusivity note (surprise for probe-dev):** `BridgeServer.serve_forever` serves one connection
at a time and `_pump` holds it for the whole session. A `console` session therefore **holds the
persistent serial daemon exclusively for its entire lifetime** - concurrent `probe uart read/write`
commands block on `accept()` until detach. This is correct and faithful (like `screen` locking the
port), but a wedged console session blocks the line; document it.

---

## 5. `probe uart send` (scriptable one-shot sibling)

### 5.1 New verb, not a flag on `write`

**Decision: a new verb `uart send`, not `uart write --read/--expect`.**

Rationale: `uart write` is a faithful raw primitive ("put these bytes on the line, report the
count"). Bolting `--read`/`--expect`/terminator policy onto it overloads the primitive with
response-draining semantics and changes its output contract. `send` is a distinct atomic
operation - append terminator, write, drain the response, one process, one connection - with its
own output (the response on stdout) and its own exit semantics (`--expect`). Two clear verbs beat
one overloaded verb; `write` stays a pure primitive.

### 5.2 CLI + contract

```
probe uart send <text> [-t SECS] [--eol cr|lf|crlf] [--expect REGEX] [--no-read] [--raw]
```

- Encode `<text>` (default UTF-8; `--raw` reads hex like other verbs if needed - optional, defer if
  unused), append the terminator (`--eol`, default `cr`, same mapping as `console`).
- **Atomic send-then-drain on ONE duplex connection:** `ch = backend.stream_open("duplex")`;
  `ch.send(payload)`; `resp = ch.drain(timeout)` (default `UART_READ_TIMEOUT_DEFAULT`); print `resp`
  to stdout decoded `errors="replace"` (identical rendering to `uart read`).
- `--no-read`: send only, print nothing (a bare atomic write with terminator).
- `--expect REGEX`: exit 0 iff the drained response matches; else exit nonzero (for CI/solver
  assertions). Regex is a stdlib `re` search over the decoded response; no DSL.

### 5.3 Why it exists (vs `uart write` then `uart read`)

**It MUST attach duplex, and that is the whole point.** `_attach_stream` is once-per-connection and
a `"write"` attach puts the server pump in `feed = False`, so device RX is **not** fed back on a
write connection. Two separate processes (`uart write` then `uart read`) are two connections; on the
**persistent** serial daemon the response emitted between them survives in `_buf` and the pattern
happens to work, but on a **short-lived / non-persistent** bridge (the auto-spawned one-shot, and
the general bridge contract) the response emitted after the write connection closes can be lost or
reordered. `send` keeps the write and the drain on a **single duplex connection**, so the response
to *this* command is captured deterministically on any bridge. That determinism is why scripts,
test harnesses, and CI use `send` (and why they cannot use `console`, which needs a
tty). **This duplex requirement is a gotcha:** do not implement `send` as `stream_write` then
`stream_read` - that attaches `"write"` and the read sees nothing.

---

## 6. Backend / transport impact (summary)

| Layer | Change |
|---|---|
| `core/wire.py` | **none** (duplex attach + STREAM_READY already exist) |
| `bridges/*` (server pump, serial medium, ConsoleMedium) | **none** (duplex pump already built and shared) |
| `core/backend.py` stream semantics | **none** |
| `backends/virtual.py` | **add** `stream_open(mode) -> StreamChannel`; **add** `StreamChannel` (fileno/take_backlog/recv/send/drain); optionally re-express `stream_read` via `stream_open("read").drain` (one drain home) |
| `backends/serial.py` | **none** (inherits `stream_open`) |
| `core/console.py` | **new** stdlib-only interactive loop (termios/tty/select/os/signal) |
| `cli.py` | **add** `uart console` (+ `--local-echo/--eol/--replay-buffer`) and `uart send` (+ `-t/--eol/--expect/--no-read`); gate both on `caps.shape == "stream"` in addition to the existing `uart`-in-`caps.verbs` gate |

Stdlib-only in the client core holds: `termios`, `tty`, `select`, `os`, `signal`, `sys`, `re` are
all stdlib. No third-party dependency. The daemon-buffering interaction (section 4) is handled by a
client-side attach-clean policy, needing no bridge change.

---

## 7. Test / conformance approach (not designed in depth)

- **Interactive `console`:** drive it with a **pty pair on our stdin**. In the test, `os.openpty()`
  gives `(master, slave)`; run the console loop with `stdin_fd = slave` and `stdout_fd` = a pipe or
  a second pty; the test writes keystrokes to `master` and reads device output back. Assert:
  keystrokes forwarded to the backend; device output surfaced on stdout; `0x1d` detaches and is
  **not** forwarded; default has no double-echo, `--local-echo` doubles; `--eol lf/crlf` maps Enter;
  `termios.tcgetattr(slave)` equals the saved attrs after exit (terminal restored on every path,
  including an injected SIGTERM). Run the **same** keystroke tape against the virtual bridge and a
  pty-backed serial bridge (reuse the existing conformance fixtures) and assert the forwarded and
  received byte streams are identical - the fidelity thesis, now for `console`. The no-tty error is
  its own test: a pipe on stdin -> expect the clean error + nonzero exit.
- **`uart send`:** folds into the **existing** conformance harness with no new machinery because it
  is non-interactive - add it to the tape runner (`conformance/runner.py` / `tapes`) as a verb that
  emits stdout, and diff virtual vs pty-serial **byte-for-byte**, exactly like `uart read`. It is
  the scriptable primitive the harness/solvers already need; it also lets the harness replace the
  fragile two-process `write` then `read` pattern with one atomic call.
- Do not hand-guess the discard/attach-clean timing; assert it behaviourally (backlog dropped by
  default, present under `--replay-buffer`).

---

## 8. Surprises to flag for probe-dev (checklist)

1. **`uart send` MUST attach duplex.** `stream_write` then `stream_read` attaches `"write"`
   (pump `feed=False`) and the read returns nothing. Use `stream_open("duplex")`.
2. **Console holds the persistent serial daemon exclusively** for its whole lifetime (one-conn
   serve loop); other `probe uart *` commands block until detach. Faithful, but document it.
3. **Attach-clean discards the virtual/boot banner** (it is pre-attach backlog), exactly as `screen`
   shows no history; the banner returns only on a post-attach reset or with `--replay-buffer`.
4. **In raw mode Ctrl-C (0x03) and Ctrl-D (0x04) are bytes forwarded to the device**, not local
   signal/EOF. Detach is only Ctrl-] (0x1d). This surprises Ctrl-C-to-quit muscle memory.
5. **Terminal restore lives in `finally` + SIGTERM/SIGHUP handlers.** An external kill without a
   handler leaves the operator's tty in raw mode (garbled). This is the classic footgun.
6. **`_stream_buf` (attach-time buffered bytes) is invisible to `select()`.** Consume
   `take_backlog()` before the loop or those bytes are lost/delayed.
