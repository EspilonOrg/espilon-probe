# Protocol: UART

**Status:** shape `stream`. Both backends work today: the `virtual` backend and the real
`serial` backend (pty / USB-UART).

Read `../protocol-conventions.md` first. This doc specifies `protocols/uart.py` and what a virtual
backend must simulate; the same `probe uart *` commands drive the real `serial` backend unchanged.

## 1. What it models

A UART is a continuous octet flow: message boundaries are an application convention (a newline, a
prompt), never a transport fact. `probe` treats it as a RAW-STREAM byte pipe, the purest relay -
once the stream is attached the bridge forwards bytes both ways and parses nothing; the device owns
all UART semantics.

An operator on a serial console (screen / minicom / a USB-UART adapter):

- read from the line (drain whatever the device has emitted),
- write to the line (send a command / payload),
- send-then-read on one connection (drive a console command and capture its reply),
- open an interactive console.

Tradecraft mapping:

| Real tool | probe verb |
|---|---|
| `screen /dev/ttyUSB0 115200`, drain | `probe uart read` |
| type a command | `probe uart write --text ...` |
| send a command and read its reply | `probe uart send ...` |
| interactive console | `probe uart console` |

## 2. Shape and verb set

Shape: RAW-STREAM. `capabilities.shape == "stream"`. Because boundaries are not a transport fact,
the packet core verbs do not apply.

Core verbs:

| Core verb | UART | Reason |
|---|---|---|
| `scan` | OFFERED | the framed pre-upgrade handshake still answers `info`/caps |
| `sniff` | REDEFINED | a passive byte-log tee of the raw octet stream, not a frame stream |
| `inject` | GATED OUT | no packet to inject; you `uart write` raw bytes |
| `replay` | GATED OUT | no frame capture to replay on a raw stream |

Asking for a gated verb -> `ProbeError` (rule 2), e.g.
`probe: 'inject' is not supported on protocol 'uart' (supported: scan, uart)`.

Protocol verbs (group `uart`):

| CLI | maps to | args | returns |
|---|---|---|---|
| `probe uart read` | `backend.stream_read` | `-t timeout?` | raw bytes drained from the line |
| `probe uart write` | `backend.stream_write` | `--text` / `--hex` | bytes written |
| `probe uart send` | duplex attach + write + drain | payload, `-t?` | the reply bytes to this command |
| `probe uart console` | duplex attach, interactive | - | interactive session |

`read` blocks up to `-t` for the first byte, then drains until one `UART_READ_IDLE_GAP` of idle.
`send` attaches a DUPLEX connection so the reply to exactly this command is captured
deterministically on any bridge (persistent or short-lived auto-spawn). Shared constants
(`UART_READ_TIMEOUT_DEFAULT = 1.0`, `UART_READ_IDLE_GAP`) live in `core/backend.py` so the serial
medium and the virtual bridge cannot drift.

## 3. Transport upgrade

UART is established framed (`HELLO`/`WELCOME`, so `info`/`scan`/caps still work), then upgraded
ONCE, lazily, when the first stream verb runs: the client sends `STREAM_ATTACH`, the bridge replies
`STREAM_READY`, and from the byte after `STREAM_READY` both directions are raw bytes on that
connection - no length prefix, no JSON. The upgrade is one-way and per-connection. See
[`../design/01-transport.md`](../design/01-transport.md) section 3.

## 4. Capture representation

A RAW-STREAM has no frame boundaries and therefore no packet DLT. `sniff` is a byte-log tee: it
writes the raw octets seen on the line to a file, exactly as they arrived. There is no dissectable
pcap because there are no frames; the operator reads the byte log directly.

## 5. What a virtual target must simulate

A virtual target exposes a console model:

- a banner emitted on attach, command echo, and a prompt, so a `send` observes echo -> response ->
  prompt in order.
- baud-mismatch physics: the virtual side expands each byte into a 10-bit UART symbol frame
  (start bit, 8 data bits LSB-first, stop bit), resamples at the receiver clock (`round(i *
  device_baud / client_baud)`), and re-frames, so a wrong `--baud` yields real line noise and only
  the exact rate
  reads clean. The clean/garbled decision is a sound binary gate (match within `MATCH_TOLERANCE`, a
  float-epsilon cushion far below one baud); the off-rate path scrambles the whole buffer, so there
  is no near-rate readable prefix.

Same-commands-transfer note: the identical `probe uart *` commands run against the real `serial`
backend (`probe-bridge --medium serial --endpoint /dev/ttyUSB0`, or a pty), which opens the fd (raw
mode, with termios baud on a real tty and a no-op on a pty) and raw-pumps bytes both ways. The
protocol module
and CLI are unchanged; only the backend swaps. A console workflow validated on the virtual bridge
transfers to a real USB-UART adapter.

## 6. Contract items touched

- The stream shape (`capabilities.shape == "stream"`) and its packet-verb gate.
- The `STREAM_ATTACH`/`STREAM_READY` raw-upgrade seam ([`../design/01-transport.md`](../design/01-transport.md)).
- Shared stream constants in `core/backend.py` so virtual and serial cannot drift.
- No new wire message beyond `STREAM_ATTACH`/`STREAM_READY`.
