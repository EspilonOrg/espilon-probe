# uart-console-esp32 - real-hardware leg of the UART Console conformance test

This is the classic-ESP32 firmware counterpart of the virtual UART Console reference model in
`conformance/console.py`. It presents a raw UART console whose **observable bytes are identical** to
the Python model, so the fidelity conformance diff can be run against real silicon:

```
probe --backend serial --target <console-port>     # this firmware
   ==  (byte-for-byte)  ==
probe --backend virtual                            # conformance/console.py
```

**Default console line: UART2 on GPIO17 (TX) / GPIO16 (RX).** This is the faithful "clip your own
USB-TTL adapter onto the target's pins" gesture - the console is a bare UART on GPIOs, exactly what a
hardware target exposes, and the firmware is flashed over UART0/USB but interacted with over the
pins. A one-cable convenience variant runs the console on UART0/USB instead (build with
`-DCONSOLE_ON_UART0`).

It is a conformance TEST fixture that pairs with `conformance/console.py`. Like the rest of
`conformance/`, it is NOT shipped in the `espilon-probe` wheel. It carries no flag and no challenge
content.

## Wiring (default UART2 path)

Clip a 3.3 V USB-TTL adapter onto the ESP32 header:

| USB-TTL       | ESP32          |
|---------------|----------------|
| RX            | GPIO17 (TX)    |
| TX            | GPIO16 (RX)    |
| GND           | GND (common)   |

3.3 V logic. **Do NOT connect the adapter's VCC** - the board is already powered over its USB port
(which is also how you flash it). The adapter shows up as its own `/dev/ttyUSB*` (e.g.
`/dev/ttyUSB1` while the ESP32's own USB is `/dev/ttyUSB0`); point `--target` at the ADAPTER.

## Console spec implemented (ported from console.py)

All strings are byte-for-byte copies of the reference model. `\r` = 0x0D, `\n` = 0x0A.

- **Boot banner** (emitted once at power-on): `=== espilon uart console (pilot) ===\r\n`
  immediately followed by the prompt `boot> ` (i.e. `Console.banner()` = `BANNER + PROMPT`).
- **Echo**: every received NON-terminator byte is echoed back verbatim. Echo is raw (no cooked-mode
  processing). A dispatching terminator does NOT echo its raw byte; it emits `\r\n` (see line
  handling).
- **Line handling**: Enter is **CR** (`\r`, 0x0D) - a real U-Boot/`boot>` console, and what a
  terminal (screen/picocom) and probe's default `--eol cr` actually send. A line is terminated by
  CR: on CR the accumulated line is dispatched and the buffer reset. A bare `\n` (0x0A) also
  dispatches (LF-only clients are tolerated). The second half of a CRLF/LFCR pair - a terminator of
  the OTHER kind immediately after one that just dispatched - is **swallowed**, so a two-byte Enter
  dispatches exactly once (no spurious empty line). CR/LF never enter the line buffer, so the
  dispatched command bytes are clean. On a dispatching terminator the console emits `\r\n` (a real
  console moves to a fresh line) in place of echoing the raw terminator byte, then the response and
  prompt. Net for `help<CR>`: `help\r\ncommands: help printenv echo <text>\r\nboot> `.
- **Dispatch**: the line is split on the FIRST space into `cmd` and `arg`. `cmd` is stripped
  of leading/trailing ASCII whitespace; `arg` is left exactly as received (not stripped).
  - empty `cmd`               -> emit just `boot> ` (prompt only)
  - `help`                    -> `commands: help printenv echo <text>\r\n` + prompt
  - `printenv`                -> `bootcmd=run distro_bootcmd\r\nbaudrate=115200\r\nver=pilot-1\r\n` + prompt
  - `echo`                    -> `<arg>\r\n` + prompt  (arg verbatim, unstripped)
  - anything else             -> `unknown command: <cmd>\r\n` + prompt  (cmd is the stripped token)
- **Deterministic**: no timestamps, no per-boot randomness, no log interleaving.

The C port lives in `main/uart_console.c`; each function is annotated with the `console.py`
line it mirrors.

## Why the bytes stay clean

The console runs on the raw UART driver (`uart_read_bytes` / `uart_write_bytes`), NOT on stdio/VFS.
That means no CRLF translation and no cooked echo from the OS/IDF layer - the ESP32 transmits exactly
the bytes the model computes. In addition (`sdkconfig.defaults`):

- `CONFIG_BOOTLOADER_LOG_LEVEL_NONE=y` - the second-stage bootloader prints nothing.
- `CONFIG_LOG_DEFAULT_LEVEL_NONE=y` - app `ESP_LOGx` above "none" is compiled out.
- `CONFIG_ESP_CONSOLE_UART_NONE=y` - the IDF console/stdio is detached from every UART, so no boot
  log or stray `printf` can land on the console line.

On the default **UART2** path the console line is a dedicated pair of GPIOs, physically separate from
UART0 - so the mask-ROM boot log (which the ROM prints on **UART0**) never reaches the console line
at all. On the **UART0** variant the firmware owns UART0 exclusively, but the mask-ROM log still
precedes it (see below).

## Build / flash

```
source ~/esp-idf/export.sh          # IDF v5.3.2, target esp32
idf.py set-target esp32             # already captured in sdkconfig.defaults
idf.py build                        # default: console on UART2 (GPIO17/16)
idf.py -p /dev/ttyUSB0 flash        # flash over the ESP32's own USB (UART0)
```

One-cable UART0 variant (console on the USB port):

```
idf.py build -DCONSOLE_ON_UART0
idf.py -p /dev/ttyUSB0 flash
```

## Pairing with the conformance harness (real-hardware leg)

The virtual leg runs `conformance/console.py` behind the virtual bridge. The real leg is the
physical board, and the shipped client is invoked as `probe --backend serial --target <console-port>`
(the USB-TTL adapter on UART2, or `/dev/ttyUSB0` for the UART0 variant). The runner's `diff_runs` then
asserts the two RX byte streams are equal and that every `expect` in `tapes/uart_smoke.json` is present
on both sides:

```
make conformance-uart-real TARGET=/dev/ttyUSB1              # UART2 via a USB-TTL adapter
make conformance-uart-real TARGET=/dev/ttyUSB0              # UART0 variant (one cable)
make conformance-uart-real TARGET=/dev/ttyUSB0 GARBLE=57600 # + wrong-baud garble assertion
```

**Bring-up ordering (load-bearing).** The banner is emitted once at device boot and must be captured
by a reader that is already attached. So the sequence must be: (1) open the port / start the
serial-bridge daemon holding it, THEN (2) reset the ESP32 so the banner lands in the RX buffer that
the first `uart read -t 1` drains. If the board booted before the port was opened, the banner is
already gone and step 0 of the tape will diff.

### Reset + banner capture depends on the path

- **UART0/USB (or a reset-wired adapter):** the daemon's `--reset-on-open` pulses DTR/RTS (esptool
  ClassicReset polarity: IO0 via DTR, EN pulsed via RTS) to reboot the board after the port is open,
  so the banner is captured (`SerialMedium._reset_board`). This is the CI-friendly one-cable path.
- **UART2 via a passive USB-TTL:** a passive adapter's DTR/RTS are NOT wired to the ESP32 EN/IO0, so
  the auto-reset does nothing - the board cannot be reset over the console line. On this path the
  boot-only banner is **faithfully missed** (just as it would be for a human clipping a plain USB-TTL
  onto a running target): press the board's EN button while the port is open to capture it, or use a
  reset-wired adapter. This is honest hardware behaviour, not a harness bug.

## Hardware-forced deviation: the ROM boot log (UART0 variant only)

On power-on/reset the ESP32 mask-ROM bootloader prints a boot message on **UART0** TX (e.g.
`rst:0x1 (POWERON_RESET),boot:0x13 ...` / `ets Jun  8 2016 ...`) BEFORE our firmware runs. This is
mask-ROM code, not controllable via Kconfig on the classic ESP32 (no eFuse to gate it, unlike
ESP32-S3/C3/C6); it is silenced in hardware by strapping **GPIO15 (MTDO) LOW at reset**.

- On the **default UART2 console**, the ROM log is on a DIFFERENT line (UART0) and never reaches the
  console pins, so there is nothing to reconcile - the console line carries only the model bytes.
- On the **UART0 console variant**, the ROM log prepends to the first RX read. Reconciliation:
  1. Pull GPIO15 to GND on the board under test (eliminates the log entirely), or
  2. Drop everything before the first occurrence of the firmware banner before comparing - this is
     what the harness does (`runner.trim_real_reads`, up to but NOT including the banner, so the
     banner is still byte-diffed and `expect`-gated). Everything after the banner (echo, responses,
     prompt) is byte-identical to the model; no CRLF/echo deviation exists.

**Line-buffer bound.** Both terminations cap the line buffer at `LINE_MAX` (2048 bytes) and drop
buffer bytes beyond that (echo still happens for every byte); the virtual `console.py` model matches
this firmware value exactly, so a line longer than the cap dispatches the same first 2048 bytes on
both sides. A model unit test asserts this against the firmware behaviour. The conformance tape lines
are a few bytes long, so the cap is never reached in the tape itself.

## Harness implementation (what actually runs)

- **Reset-on-open.** `--reset-on-open` pulses DTR/RTS to reboot the board after the port is open so
  the banner is captured. Effective on UART0/USB or a reset-wired adapter (see the path note above).
- **Drop-to-banner.** `runner.trim_real_reads` trims each real read to START at the firmware banner,
  dropping any preceding chatter (the UART0 ROM log) while keeping the banner itself in the diff.
- **Baud garble (real silicon only).** `GARBLE=<wrong-baud>` opens the line at the wrong rate and
  asserts the firmware banner is NOT readable (`conformance.run.check_baud_garble`). A pty cannot do
  this (no bit clock), so it is asserted only against real silicon; the rest of the diff is proven on
  a pty in CI.
- **CI without hardware.** The real-device code path (reset-on-open, drop-to-banner, the diff) is kept
  green with no board by a pty stand-in that injects a fake ROM boot log ahead of the banner
  (`tests/test_conformance_uart.py::test_real_device_mode_over_pty_stand_in`).
