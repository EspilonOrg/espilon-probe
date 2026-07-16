"""The UART conformance gate: virtual == real(pty), zero hardware (docs/04).

Runs the same-tape-two-bridges diff from the conformance harness in-process and asserts the two
terminations are observationally equal. A pty is the "real" side, so this runs in CI with nothing
but the kernel. This is the release gate the pilot exists to turn green.
"""

import os

from conformance.console import Console
from conformance.pty_adapter import ConformanceRealSide
from conformance.run import BANNER_MARKER, run_conformance

_TAPE = os.path.join(os.path.dirname(__file__), "..", "conformance", "tapes", "uart_smoke.json")

# A stand-in for the classic-ESP32 mask-ROM boot log that precedes the firmware banner on real HW.
_FAKE_ROM_LOG = (b"rst:0x1 (POWERON_RESET),boot:0x13 (SPI_FAST_FLASH_BOOT)\r\n"
                 b"ets Jun  8 2016 00:22:57\r\nconfigsip: 0, SPIWP:0xee\r\n")


def test_uart_virtual_equals_real_over_pty():
    equal, report = run_conformance(_TAPE)
    assert equal, "virtual != real:\n" + report
    # The report must show real per-step comparisons and the concatenated-RX equality.
    assert "RESULT: PASS" in report
    assert "concatenated RX equal: True" in report


def test_real_device_mode_over_pty_stand_in():
    # Exercises the REAL-DEVICE code path (reset-on-open + drop-to-banner + the diff) with no board:
    # a pty stand-in injects a fake mask-ROM boot log ahead of the banner, and the drop-to-banner
    # trim must strip it so virtual == real still holds. This keeps the real-device mode green in CI.
    real = ConformanceRealSide(Console(), boot_log=_FAKE_ROM_LOG, reset_on_open=True)
    equal, report = run_conformance(_TAPE, real_side=real, drop_marker=BANNER_MARKER)
    assert equal, "real-device mode (pty stand-in) diff failed:\n" + report
    assert "RESULT: PASS" in report
    assert "content expectations present (virtual & real): True" in report


def test_drop_to_banner_strips_rom_log_but_keeps_banner():
    # The trim drops everything BEFORE the banner (the ROM log) and keeps the banner onward, so the
    # banner itself is still diffed/gated - not dropped through.
    from conformance.runner import StepResult, trim_real_reads
    noisy = _FAKE_ROM_LOG.decode() + "=== espilon uart console (pilot) ===\r\nboot> "
    r = StepResult(argv=["uart", "read", "-t", "1"], stdout=noisy, exit_code=0, expect=[])
    trimmed = trim_real_reads([r], BANNER_MARKER)[0].stdout
    assert trimmed == "=== espilon uart console (pilot) ===\r\nboot> "
    assert "rst:0x1" not in trimmed


def test_console_model_command_ordering():
    # The model-level (no-socket) ordering assertion from docs/protocols/uart.md: feeding a full
    # command yields the echo, then the response body, then the prompt, in order.
    c = Console()
    out = c.feed(b"printenv\r\n")
    assert out.startswith(b"printenv\r\n")                 # echo first (then CRLF for the CR Enter)
    i_body = out.index(b"bootcmd=")                        # then the response body
    i_prompt = out.index(b"boot> ")                        # then the prompt
    assert out.index(b"printenv\r\n") < i_body < i_prompt


def test_console_dispatches_on_cr():
    # The load-bearing fidelity fix: Enter is CR (0x0d - what a real terminal and probe's default
    # --eol cr send), so a bare-CR line MUST dispatch. Byte-exact: echo "help", CRLF for Enter,
    # response, prompt.
    c = Console()
    assert c.feed(b"help\r") == b"help\r\ncommands: help printenv echo <text>\r\nboot> "


def test_console_crlf_dispatches_once_no_empty_second_line():
    # CRLF collapse: the LF right after the CR is swallowed, so "help\r\n" dispatches EXACTLY once
    # and never emits a spurious empty (prompt-only) second line. Byte-identical to bare-CR.
    c = Console()
    out = c.feed(b"help\r\n")
    assert out == b"help\r\ncommands: help printenv echo <text>\r\nboot> "
    assert out.count(b"boot> ") == 1                       # one prompt -> one dispatch, no empty line


def test_console_crlf_split_across_feeds_still_collapses():
    # The CR and its trailing LF can arrive in separate reads; the collapse must survive the seam.
    c = Console()
    first = c.feed(b"help\r")
    assert first == b"help\r\ncommands: help printenv echo <text>\r\nboot> "
    assert c.feed(b"\n") == b""                             # the lone LF is swallowed, not a dispatch


def test_console_tolerates_bare_lf():
    # Bare-LF tolerance: an LF-only client still dispatches. The Enter still renders as CRLF.
    c = Console()
    assert c.feed(b"echo hi\n") == b"echo hi\r\nhi\r\nboot> "


def test_console_lfcr_pair_also_collapses():
    # The pair is symmetric: LF then CR collapses too (the CR is the swallowed second half).
    c = Console()
    out = c.feed(b"help\n\r")
    assert out == b"help\r\ncommands: help printenv echo <text>\r\nboot> "
    assert out.count(b"boot> ") == 1


def test_console_two_bare_crs_dispatch_twice():
    # Two CRs are two Enters (not a pair), so an empty line between them yields a prompt-only
    # dispatch: the state machine only collapses OPPOSITE-kind adjacent terminators.
    c = Console()
    assert c.feed(b"\r\r") == b"\r\nboot> \r\nboot> "       # two empty dispatches, two prompts


def test_console_command_bytes_are_clean_no_stray_cr():
    # CR/LF are terminators, never buffered, so the dispatched command carries no stray CR/LF: an
    # unknown command echoes back exactly the typed token.
    c = Console()
    assert c.feed(b"bogusdev\r") == b"bogusdev\r\nunknown command: bogusdev\r\nboot> "


def test_console_banner_precedes_everything():
    c = Console()
    assert c.banner().startswith(b"=== espilon uart console")
    assert c.banner().endswith(b"boot> ")


def _firmware_feed(data: bytes) -> bytes:
    """A faithful Python port of uart_console.c feed()+dispatch() - the GROUND TRUTH the virtual
    model must match. LINE_MAX-bounded (bytes past the cap are dropped from the buffer, echo still
    happens), CR/LF terminators, CRLF/LFCR collapse. Kept deliberately independent of console.py so
    this test compares the model against the firmware behaviour, not against itself."""
    LINE_MAX = 2048
    EOL = b"\r\n"
    PROMPT = b"boot> "
    line = bytearray()
    prev_term = b""
    out = bytearray()

    def dispatch(ln: bytes) -> bytes:
        cmd, _, arg = ln.partition(b" ")
        cmd = cmd.strip()
        if cmd == b"":
            return PROMPT
        if cmd == b"help":
            body = b"commands: help printenv echo <text>\r\n"
        elif cmd == b"printenv":
            body = b"bootcmd=run distro_bootcmd\r\nbaudrate=115200\r\nver=pilot-1\r\n"
        elif cmd == b"echo":
            body = arg + EOL
        else:
            body = b"unknown command: " + cmd + EOL
        return body + PROMPT

    for byte in data:
        b = bytes((byte,))
        if b in (b"\r", b"\n"):
            if prev_term and b != prev_term:
                prev_term = b""
                continue
            out += EOL                              # echo on: Enter -> fresh line
            out += dispatch(bytes(line))
            line.clear()
            prev_term = b
        else:
            out += b                                # echo every byte, even past the cap
            if len(line) < LINE_MAX:                # ... but only buffer up to LINE_MAX
                line += b
            prev_term = b""
    return bytes(out)


def test_console_line_over_LINE_MAX_matches_firmware_byte_for_byte():
    # Fix 4: a single line longer than LINE_MAX (2048) must diverge NOWHERE from the firmware. The C
    # echoes every byte but buffers only the first 2048, so a 3005-byte `echo ...` line dispatches its
    # first 2048 buffered bytes only. Assert the virtual model is byte-identical to the firmware port,
    # so the deviation is tested rather than silently green.
    line = b"echo " + b"A" * 3000 + b"\r"           # 3006 bytes: far past the 2048 cap
    got = Console().feed(line)
    assert got == _firmware_feed(line)

    # And pin the concrete firmware-expected bytes so the reimplementation itself cannot drift:
    #   echo of ALL 3005 non-terminator bytes, then CRLF, then the dispatched arg = the 2043 'A's
    #   that fit after "echo " within LINE_MAX (2048 - len("echo ") = 2043), then CRLF, then PROMPT.
    expected = (b"echo " + b"A" * 3000 + b"\r\n"
                + b"A" * (2048 - len("echo ")) + b"\r\n" + b"boot> ")
    assert got == expected
