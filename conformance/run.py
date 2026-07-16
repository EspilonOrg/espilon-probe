"""`python -m conformance.run [--real-target DEV] <tape.json>` - the same-tape-two-bridges diff.

Stands up a fresh VIRTUAL bridge (Console over TCP, `--backend virtual`) and a REAL side, plays the
tape against each with an identical `probe` client, prints the diff, and exits 0 iff virtual == real.

Two real sides:
  - default (no hardware): the same Console on a PTY, reached through the shipped `--backend serial`
    daemon. This is what `make conformance-uart` runs; a pty is kernel-provided.
  - `--real-target /dev/ttyUSB0`: an ACTUAL board, reached through the shipped `--backend serial`
    daemon opened with `--reset-on-open` (resets the board so its boot-only banner is captured). The
    mask-ROM boot log before the firmware banner is dropped before comparing (docs/design/04, real-device
    mode; conformance/hardware/uart-console-esp32/README.md). This is what `make conformance-uart-real
    TARGET=/dev/ttyUSB0` runs. With `--garble-baud N` it also asserts the wrong-baud read is garbled
    (real silicon only - a pty has no bit clock).
"""

from __future__ import annotations

import argparse
import sys

from .console import BANNER, Console
from .pty_adapter import ConformanceRealSide, RealDeviceSide
from .runner import diff_runs, load_tape, run_tape, trim_real_reads
from .virtual_bridge import VirtualConsoleBridge

# The firmware banner marker used to drop a real board's pre-banner mask-ROM boot chatter.
BANNER_MARKER = BANNER.decode(errors="replace").strip()


def run_conformance(tape_path: str, real_side=None, drop_marker: str | None = None) -> tuple[bool, str]:
    """Run the diff. `real_side` defaults to the pty ConformanceRealSide; pass a RealDeviceSide (or a
    pty stand-in with a boot log) to exercise the real-device path. `drop_marker`, when set, trims the
    real side's pre-banner boot chatter before comparing."""
    tape = load_tape(tape_path)
    steps = tape["steps"]

    # Each side gets its OWN fresh Console instance (same class -> identical behaviour), so the two
    # runs start from an identical device state and any difference is transport, not model drift.
    with VirtualConsoleBridge(Console()) as virtual:
        virtual_results = run_tape(virtual.backend, virtual.target, steps, env=virtual.env)

    real_side = real_side if real_side is not None else ConformanceRealSide(Console())
    with real_side as real:
        real_results = run_tape(real.backend, real.target, steps, env=real.env)

    if drop_marker:
        real_results = trim_real_reads(real_results, drop_marker)

    return diff_runs(virtual_results, real_results)


def check_baud_garble(endpoint: str, garble_baud: int, marker: str) -> tuple[bool, str]:
    """Real-silicon only: bring up the daemon at the WRONG baud (so the boot banner is sampled at the
    wrong rate) and assert the firmware banner does NOT appear in a read - i.e. the line is garbled.

    Returns (garbled, output). On a pty this always returns garbled=False (no bit clock), which is why
    it is a hardware-only assertion (docs/design/04 section 7)."""
    real = RealDeviceSide(endpoint, baud=garble_baud, reset_on_open=True)
    with real as r:
        results = run_tape(r.backend, r.target,
                           [{"argv": ["--baud", str(garble_baud), "uart", "read", "-t", "2"]}],
                           env=r.env)
    out = results[0].stdout if results else ""
    return (marker not in out), out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="conformance.run",
                                 description="UART conformance: virtual == real over the shipped clients.")
    ap.add_argument("tape", help="path to the tape JSON")
    ap.add_argument("--real-target", metavar="DEV",
                    help="drive the real side against an ACTUAL serial device (e.g. /dev/ttyUSB0)")
    ap.add_argument("--real-baud", type=int, default=115200, help="baud for --real-target (default 115200)")
    ap.add_argument("--garble-baud", type=int, metavar="N",
                    help="also assert a wrong-baud read is garbled (real silicon only)")
    args = ap.parse_args(argv)

    if args.real_target:
        real_side = RealDeviceSide(args.real_target, baud=args.real_baud, reset_on_open=True)
        drop_marker = BANNER_MARKER
    else:
        real_side, drop_marker = None, None

    try:
        equal, report = run_conformance(args.tape, real_side=real_side, drop_marker=drop_marker)
    except RuntimeError as e:
        print(f"conformance: {e}", file=sys.stderr)
        return 2
    print(report)
    ok = equal

    if args.real_target and args.garble_baud:
        try:
            garbled, gout = check_baud_garble(args.real_target, args.garble_baud, BANNER_MARKER)
        except RuntimeError as e:
            print(f"conformance: baud-garble check could not run: {e}", file=sys.stderr)
            return 2
        print(f"\nbaud-garble @ {args.garble_baud} (wrong): garbled={garbled}")
        if not garbled:
            print(f"  FAIL: the firmware banner still readable at the wrong baud: {gout!r}")
        ok = ok and garbled

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
