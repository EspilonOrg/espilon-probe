"""`python -m conformance.run_gatt [--virtual-only] <tape.json>` - the BLE GATT conformance runner.

The TRANSACTION-shape counterpart to run.py (UART) and run_can.py (CAN). The observable is stdout +
exit code (like UART, not the pcap CAN uses): the `probe gatt` CLI renders the op result to stdout
(enum rows, read value, write ack) and an ATT error to stderr with a nonzero exit, so the comparator
is essentially runner.normalize plus a stderr-aware content check for the ATT errors.

TWO legs, and a DELIBERATE asymmetry vs CAN (docs/design/ble-gatt.md sections 0.3, 4.6):

  - `--virtual-only` (the CI GATE): play the tape against ONLY the virtual GATT bridge (GattServer
    behind GattOpMedium over _serve_op). Needs nothing but stdlib - no bleak, no BlueZ, no hardware -
    so it runs anywhere. This is the virtual-self-consistent bar: it proves _serve_op + GattServer
    end to end over the SHIPPED client, and the tape's per-step `exit` / `expect` / `expect_stderr`
    are the oracle (there is no second software leg to diff against).

  - full mode (the SPOT-CHECK): virtual == the real AX201<->ESP32 leg. BLE has NO software loopback
    (no "vble"), so this needs the [hci] extra AND a reflashed peripheral and is a GATED spot-check on
    the dev box, NOT a CI gate. When either prerequisite is absent it prints the setup hint and exits
    77 (the automake skip code), never fails - the same clean-skip contract as conformance-can on a
    missing vcan0. The real leg (an hci_adapter driving bleak) is NOT built in this pilot.

Exit codes: 0 pass, 1 a diff/oracle mismatch, 2 a bring-up error, 77 the real leg's prerequisites
are absent (a skip, not a failure).
"""

from __future__ import annotations

import sys

from .gatt_server import GattServer
from .runner import load_tape, normalize, run_tape
from .virtual_gatt_bridge import VirtualGattBridge


def _has_hci() -> bool:
    """True iff a BlueZ adapter is usable AND `import bleak` succeeds - the real leg's prerequisites.

    Conservative: any failure (no bleak, no adapter, no permission) returns False so the real leg
    SKIPS cleanly rather than erroring. The pilot never runs this (there is no real-leg harness yet);
    it is the guard the gated hardware session's runner uses, mirroring run_can._has_vcan."""
    try:
        import bleak  # noqa: F401
    except ImportError:
        return False
    try:
        import socket
        # A BlueZ HCI socket proves an adapter/stack is present without opening a device.
        s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)  # type: ignore[attr-defined]
        s.close()
        return True
    except (OSError, AttributeError):
        return False


def _esp32_present() -> bool:
    """True iff the pilot GATT-server peripheral is advertising / reachable. Unbuildable without the
    reflashed board + bleak, so it is always False in this pilot (the firmware is the gated hardware
    follow-up); the gated session's runner fills this in. Kept as the explicit skip guard so the real
    leg can never silently run against a board that is not there."""
    return False


def check_virtual(results, steps) -> tuple[bool, str]:
    """The virtual-self-consistent oracle: each step's exit code matches the tape's `exit`, each
    `expect` substring is present in stdout, and each `expect_stderr` substring is present in stderr.

    The stderr check is what makes the ATT-error path a HARD assertion (an error rendered to stderr
    with a nonzero exit), so a "the tool rendered nothing / exited zero" regression on an error step
    cannot pass green - the transaction analogue of the UART harness's expect-content check."""
    lines: list[str] = []
    ok = True
    if len(results) != len(steps):
        return False, f"step count differs: results={len(results)} tape={len(steps)}"

    lines.append(f"{'step':<4} {'argv':<26} {'stdout':<18} exit  result")
    lines.append("-" * 70)
    for i, (res, step) in enumerate(zip(results, steps)):
        want_exit = step.get("exit", 0)
        step_ok = res.exit_code == want_exit
        for want in step.get("expect", []):
            if want not in res.stdout:
                step_ok = False
                lines.append(f"  step {i} ({' '.join(res.argv)}): missing {want!r} in "
                             f"stdout={res.stdout!r}")
        for want in step.get("expect_stderr", []):
            if want not in res.stderr:
                step_ok = False
                lines.append(f"  step {i} ({' '.join(res.argv)}): missing {want!r} in "
                             f"stderr={res.stderr!r}")
        if res.exit_code != want_exit:
            lines.append(f"  step {i} ({' '.join(res.argv)}): exit {res.exit_code} != "
                         f"expected {want_exit}")
        ok = ok and step_ok
        stdout, code = normalize(res)
        lines.append(f"{i:<4} {_argv(res.argv):<26} {_show(stdout):<18} {code:<5} "
                     f"{'OK' if step_ok else 'FAIL'}")

    lines.append("-" * 70)
    lines.append(f"\nRESULT: {'PASS (virtual self-consistent, content present)' if ok else 'FAIL'}")
    return ok, "\n".join(lines)


def run_virtual_only(tape_path: str) -> tuple[list, list[dict]]:
    """Play the tape against ONLY the virtual GATT bridge (no bleak / no BlueZ / no hardware). Proves
    the transaction serve path + the model end to end over the shipped client."""
    tape = load_tape(tape_path)
    steps = tape["steps"]
    with VirtualGattBridge(GattServer()) as virtual:
        results = run_tape(virtual.backend, virtual.target, steps, env=virtual.env)
    return results, steps


def _argv(argv: list[str]) -> str:
    s = " ".join(argv)
    return s if len(s) <= 26 else s[:23] + "..."


def _show(stdout: str) -> str:
    r = repr(stdout)
    return r if len(r) <= 16 else r[:13] + "...'"


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    virtual_only = "--virtual-only" in args
    tape_args = [a for a in args if a != "--virtual-only"]
    if not tape_args:
        print("usage: python -m conformance.run_gatt [--virtual-only] <tape.json>", file=sys.stderr)
        return 2
    tape_path = tape_args[0]

    if not virtual_only:
        # The real AX201<->ESP32 spot-check: skip cleanly (exit 77) unless the [hci] extra AND the
        # reflashed peripheral are both present. The real-leg diff harness is the gated follow-up.
        if not (_has_hci() and _esp32_present()):
            print("conformance-gatt-real: no [hci] extra / BlueZ adapter / advertising ESP32 "
                  "peripheral; skipping the virtual==real spot-check.", file=sys.stderr)
            print("  install the extra: pip install 'espilon-probe[hci]', flash the pilot "
                  "GATT-server firmware, then re-run without --virtual-only.", file=sys.stderr)
            return 77                       # automake skip code: a skip, not a failure
        print("conformance-gatt-real: the real-leg diff harness is the gated hardware follow-up "
              "and is not built in this pilot.", file=sys.stderr)
        return 2

    try:
        results, steps = run_virtual_only(tape_path)
    except RuntimeError as e:
        print(f"conformance-gatt: {e}", file=sys.stderr)
        return 2
    ok, report = check_virtual(results, steps)
    print(report)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
