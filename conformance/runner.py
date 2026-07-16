"""Tape runner, normalizer, content expectations, and the same-tape-two-bridges diff (docs/design/04).

A TAPE is an ordered list of `probe` invocations (argv only, no backend knowledge). The runner plays
a tape against a target bridge by invoking the real `probe` CLI as a subprocess per step - one
short-lived connection per verb, exactly as a user runs it (docs/design/04 section 3) - through whatever
`--backend`/`--target` that side uses (VIRTUAL via `--backend virtual`, REAL via the shipped
`--backend serial`). The DIFF plays the SAME tape against both and asserts the normalized observables
are equal; an `expected`-mode content check additionally asserts the banner and each command response
are actually PRESENT on both, so a "both sides lose the data identically" regression cannot pass as
green.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass


@dataclass
class StepResult:
    argv: list[str]
    stdout: str
    exit_code: int
    expect: list[str]
    # Captured stderr. The UART/CAN diffs compare stdout+exit only (normalize), but the transaction
    # (GATT) leg renders an ATT error to stderr with a nonzero exit, so its harness asserts the error
    # text here. Defaulted so existing constructors (trim_real_reads, tests) are unaffected.
    stderr: str = ""


# A generous per-step ceiling: a stream `read -t N` can legitimately wait N seconds; give margin.
_STEP_TIMEOUT = 30.0


def load_tape(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        tape = json.load(fh)
    if not isinstance(tape, dict) or not isinstance(tape.get("steps"), list):
        raise ValueError(f"malformed tape {path!r}: expected an object with a 'steps' list")
    return tape


def run_tape(backend: str, target: str, steps: list[dict], env: dict | None = None) -> list[StepResult]:
    """Play a tape against one bridge (`--backend backend --target target`), per-step observables."""
    results: list[StepResult] = []
    for step in steps:
        argv = step.get("argv")
        if not isinstance(argv, list):
            raise ValueError(f"malformed step (no argv list): {step!r}")
        expect = step.get("expect", [])
        if isinstance(expect, str):
            expect = [expect]
        cmd = [sys.executable, "-m", "espilon_probe.cli",
               "--backend", backend, "--target", target, *[str(a) for a in argv]]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=_STEP_TIMEOUT, env=env)
        results.append(StepResult(argv=[str(a) for a in argv], stdout=proc.stdout,
                                  exit_code=proc.returncode, expect=list(expect),
                                  stderr=proc.stderr))
    return results


def trim_real_reads(results: list[StepResult], marker: str) -> list[StepResult]:
    """Drop a real device's pre-banner boot chatter before comparing (docs/design/04, real-device mode).

    A real board (e.g. the classic ESP32) prints a mask-ROM boot log (`rst:0x.. ets ..`) on reset
    BEFORE the firmware banner. That noise is real hardware, not a fidelity difference, so on the real
    side we drop everything before the FIRST occurrence of the firmware banner `marker` in each read's
    stdout (reads without the marker are untouched). Both sides then start at the same banner. This
    is applied ONLY to the real side and ONLY in real-device mode; the virtual side is never trimmed."""
    out: list[StepResult] = []
    for r in results:
        stdout = r.stdout
        if _is_read(r.argv):
            idx = stdout.find(marker)
            if idx > 0:
                stdout = stdout[idx:]
        out.append(StepResult(argv=r.argv, stdout=stdout, exit_code=r.exit_code, expect=r.expect))
    return out


def normalize(result: StepResult) -> tuple[str, int]:
    """Strip exactly the allowed-to-differ surfaces (docs/design/04 section 3) before comparing.

    For the UART read/write pilot the observable is raw console bytes and a `wrote N byte(s)` line:
    there is nothing wall-clock in it, so this is the identity on stdout (we do NOT over-normalize -
    over-normalizing hides real drift). The pcap-timestamp / RSSI / random-id stripping this hook is
    the home for lands with the FRAMED protocols and UART `sniff` (deferred with the byte-log tee)."""
    return result.stdout, result.exit_code


def check_expectations(label: str, results: list[StepResult]) -> tuple[bool, list[str]]:
    """`expected`-mode content check: every substring a step declares in `expect` must appear in that
    step's stdout on this backend. This is what makes "the banner / command response is actually
    present" a hard assertion, so a silent both-sides-empty regression fails."""
    ok = True
    lines: list[str] = []
    for i, r in enumerate(results):
        for want in r.expect:
            if want not in r.stdout:
                ok = False
                lines.append(f"  [{label}] step {i} ({' '.join(r.argv)}): "
                             f"missing expected {want!r} in stdout={r.stdout!r}")
    return ok, lines


def diff_runs(virtual: list[StepResult], real: list[StepResult]) -> tuple[bool, str]:
    """Compare two runs step-by-step, on the concatenated RX, and on the per-step content
    expectations. Return (equal_and_expected, human report)."""
    lines: list[str] = []
    equal = True
    if len(virtual) != len(real):
        return False, f"step count differs: virtual={len(virtual)} real={len(real)}"

    lines.append(f"{'step':<4} {'argv':<28} {'virtual':<20} {'real (serial/pty)':<20} result")
    lines.append("-" * 92)
    for i, (v, r) in enumerate(zip(virtual, real)):
        vn, rn = normalize(v), normalize(r)
        step_equal = vn == rn
        equal = equal and step_equal
        lines.append(f"{i:<4} {_argv(v.argv):<28} {_show(vn):<20} {_show(rn):<20} "
                     f"{'OK' if step_equal else 'DIFFER'}")
        if not step_equal:
            lines.append(f"       virtual: stdout={v.stdout!r} exit={v.exit_code}")
            lines.append(f"       real:    stdout={r.stdout!r} exit={r.exit_code}")

    # Concatenated-RX check (docs/design/04 section 3): a stream has no chunking to normalize, so drain each
    # backend's RX to idle, concatenate, and compare the two byte strings.
    v_rx = "".join(s.stdout for s in virtual if _is_read(s.argv))
    r_rx = "".join(s.stdout for s in real if _is_read(s.argv))
    rx_equal = v_rx == r_rx
    equal = equal and rx_equal
    lines.append("-" * 92)
    lines.append(f"concatenated RX equal: {rx_equal}")
    if not rx_equal:
        lines.append(f"  virtual RX: {v_rx!r}")
        lines.append(f"  real RX:    {r_rx!r}")

    # Content expectations on BOTH sides (so "both empty" cannot pass).
    v_ok, v_missing = check_expectations("virtual", virtual)
    r_ok, r_missing = check_expectations("real", real)
    expected_ok = v_ok and r_ok
    equal = equal and expected_ok
    lines.append(f"content expectations present (virtual & real): {expected_ok}")
    lines.extend(v_missing)
    lines.extend(r_missing)

    lines.append(f"\nRESULT: {'PASS (virtual == real, content present)' if equal else 'FAIL'}")
    return equal, "\n".join(lines)


def _is_read(argv: list[str]) -> bool:
    return "uart" in argv and "read" in argv


def _argv(argv: list[str]) -> str:
    s = " ".join(argv)
    return s if len(s) <= 28 else s[:25] + "..."


def _show(norm: tuple[str, int]) -> str:
    stdout, code = norm
    r = repr(stdout)
    if len(r) > 16:
        r = r[:13] + "...'"
    return f"{r} x{code}"
