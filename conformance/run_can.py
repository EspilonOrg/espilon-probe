"""`python -m conformance.run_can <tape.json>` - the CAN FRAMED same-tape-two-bridges diff.

Stands up a VIRTUAL CAN bridge (the UdsEcu behind CanFrameMedium over TCP, `--backend virtual`) and a
REAL side (the generalist socketcan bridge on vcan0 + a SEPARATE UdsEcu responder process, `--backend
socketcan`), plays the SAME argv tape against each with the shipped `probe` client, and diffs the
captured pcap frames.

The observable for CAN is the pcap `can dump` writes, not stdout (docs/design/can-framed.md
section 4.3): for each `can dump` step we read the produced pcap, take the ORDERED list of frame
`raw` payloads, and diff virtual-vs-real byte-for-byte - pcap timestamps are normalized out simply by
comparing only the frame bytes (read_pcap discards the record header). A per-step `expect` content
check (each declared response PDU must be decodable-present on BOTH sides) additionally guarantees a
"both sides captured nothing identically" regression cannot pass green.

Exit codes mirror the UART runner + the vcan skip contract:
  0  virtual == real and every expected frame present
  1  a real diff
  2  a bring-up error
  77 vcan0 absent (the automake skip code; `conformance-can` is a make target, so this is a clean
     skip, not a silent pass).
"""

from __future__ import annotations

import copy
import os
import shutil
import socket
import sys
import tempfile

from espilon_probe.core.frame import read_pcap

from . import can_isotp
from .runner import load_tape, run_tape
from .uds_ecu import UdsEcu
from .vcan_adapter import VcanRealSide
from .virtual_can_bridge import VirtualCanBridge

_WRITE_FLAGS = ("-w", "--write")


def _has_vcan(name: str = "vcan0") -> bool:
    """True iff a SocketCAN interface `name` exists and can be bound (mirrors
    tests/test_socketcan_live.py exactly)."""
    try:
        s = socket.socket(socket.PF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
        s.bind((name,))
        s.close()
        return True
    except OSError:
        return False


def _rewrite_dumps(steps: list[dict], tmpdir: str) -> tuple[list[dict], dict[int, str]]:
    """Give each `can dump -w <name>` step its OWN pcap path under `tmpdir`, so both sides' captures
    persist for comparison and successive dumps never overwrite each other. Returns the rewritten
    steps and a {step_index: pcap_path} map."""
    out: list[dict] = []
    dump_paths: dict[int, str] = {}
    for i, step in enumerate(steps):
        step = copy.deepcopy(step)
        argv = [str(a) for a in step.get("argv", [])]
        for j, tok in enumerate(argv):
            if tok in _WRITE_FLAGS and j + 1 < len(argv):
                path = os.path.join(tmpdir, f"cap{i}.pcap")
                argv[j + 1] = path
                dump_paths[i] = path
        step["argv"] = argv
        out.append(step)
    return out, dump_paths


def _read_frames(path: str) -> list[str]:
    """The ordered list of frame `raw` payloads (hex) in a pcap, or [] if it is missing/empty."""
    if not os.path.exists(path):
        return []
    try:
        _dlt, frames = read_pcap(path)
    except (OSError, ValueError):
        return []
    return [f.hex() for f in frames]


def _pdus(frame_hexes: list[str]) -> list[str]:
    """Decode captured frames to their UDS PDUs (hex), dropping any non-SF frame."""
    out: list[str] = []
    for h in frame_hexes:
        try:
            _id, pdu = can_isotp.decode(bytes.fromhex(h))
        except ValueError:
            continue
        out.append(pdu.hex())
    return out


def _run_side(backend: str, target: str, steps: list[dict], env: dict) -> tuple[list, dict[int, list[str]]]:
    tmpdir = tempfile.mkdtemp(prefix="espilon-can-cap-")
    try:
        rewritten, dump_paths = _rewrite_dumps(steps, tmpdir)
        results = run_tape(backend, target, rewritten, env=env)
        captures = {i: _read_frames(path) for i, path in dump_paths.items()}
        return results, captures
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _norm(hexes) -> list[str]:
    return [str(h).replace(" ", "").lower() for h in hexes]


def diff_runs(virtual, real, steps) -> tuple[bool, str]:
    """Compare the two runs: exit codes, the per-dump-step captured-frame lists (byte-for-byte), and
    the per-step response-PDU content expectations on BOTH sides."""
    vres, vcap = virtual
    rres, rcap = real
    lines: list[str] = []
    equal = True

    if len(vres) != len(rres):
        return False, f"step count differs: virtual={len(vres)} real={len(rres)}"

    lines.append(f"{'step':<4} {'argv':<26} {'v.frames':<10} {'r.frames':<10} result")
    lines.append("-" * 70)
    dump_indices = sorted(set(vcap) | set(rcap))
    for i in dump_indices:
        vf, rf = vcap.get(i, []), rcap.get(i, [])
        step_equal = vf == rf
        equal = equal and step_equal
        lines.append(f"{i:<4} {_argv(vres[i].argv):<26} {len(vf):<10} {len(rf):<10} "
                     f"{'OK' if step_equal else 'DIFFER'}")
        if not step_equal:
            lines.append(f"       virtual frames: {vf}")
            lines.append(f"       real frames:    {rf}")

    # Exit codes must match and be clean on both sides (a send/dump that errored one side only).
    for i, (v, r) in enumerate(zip(vres, rres)):
        if v.exit_code != r.exit_code:
            equal = False
            lines.append(f"  step {i} ({' '.join(v.argv)}): exit differs "
                         f"virtual={v.exit_code} real={r.exit_code}")
            lines.append(f"       virtual stdout={v.stdout!r}")
            lines.append(f"       real    stdout={r.stdout!r}")

    # Content expectations on BOTH sides (so "both captured nothing identically" cannot pass): each
    # dump step's declared response PDUs must be decodable-present in that side's captured frames.
    lines.append("-" * 70)
    content_ok = True
    for i in dump_indices:
        want = _norm(steps[i].get("expect", []))
        if not want:
            continue
        v_pdus, r_pdus = _pdus(vcap.get(i, [])), _pdus(rcap.get(i, []))
        for w in want:
            if w not in v_pdus:
                content_ok = False
                lines.append(f"  [virtual] step {i}: expected PDU {w!r} not in {v_pdus}")
            if w not in r_pdus:
                content_ok = False
                lines.append(f"  [real]    step {i}: expected PDU {w!r} not in {r_pdus}")
    equal = equal and content_ok
    lines.append(f"content expectations present (virtual & real): {content_ok}")

    lines.append(f"\nRESULT: {'PASS (virtual == real, content present)' if equal else 'FAIL'}")
    return equal, "\n".join(lines)


def _argv(argv: list[str]) -> str:
    s = " ".join(argv)
    return s if len(s) <= 26 else s[:23] + "..."


def run_conformance(tape_path: str) -> tuple[bool, str]:
    """Run the diff. Each side gets its OWN fresh UdsEcu (same class -> identical behaviour), so the
    two runs start from an identical device state and any difference is transport, not model drift."""
    tape = load_tape(tape_path)
    steps = tape["steps"]

    with VirtualCanBridge(UdsEcu()) as virtual:
        virtual_run = _run_side(virtual.backend, virtual.target, steps, virtual.env)

    with VcanRealSide() as real:
        real_run = _run_side(real.backend, real.target, steps, real.env)

    return diff_runs(virtual_run, real_run, steps)


def run_virtual_only(tape_path: str) -> tuple[list, dict[int, list[str]], list[dict]]:
    """Play the tape against ONLY the virtual bridge (no vcan0 / no root needed). Proves the generic
    FRAMED serve path + the model end-to-end over the shipped client; the real leg (and the full
    virtual==real diff) needs vcan0."""
    tape = load_tape(tape_path)
    steps = tape["steps"]
    with VirtualCanBridge(UdsEcu()) as virtual:
        results, captures = _run_side(virtual.backend, virtual.target, steps, virtual.env)
    return results, captures, steps


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print("usage: python -m conformance.run_can <tape.json>", file=sys.stderr)
        return 2
    tape_path = args[0]

    if not _has_vcan():
        print("conformance-can: no vcan0; skipping the virtual==real diff.", file=sys.stderr)
        print("  bring it up with: sudo ip link add dev vcan0 type vcan && "
              "sudo ip link set up vcan0", file=sys.stderr)
        return 77                    # automake skip code: a skip, not a failure

    try:
        equal, report = run_conformance(tape_path)
    except RuntimeError as e:
        print(f"conformance-can: {e}", file=sys.stderr)
        return 2
    print(report)
    return 0 if equal else 1


if __name__ == "__main__":
    raise SystemExit(main())
