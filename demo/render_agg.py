#!/usr/bin/env python3
"""Fallback renderer for the probe demo GIFs (asciinema cast + agg).

The canonical demo scripts are the VHS `*.tape` files. VHS drives ttyd + a headless
chromium, which this sandbox refused to run; agg (pure Rust, no browser) is the sanctioned
fallback. Rather than depend on a live PTY of the right size, this builds asciicast v2 files
directly: it simulates the typed prompt, runs the REAL `probe` commands, and captures their
REAL stdout, then hands the cast to `agg` to produce the GIF. Same commands, same output as
the tapes; only the recording mechanism differs.

Usage:
    python3 demo/render_agg.py --agg /path/to/agg [--only demo-gatt]

Env it expects: a probe venv on PATH (so `probe` resolves) and demo_bridge.py alongside.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
BRIDGE = os.path.join(HERE, "demo_bridge.py")

PROMPT = "\x1b[36mprobe-demo\x1b[0m \x1b[2m$\x1b[0m "   # cyan name + dim $
CHAR_DT = 0.028        # per-typed-char delay
AFTER_ENTER = 0.18     # pause after Enter before output
COLS = 118
FONT_SIZE = 15
THEME = "dracula"

# Each demo: scenario, tcp port, run-dir, and the visible command list. `pause` is the
# dwell after that command's output (seconds).
DEMOS = {
    "demo-info": dict(scenario="info", port=5551, steps=[
        ("probe --help", 3.2),
        ("probe info", 3.2),
    ]),
    "demo-scan-sniff": dict(scenario="zigbee", port=5552, steps=[
        ("probe info", 1.6),
        ("probe scan", 2.2),
        ("probe sniff -w capture.pcap -c 8", 1.8),
        ("file capture.pcap", 3.0),
    ]),
    "demo-gatt": dict(scenario="gatt", port=5553, steps=[
        ("probe scan", 1.8),
        ("probe gatt enum", 2.0),
        ("probe gatt read 0x0011", 1.6),
        ("probe gatt write 0x0014 01", 1.6),
        ("probe gatt read 0x0011", 3.0),
    ]),
    "demo-bus": dict(scenario="spi", port=5554, steps=[
        ("probe spi id", 1.8),
        ("probe spi read --addr 0 --len 32", 1.8),
        ("probe spi dump --len 4096 -w flash.bin", 1.6),
        ("hexdump -C flash.bin | head -4", 3.0),
    ]),
    "demo-solve": dict(scenario="solve", port=5555, steps=[
        ("probe scan", 1.8),
        ("probe gatt enum", 1.8),
        ("probe gatt read 0x0011", 1.4),
        ("probe gatt write 0x0014 c0ffee", 1.4),
        ("probe gatt read 0x0011", 3.5),
    ]),
}


class Cast:
    """Accumulates asciicast v2 events with a running clock; writes a .cast file."""

    def __init__(self, width, height):
        self.width = width
        self.height = height
        self.t = 0.0
        self.events = []

    def out(self, data, dt=0.0):
        self.t += dt
        self.events.append([round(self.t, 4), "o", data])

    def type_line(self, cmd):
        self.out(PROMPT, 0.25)
        for ch in cmd:
            self.out(ch, CHAR_DT)
        self.out("\r\n", 0.12)

    def emit_output(self, text):
        if not text:
            return
        text = text.replace("\n", "\r\n")
        self.out(text, AFTER_ENTER)

    def write(self, path):
        header = {"version": 2, "width": self.width, "height": self.height,
                  "timestamp": int(time.time()),
                  "env": {"TERM": "xterm-256color", "SHELL": "/bin/bash"}}
        with open(path, "w") as fh:
            fh.write(json.dumps(header) + "\n")
            for ev in self.events:
                fh.write(json.dumps(ev) + "\n")


def wait_port(port, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def run_cmd(cmd, cwd, env):
    """Run a visible command through bash (so pipes/redirs/`file`/`hexdump` work),
    capturing combined stdout+stderr exactly as the terminal would show it."""
    p = subprocess.run(["bash", "-c", cmd], cwd=cwd, env=env,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return p.stdout.decode("utf-8", "replace")


def build_demo(name, spec, agg_path, out_dir, run_root, env_base):
    port = spec["port"]
    run_dir = os.path.join(run_root, name)
    os.makedirs(run_dir, exist_ok=True)
    # clean any prior artifacts so the recording is deterministic
    for f in os.listdir(run_dir):
        os.remove(os.path.join(run_dir, f))

    bridge = subprocess.Popen([sys.executable, BRIDGE, "--scenario", spec["scenario"],
                               "--port", str(port)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_port(port):
            raise RuntimeError(f"{name}: bridge did not open port {port}")
        env = dict(env_base)
        env["ESP_PROBE"] = f"tcp://127.0.0.1:{port}"

        # Render each step, measuring content height so nothing scrolls.
        cast = Cast(COLS, 24)
        lines = 1
        for cmd, pause in spec["steps"]:
            cast.type_line(cmd)
            lines += 1
            out = run_cmd(cmd, run_dir, env)
            cast.emit_output(out)
            lines += out.count("\n") + (0 if out.endswith("\n") else 1) if out else 0
            cast.t += pause          # dwell
        cast.height = max(12, lines + 2)

        cast_path = os.path.join(run_dir, name + ".cast")
        cast.write(cast_path)

        gif_path = os.path.join(out_dir, name + ".gif")
        agg_cmd = [agg_path, "--theme", THEME, "--font-size", str(FONT_SIZE),
                   "--idle-time-limit", "2.5", "--cols", str(COLS),
                   "--rows", str(cast.height), cast_path, gif_path]
        r = subprocess.run(agg_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        ok = r.returncode == 0 and os.path.exists(gif_path)
        size = os.path.getsize(gif_path) if ok else 0
        print(f"[{'OK' if ok else 'FAIL'}] {name}: rows={cast.height} "
              f"gif={'%.0fKB' % (size/1024) if ok else 'none'}")
        if not ok:
            print(r.stdout.decode("utf-8", "replace"))
        return ok
    finally:
        bridge.send_signal(signal.SIGTERM)
        try:
            bridge.wait(timeout=3)
        except subprocess.TimeoutExpired:
            bridge.kill()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agg", required=True, help="path to the agg binary")
    ap.add_argument("--only", help="render just one demo (e.g. demo-gatt)")
    ap.add_argument("--run-root", default=os.path.join(REPO, ".demo-work", "run"))
    args = ap.parse_args()

    env_base = dict(os.environ)
    env_base["ESP_PROBE_TIMEOUT"] = "10"
    env_base["TERM"] = "xterm-256color"

    names = [args.only] if args.only else list(DEMOS)
    os.makedirs(args.run_root, exist_ok=True)
    results = {}
    for name in names:
        results[name] = build_demo(name, DEMOS[name], args.agg, HERE,
                                   args.run_root, env_base)
    ok = sum(results.values())
    print(f"\n{ok}/{len(results)} demos rendered")
    sys.exit(0 if ok == len(results) else 1)


if __name__ == "__main__":
    main()
