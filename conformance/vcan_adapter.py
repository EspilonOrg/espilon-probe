"""The REAL side for the CAN FRAMED pilot: vcan0 as a genuine in-kernel SocketCAN stack.

Twin of pty_adapter.py::ConformanceRealSide (docs/design/can-framed.md section 4.2). vcan0 IS the
"real medium" (a real SocketCAN stack, not a simulator), so there is no separate hardware target for
the pilot. Two independent PF_CAN sockets live on the bus:

  1. the generalist socketcan `probe-bridge` daemon (the socket the shipped `probe --backend
     socketcan --target vcan0` client discovers and drives) - relays INJECT onto the bus, buffers bus
     frames for SNIFF; NO model;
  2. the UdsEcu responder process (conformance/uds_responder.py) - binds its own PF_CAN socket, reads
     0x7E0 requests, writes 0x7E8 responses.

Bring-up ordering mirrors the pty banner rule: the persistent bridge daemon (a socket bound and
buffering) AND the responder come up BEFORE the tape's first `can send`, so no response is lost to an
unbound bus. The per-verb `probe --backend socketcan` invocations then DISCOVER the same daemon by
target (an isolated rendezvous dir so the harness owns its lifetime).
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile

from espilon_probe.backends.serial import _runtime_dir, _target_key

from . import uds_responder

_BRIDGE_READY_PREFIX = "PROBE_BRIDGE_LISTENING"


class VcanRealSide:
    """The real side: the generalist socketcan bridge daemon on vcan0 + a separate UdsEcu responder,
    driven by `probe --backend socketcan --target vcan0`."""

    backend = "socketcan"

    def __init__(self, iface: str = "vcan0"):
        self.iface = iface
        self._bridge: subprocess.Popen | None = None
        self._responder: subprocess.Popen | None = None
        self._runtime: str | None = None
        self._info_path: str | None = None

    @property
    def target(self) -> str:
        return self.iface

    @property
    def env(self) -> dict:
        """Environment the runner passes to `probe` so it discovers THIS bridge daemon (isolated
        rendezvous dir + a short idle lifetime so nothing leaks)."""
        e = dict(os.environ)
        e["ESPILON_PROBE_RUNTIME"] = self._runtime or ""
        e["ESPILON_PROBE_BRIDGE_IDLE"] = "30"
        return e

    def start(self) -> str:
        self._runtime = tempfile.mkdtemp(prefix="espilon-probe-can-")
        os.environ["ESPILON_PROBE_RUNTIME"] = self._runtime
        os.environ["ESPILON_PROBE_BRIDGE_IDLE"] = "30"
        self._info_path = os.path.join(_runtime_dir(),
                                       f"{_target_key('socketcan', self.iface)}.json")

        # 1) the generalist socketcan bridge daemon on vcan0 (bound + buffering BEFORE any inject),
        # announcing to the SAME rendezvous file the `probe --backend socketcan` client looks up.
        bridge_cmd = [sys.executable, "-m", "espilon_probe.bridges",
                      "--medium", "socketcan", "--endpoint", self.iface,
                      "--listen", "127.0.0.1:0", "--announce", self._info_path,
                      "--idle-timeout", "30"]
        self._bridge = subprocess.Popen(bridge_cmd, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True)
        self._await(self._bridge, _BRIDGE_READY_PREFIX, "socketcan bridge")

        # 2) the UdsEcu responder bound to vcan0 (up BEFORE the first request is injected).
        resp_cmd = [sys.executable, "-m", "conformance.uds_responder", "--iface", self.iface]
        self._responder = subprocess.Popen(resp_cmd, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, text=True)
        self._await(self._responder, uds_responder.READY_PREFIX, "uds responder")
        return self.iface

    def _await(self, proc: subprocess.Popen, prefix: str, label: str) -> None:
        line = proc.stdout.readline() if proc.stdout else ""
        if not line.strip().startswith(prefix):
            err = proc.stderr.read() if proc.stderr else ""
            raise RuntimeError(f"{label} did not start: {line.strip()!r} {err.strip()}")

    def stop(self) -> None:
        for proc in (self._responder, self._bridge):
            if proc is None:
                continue
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            for stream in (proc.stdout, proc.stderr):
                try:
                    if stream:
                        stream.close()
                except Exception:
                    pass
        if self._info_path:
            try:
                os.unlink(self._info_path)
            except OSError:
                pass

    def __enter__(self) -> "VcanRealSide":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()
