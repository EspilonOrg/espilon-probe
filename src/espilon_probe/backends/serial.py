"""serial backend: a loopback launcher for a real UART over a serial device or pty.

`probe --backend serial --target /dev/ttyUSB0` stays simple for the user, but internally probe
reaches a PERSISTENT `probe-bridge` daemon for the serial medium and connects to it over the
ordinary wire tunnel (docs/design/00 decision 5, docs/design/02 sections 3-4). The client holds ZERO medium
knowledge: the fd + termios + raw-pump I/O lives in the bridge's serial medium; here the client
only does process orchestration + rendezvous.

Why PERSISTENT (the fix for "async output lost between verbs"): each `probe` invocation is one
short-lived connection running one verb. If every verb spawned and tore down its own bridge, the
medium (and its RX buffer) would close between a `probe uart write` and a later `probe uart read`,
losing the device output emitted in between - exactly the failure mode the corpus's persistent
session solves. So the FIRST `probe --backend serial --target X` spawns a detached daemon that holds
the medium open and keeps its RX FIFO; SUBSEQUENT invocations for the same target DISCOVER and
connect to the already-running daemon instead of spawning a new one. The daemon retires itself on an
idle timeout or when the medium goes away, so nothing leaks. Discovery is a per-target rendezvous
file (port + pid) under a runtime dir; the spawn decision is serialized by a file lock AND the
liveness check trusts the registered PID - a transient reachability-probe failure under connection
fan-out is NOT read as "no daemon" - so concurrent first-touches converge on a SINGLE daemon.

This is a subclass of the tunnel client (VirtualBackend): once connected it IS the tunnel client, so
the RAW-STREAM path (`stream_read`/`stream_write`) is inherited unchanged. `close()` only closes the
tunnel connection; it does NOT kill the daemon (that is the whole point of persistence).
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time

from .virtual import VirtualBackend

# How long to wait for a freshly-spawned daemon to announce its port.
_SPAWN_READY_TIMEOUT = 10.0
# Idle lifetime handed to an auto-spawned daemon (overridable for tests via env, below).
_DEFAULT_IDLE_TIMEOUT = 120.0


class SerialBackend(VirtualBackend):
    _transport_label = "serial"

    def __init__(self, target: str | None = None, baud: int = 115200):
        # The tunnel target is not known until we discover/spawn the daemon (set in open()).
        super().__init__(target=None, baud=baud)
        self.endpoint = target or "/dev/ttyUSB0"

    def open(self) -> None:
        port = _ensure_bridge("serial", self.endpoint, self.baud)
        self.target = f"tcp://127.0.0.1:{port}"
        super().open()

    # close() is inherited from VirtualBackend: it closes ONLY the tunnel connection. The daemon is
    # persistent and retires on its own idle timeout / medium EOF; we deliberately do not kill it.


# --- persistent-daemon rendezvous ----------------------------------------------------------------

def _runtime_dir() -> str:
    """A per-user runtime dir for the rendezvous files. Overridable with ESPILON_PROBE_RUNTIME
    (tests point it at a tmp dir for isolation)."""
    base = (os.environ.get("ESPILON_PROBE_RUNTIME")
            or os.environ.get("XDG_RUNTIME_DIR")
            or tempfile.gettempdir())
    path = os.path.join(base, "espilon-probe")
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def _target_key(medium: str, endpoint: str) -> str:
    raw = f"{medium}\0{endpoint}\0{os.getuid()}".encode("utf-8")
    return hashlib.sha1(raw).hexdigest()[:16]


def _idle_timeout() -> float:
    raw = os.environ.get("ESPILON_PROBE_BRIDGE_IDLE")
    if raw is None:
        return _DEFAULT_IDLE_TIMEOUT
    try:
        return float(raw)
    except ValueError:
        return _DEFAULT_IDLE_TIMEOUT


def _ensure_bridge(medium: str, endpoint: str, baud: int) -> int:
    """Return the loopback port of a running daemon for (medium, endpoint), spawning one if needed.

    Discover-or-spawn under a per-target file lock so two concurrent first-invocations cannot spawn
    two daemons for the same target."""
    key = _target_key(medium, endpoint)
    info_path = os.path.join(_runtime_dir(), f"{key}.json")
    lock_path = os.path.join(_runtime_dir(), f"{key}.lock")

    port = _connect_existing(info_path)
    if port is not None:
        return port

    import fcntl
    with open(lock_path, "w") as lockf:
        fcntl.flock(lockf, fcntl.LOCK_EX)
        try:
            port = _connect_existing(info_path)          # re-check under the lock
            if port is not None:
                return port
            return _spawn_daemon(medium, endpoint, baud, info_path)
        finally:
            fcntl.flock(lockf, fcntl.LOCK_UN)


def _connect_existing(info_path: str) -> int | None:
    """If a live daemon is registered at `info_path`, return its port; else clean a stale file.

    Liveness trusts the registered PID. A daemon writes its rendezvous file only AFTER binding, so
    `pid alive` implies `port bound`; we then confirm reachability WITH RETRIES, because under a
    burst of concurrent connects a single probe can transiently fail (backlog pressure) even though
    the daemon is fine. We only declare a registration stale - remove it, so the caller spawns - when
    the PID is DEAD (or the file is unreadable). This is what stops a transient probe failure from
    being misread as absence and spawning a SECOND daemon (which would steal RX)."""
    try:
        with open(info_path, "r", encoding="utf-8") as fh:
            info = json.load(fh)
        port, pid = int(info["port"]), int(info["pid"])
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if not _pid_alive(pid):
        try:
            os.unlink(info_path)                         # the daemon is gone: truly stale
        except OSError:
            pass
        return None
    # PID alive: the daemon exists. Confirm the port answers, RETRYING so a transient backlog blip
    # never demotes a live daemon to "absent" (that was the double-spawn bug). With the large listen
    # backlog the kernel completes the handshake for a genuinely-live daemon immediately, so several
    # retries always succeed for a real daemon under fan-out. Only if the port stays dead across all
    # retries (the PID was reused by an unrelated process after a SIGKILLed daemon left its file) do
    # we treat it as stale and let the caller respawn - self-healing without ever double-spawning a
    # live one.
    if _port_reachable(port, attempts=8):
        return port
    try:
        os.unlink(info_path)
    except OSError:
        pass
    return None


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _port_reachable(port: int, attempts: int = 1) -> bool:
    for i in range(attempts):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.0):
                return True
        except OSError:
            if i + 1 < attempts:
                time.sleep(0.05)
    return False


def _spawn_daemon(medium: str, endpoint: str, baud: int, info_path: str) -> int:
    """Spawn a DETACHED persistent bridge daemon and wait for it to announce its port.

    Detached (start_new_session=True, stdio to devnull) so it OUTLIVES this `probe` process. Invoked
    via `python -m espilon_probe.bridges` so a source checkout works; inherits the environment
    (PYTHONPATH) so a non-installed `espilon_probe` resolves in the child."""
    cmd = [sys.executable, "-m", "espilon_probe.bridges",
           "--medium", medium, "--endpoint", endpoint,
           "--listen", "127.0.0.1:0", "--baud", str(baud),
           "--announce", info_path, "--idle-timeout", str(_idle_timeout())]
    devnull = open(os.devnull, "wb")
    try:
        proc = subprocess.Popen(cmd, stdout=devnull, stderr=devnull,
                                stdin=subprocess.DEVNULL, start_new_session=True)
    finally:
        devnull.close()

    deadline = time.monotonic() + _SPAWN_READY_TIMEOUT
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(
                f"loopback {medium} bridge for {endpoint!r} exited before announcing "
                f"(code {proc.returncode})")
        port = _connect_existing(info_path)
        if port is not None:
            return port
        time.sleep(0.02)
    try:
        proc.terminate()                                 # unhealthy: best-effort teardown
    except Exception:
        pass
    raise RuntimeError(f"loopback {medium} bridge for {endpoint!r} did not announce a port in time")
