"""The REAL side, driven by the SHIPPED `probe --backend serial --target <pty>` client.

A pty is a real serial line from the OS point of view, so this is the "real medium" the corpus's
UART pilot uses to prove virtual==real with zero hardware (docs/design/04 section 4). Crucially this drives
the GENUINE shipped path - the runner runs `probe --backend serial --target /dev/pts/N` per verb,
which discovers/uses the persistent serial-bridge daemon - NOT `--backend virtual`. The only content
is the Console DEVICE on the pty master.

Bring-up ordering (so the boot banner is captured, docs/design/01 section 4): the persistent daemon must be
up and holding the slave open BEFORE the device boots, otherwise the banner is written to a line with
no reader and lost. `ConformanceRealSide` sequences it: point the client's rendezvous at an isolated
runtime dir, spawn the daemon and wait for its announce (slave now open), THEN boot the device. The
per-verb `probe --backend serial` invocations then DISCOVER this same daemon by target.
"""

from __future__ import annotations

import os
import select
import subprocess
import sys
import tempfile
import threading

from espilon_probe.backends.serial import _runtime_dir, _target_key

from .console import Console

_READY_PREFIX = "PROBE_BRIDGE_LISTENING"


class _PtyDevice:
    """Runs the Console on the pty master fd: emit an optional boot log, the banner, then echo +
    answer forever. `boot_log` stands in for a real board's mask-ROM boot chatter (e.g. the classic
    ESP32 `rst:0x.. ets ..` log) so the drop-to-banner path can be exercised on a pty in CI."""

    def __init__(self, master_fd: int, console: Console, boot_log: bytes = b""):
        self.master_fd = master_fd
        self.console = console
        self.boot_log = boot_log
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._set_raw()
        if self.boot_log:
            os.write(self.master_fd, self.boot_log)         # mask-ROM boot chatter before firmware
        os.write(self.master_fd, self.console.banner())     # boot banner (daemon slave already open)
        self._thread = threading.Thread(target=self._loop, name="pty-console-device", daemon=True)
        self._thread.start()

    def _set_raw(self) -> None:
        try:
            import termios
            import tty
            tty.setraw(self.master_fd, termios.TCSANOW)      # no cooked echo/CRLF; do not flush RX
        except Exception:
            pass

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                ready, _, _ = select.select([self.master_fd], [], [], 0.05)
            except (OSError, ValueError):
                break
            if not ready:
                continue
            try:
                data = os.read(self.master_fd, 4096)
            except OSError:
                break
            if not data:
                break
            out = self.console.feed(data)
            if out:
                try:
                    os.write(self.master_fd, out)
                except OSError:
                    break

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=0.5)


class ConformanceRealSide:
    """The real side: a persistent serial-bridge daemon over a pty, with the Console device on the
    master, driven by `probe --backend serial --target <slave_path>`. `target` is the pty slave path
    (NOT a tcp:// URL): the runner passes `--backend serial`."""

    backend = "serial"

    def __init__(self, console: Console | None = None, boot_log: bytes = b"",
                 reset_on_open: bool = False):
        self.console = console or Console()
        self.boot_log = boot_log
        self.reset_on_open = reset_on_open
        self._master_fd: int | None = None
        self._proc: subprocess.Popen | None = None
        self._device: _PtyDevice | None = None
        self._runtime: str | None = None
        self._info_path: str | None = None
        self.slave_path: str | None = None

    @property
    def target(self) -> str:
        assert self.slave_path is not None
        return self.slave_path

    @property
    def env(self) -> dict:
        """Environment the runner must pass to `probe` so it discovers THIS daemon (isolated
        rendezvous dir + a short idle lifetime so nothing leaks)."""
        e = dict(os.environ)
        e["ESPILON_PROBE_RUNTIME"] = self._runtime or ""
        e["ESPILON_PROBE_BRIDGE_IDLE"] = "30"
        return e

    def start(self) -> str:
        import pty
        # Isolated rendezvous dir so this harness never collides with a real user daemon or a
        # parallel test. The client (in-process helpers) and the probe subprocesses both read it.
        self._runtime = tempfile.mkdtemp(prefix="espilon-probe-conf-")
        os.environ["ESPILON_PROBE_RUNTIME"] = self._runtime
        os.environ["ESPILON_PROBE_BRIDGE_IDLE"] = "30"

        master, slave = pty.openpty()
        self.slave_path = os.ttyname(slave)
        self._master_fd = master
        self._info_path = os.path.join(_runtime_dir(),
                                       f"{_target_key('serial', self.slave_path)}.json")

        # Spawn the persistent daemon ourselves (so we own its lifetime for teardown), announcing to
        # the SAME rendezvous file the `probe --backend serial` client will look up by target.
        cmd = [sys.executable, "-m", "espilon_probe.bridges",
               "--medium", "serial", "--endpoint", self.slave_path, "--listen", "127.0.0.1:0",
               "--announce", self._info_path, "--idle-timeout", "30"]
        if self.reset_on_open:
            cmd.append("--reset-on-open")            # harmless no-op on a pty; exercises the path
        self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        os.close(slave)                              # the daemon holds its own fd on the path
        self._await_ready()
        # Daemon slave is open now -> boot the device (banner will be captured into the RX FIFO).
        self._device = _PtyDevice(master, self.console, boot_log=self.boot_log)
        self._device.start()
        return self.slave_path

    def _await_ready(self) -> None:
        assert self._proc is not None and self._proc.stdout is not None
        line = self._proc.stdout.readline()
        if not line:
            err = self._proc.stderr.read() if self._proc.stderr else ""
            raise RuntimeError(f"serial bridge daemon did not start: {err.strip()}")
        if not line.strip().startswith(_READY_PREFIX):
            raise RuntimeError(f"unexpected bridge output: {line.strip()!r}")

    def stop(self) -> None:
        if self._device is not None:
            self._device.stop()
        if self._proc is not None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=2)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            for stream in (self._proc.stdout, self._proc.stderr):
                try:
                    if stream:
                        stream.close()
                except Exception:
                    pass
        if self._master_fd is not None:
            try:
                os.close(self._master_fd)
            except OSError:
                pass
            self._master_fd = None
        if self._info_path:
            try:
                os.unlink(self._info_path)
            except OSError:
                pass

    def __enter__(self) -> "ConformanceRealSide":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()


class RealDeviceSide:
    """The real side against ACTUAL hardware (docs conformance/hardware/uart-console-esp32/).

    Unlike `ConformanceRealSide`, there is NO pty and NO device thread: the device is a real board on
    `endpoint` (e.g. /dev/ttyUSB0). We bring up the persistent serial-bridge daemon on that port with
    `--reset-on-open` (which toggles DTR/RTS to reboot the board so its boot-only banner is captured),
    announce to the SAME rendezvous file the `probe --backend serial --target <endpoint>` client will
    look up, then the runner drives the tape through the shipped client. `--baud` is honoured so the
    baud-garble check can open the line at a WRONG rate.

    Isolated rendezvous so the harness owns the daemon's lifetime (killed on teardown)."""

    backend = "serial"

    def __init__(self, endpoint: str, baud: int = 115200, reset_on_open: bool = True):
        self.endpoint = endpoint
        self.baud = baud
        self.reset_on_open = reset_on_open
        self._proc: subprocess.Popen | None = None
        self._runtime: str | None = None
        self._info_path: str | None = None

    @property
    def target(self) -> str:
        return self.endpoint

    @property
    def env(self) -> dict:
        e = dict(os.environ)
        e["ESPILON_PROBE_RUNTIME"] = self._runtime or ""
        e["ESPILON_PROBE_BRIDGE_IDLE"] = "60"
        return e

    def start(self) -> str:
        self._runtime = tempfile.mkdtemp(prefix="espilon-probe-real-")
        os.environ["ESPILON_PROBE_RUNTIME"] = self._runtime
        os.environ["ESPILON_PROBE_BRIDGE_IDLE"] = "60"
        self._info_path = os.path.join(_runtime_dir(),
                                       f"{_target_key('serial', self.endpoint)}.json")
        cmd = [sys.executable, "-m", "espilon_probe.bridges",
               "--medium", "serial", "--endpoint", self.endpoint,
               "--listen", "127.0.0.1:0", "--baud", str(self.baud),
               "--announce", self._info_path, "--idle-timeout", "60"]
        if self.reset_on_open:
            cmd.append("--reset-on-open")
        self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        line = self._proc.stdout.readline() if self._proc.stdout else ""
        if not line.strip().startswith(_READY_PREFIX):
            err = self._proc.stderr.read() if self._proc.stderr else ""
            raise RuntimeError(f"serial bridge for {self.endpoint!r} did not start: "
                               f"{line.strip()!r} {err.strip()}")
        # The reset (on open) has rebooted the board; give the boot log + banner a moment to land in
        # the daemon RX FIFO before the first read.
        import time
        time.sleep(0.5)
        return self.endpoint

    def stop(self) -> None:
        if self._proc is not None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=2)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            for stream in (self._proc.stdout, self._proc.stderr):
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

    def __enter__(self) -> "RealDeviceSide":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()
