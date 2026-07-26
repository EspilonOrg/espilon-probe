"""The guided, numbered-menu wizard (`probe wizard`, or bare `probe` on a tty) - stdlib only.

A newbie front-end over the real CLI. It holds NO protocol logic: it drives the identical code
paths the verbs use (`cli._make_backend` + `open()`, `backend.scan`, `ble.gatt_enum/read/write`,
`can.send`, `backend.sniff`, `console.run_console`, `jtag`/`spi` `scan_rows`) and renders through
the same helpers (`cli._fmt_value`, `ble.att_error`, `cli._report_write`). Every action ALSO
prints the equivalent real command (`# same as: probe ...`) so the wizard teaches the CLI it
front-ends and the user can graduate off the menus.

Mechanism (D12): print options, read a line, dispatch on the number. That is the whole loop -
no curses, no readline, no third-party dependency (`glob` / `importlib.util` / `input`/`print`
only). Auto-detect is PASSIVE (D8): it inspects local sysfs / a `find_spec`, never spawns a
daemon, powers a radio, or touches the wire.

Config is written only on an explicit `y` to the save prompt (D11) - never silently.
"""

from __future__ import annotations

import glob
import importlib.util
import sys
from dataclasses import dataclass, field

from . import config

# Menu control tokens returned by `choose`.
_QUIT = "\x00quit"
_BACK = "\x00back"
_RESCAN = "\x00rescan"

# A SMALL, GENERIC BLE-SIG 16-bit assigned-numbers table (public standard, NOT device/challenge
# content). Used only to put a friendly label on a characteristic; missing -> role/uuid-tail.
_BLE_SIG_16 = {
    0x2A00: "Device Name",
    0x2A01: "Appearance",
    0x2A04: "Conn Params",
    0x2A05: "Service Changed",
    0x2A19: "Battery Level",
    0x2A23: "System ID",
    0x2A24: "Model Number",
    0x2A25: "Serial Number",
    0x2A26: "Firmware Revision",
    0x2A27: "Hardware Revision",
    0x2A28: "Software Revision",
    0x2A29: "Manufacturer Name",
    0x2A2A: "IEEE Reg Cert",
    0x2A50: "PnP ID",
    0x2AA6: "Central Address Resolution",
}
# The Bluetooth SIG base UUID: a 128-bit uuid of the form 0000XXXX-0000-1000-8000-00805f9b34fb
# carries the 16-bit assigned number XXXX. Anything else has no 16-bit form.
_BLE_BASE_SUFFIX = "0000100080000805f9b34fb"


@dataclass
class BackendChoice:
    """A viable backend the wizard offers, with how it maps a scan to a connect target."""

    name: str                       # cli backend name (virtual/hci/serial/socketcan)
    label: str                      # friendly menu label
    detail: str = ""                # short annotation ("1 adapter found", "always available")
    devices: list = field(default_factory=list)   # concrete transport candidates (tty/iface)
    # True when a scanned device's address becomes the connect target (hci: scan is target-less,
    # gatt connects to the picked peripheral). False when the transport IS the target.
    uses_scan_target: bool = False


# --------------------------------------------------------------------------------------------
# Passive auto-detect (D8): cheap, side-effect-free, local-host-only. No subprocess, no bleak
# import, no radio power, no wire.
# --------------------------------------------------------------------------------------------
def _serial_devices() -> list:
    return sorted(glob.glob("/dev/ttyUSB*") + glob.glob("/dev/ttyACM*"))


def _can_interfaces() -> list:
    ifaces = []
    for type_path in sorted(glob.glob("/sys/class/net/*/type")):
        try:
            with open(type_path, encoding="utf-8") as fh:
                if fh.read().strip() == "280":          # ARPHRD_CAN
                    ifaces.append(type_path.split("/")[-2])
        except OSError:
            continue
    return ifaces


def _hci_present() -> bool:
    # bleak availability is a `find_spec` (no import, so the client core stays stdlib-only), AND a
    # BlueZ adapter must exist in sysfs. Either missing -> hci is not offered.
    try:
        have_bleak = importlib.util.find_spec("bleak") is not None
    except (ImportError, ValueError):
        have_bleak = False
    return have_bleak and bool(glob.glob("/sys/class/bluetooth/hci*"))


def detect_backends(cfg: dict) -> list:
    """The viable backends, most-specific first, virtual always last (the escape hatch)."""
    out: list = []
    if _hci_present():
        out.append(BackendChoice("hci", "Bluetooth LE (hci)",
                                  detail="adapter found", uses_scan_target=True))
    serial = _serial_devices()
    if serial:
        out.append(BackendChoice("serial", "Serial / UART", devices=serial))
    can = _can_interfaces()
    if can:
        out.append(BackendChoice("socketcan", "CAN bus (socketcan)", devices=can))
    out.append(BackendChoice("virtual", "Virtual lab target", detail="always available"))
    return out


# --------------------------------------------------------------------------------------------
# BLE characteristic labelling (D7c): generic BLE-SIG name -> role-from-props -> short uuid tail.
# --------------------------------------------------------------------------------------------
def _uuid16(uuid: str) -> int | None:
    u = str(uuid).replace("-", "").lower()
    if len(u) == 4:
        try:
            return int(u, 16)
        except ValueError:
            return None
    if len(u) == 32 and u[8:] == _BLE_BASE_SUFFIX:
        try:
            return int(u[4:8], 16)
        except ValueError:
            return None
    return None


def _role_from_props(props: str) -> str:
    p = props.lower()
    if "write" in p and "read" not in p:
        return "command"
    if "notify" in p or "indicate" in p:
        return "status"
    if "read" in p:
        return "value"
    return ""


def char_label(char: dict) -> str:
    """A readable label for a characteristic: BLE-SIG name, else role+tail, else the uuid tail."""
    uuid = str(char.get("uuid", "")).lower()
    tail = uuid.replace("-", "")[-4:] if uuid else "?"
    num = _uuid16(uuid)
    if num is not None and num in _BLE_SIG_16:
        return _BLE_SIG_16[num]
    role = _role_from_props(str(char.get("props", "")))
    if role:
        return f"{role} ({tail})"
    return tail


# --------------------------------------------------------------------------------------------
# The menu primitive (D14): a pure function so tests feed a scripted stdin and assert the pick.
# --------------------------------------------------------------------------------------------
def choose(prompt, options, *, stdin, stdout, allow_back=False, allow_rescan=False, default=None):
    """Print a numbered menu and return the picked option TAG, or a control token.

    `options` is a list of `(tag, label)`. Returns `tag`, or `_QUIT`/`_BACK`/`_RESCAN`. An
    out-of-range or garbage line reprompts. An empty line uses `default` (a 1-based index) when
    given. Raises EOFError on a closed stdin (Ctrl-D); a KeyboardInterrupt from the read
    propagates to the caller (the wizard maps it to cancel/exit).
    """
    while True:
        print(prompt, file=stdout)
        for i, (_, label) in enumerate(options, 1):
            marker = " [default]" if default == i else ""
            print(f"  {i}) {label}{marker}", file=stdout)
        controls = []
        if allow_back:
            controls.append("b) back")
        if allow_rescan:
            controls.append("r) rescan")
        controls.append("0) quit")
        print("  " + "   ".join(controls), file=stdout)
        stdout.write("> ")
        stdout.flush()
        line = stdin.readline()
        if line == "":
            raise EOFError
        choice = line.strip().lower()
        if choice == "" and default is not None:
            choice = str(default)
        if choice in ("0", "q", "quit"):
            return _QUIT
        if allow_back and choice == "b":
            return _BACK
        if allow_rescan and choice == "r":
            return _RESCAN
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(options):
                return options[idx - 1][0]
        print(f"  ? enter a number 1-{len(options)} (or 0 to quit)", file=stdout)


class _BackSignal(Exception):
    """Internal: the user chose `b) back` inside a session - unwind to the backend menu."""


class _QuitSignal(Exception):
    """Internal: the user chose `0) quit` anywhere - unwind cleanly to a 0 exit."""


class Wizard:
    """The REPL. One instance per invocation; `run()` returns the process exit code."""

    def __init__(self, cfg: dict, stdin=None, stdout=None):
        self.cfg = cfg or {}
        self.stdin = stdin if stdin is not None else sys.stdin
        self.stdout = stdout if stdout is not None else sys.stdout
        self.baud = self.cfg.get("baud", 115200)

    # -- small IO helpers ---------------------------------------------------------------------
    def say(self, *parts) -> None:
        print(*parts, file=self.stdout)

    def ask(self, prompt: str, default: str | None = None) -> str:
        hint = f" [{default}]" if default else ""
        self.stdout.write(f"{prompt}{hint}: ")
        self.stdout.flush()
        line = self.stdin.readline()
        if line == "":
            raise EOFError
        val = line.strip()
        return val if val else (default or "")

    def _teach(self, argv: list) -> None:
        """Echo the equivalent real command so the wizard teaches the CLI (D10)."""
        import shlex
        self.say("  # same as: probe " + " ".join(shlex.quote(a) for a in argv))

    # -- top level ----------------------------------------------------------------------------
    def run(self) -> int:
        self.say("probe wizard - a guided start. Pick by number; 0 quits, b goes back.")
        try:
            return self._run()
        except _QuitSignal:
            return 0
        except KeyboardInterrupt:
            self.say("")
            return 130
        except EOFError:
            self.say("")
            return 0

    def _run(self) -> int:
        detected = detect_backends(self.cfg)
        while True:
            picked = self._menu_backend(detected)
            if picked is _QUIT:
                return 0
            if picked is _RESCAN:
                detected = detect_backends(self.cfg)
                continue
            try:
                self._session(picked)
            except _BackSignal:
                continue
            except KeyboardInterrupt:
                # Ctrl-C inside a session cancels back to the backend menu, not the whole tool.
                self.say("\n(cancelled)")
                continue

    def _menu_backend(self, detected):
        options = []
        default_idx = None
        want = self.cfg.get("backend")
        for i, ch in enumerate(detected, 1):
            extra = ch.detail
            if ch.devices:
                extra = ", ".join(ch.devices[:3]) + (" ..." if len(ch.devices) > 3 else "")
            options.append((ch, f"{ch.label:<24} {('- ' + extra) if extra else ''}".rstrip()))
            if want and ch.name == want and default_idx is None:
                default_idx = i
        return choose("Where do you want to probe?", options,
                      stdin=self.stdin, stdout=self.stdout,
                      allow_rescan=True, default=default_idx)

    # -- one backend session ------------------------------------------------------------------
    def _session(self, choice: BackendChoice) -> None:
        from . import cli
        transport = self._resolve_transport(choice)
        # Scan phase (packet/transaction). For hci the scan runs against a target-less daemon and
        # the picked peripheral becomes the connect target; for others the transport IS the target.
        connect_target = transport
        scan_backend = cli._make_backend(choice.name, transport, baud=self.baud)
        try:
            scan_backend.open()
        except Exception as e:                                  # noqa: BLE001 - report + menu
            self.say(f"  cannot open {choice.label}: {e}")
            raise _BackSignal
        try:
            caps = scan_backend.capabilities()
            if caps.shape in ("packet", "transaction"):
                device = self._scan_and_pick(scan_backend, caps, choice)
                if device is not None and choice.uses_scan_target:
                    connect_target = device.get("name") or device.get("addr") or transport
        finally:
            scan_backend.close()

        self._offer_save(choice.name, connect_target)

        # Action phase: ONE backend, opened with the resolved connect target and reused across
        # every read/write (this is what preserves the hci held-connection unlock state).
        action_backend = cli._make_backend(choice.name, connect_target, baud=self.baud)
        try:
            action_backend.open()
        except Exception as e:                                  # noqa: BLE001 - report + menu
            self.say(f"  cannot open {choice.label}: {e}")
            raise _BackSignal
        try:
            self._actions(action_backend, action_backend.capabilities(), choice, connect_target)
        finally:
            action_backend.close()

    def _resolve_transport(self, choice: BackendChoice):
        if choice.name == "virtual":
            import os
            default = self.cfg.get("target") or os.environ.get("ESP_PROBE") or "tcp://127.0.0.1:9000"
            return self.ask("Virtual target endpoint (tcp://host:port)", default=default)
        if choice.name == "hci":
            return None                     # scan is target-less; the peripheral is picked below
        if choice.devices:
            if len(choice.devices) == 1:
                return choice.devices[0]
            opts = [(d, d) for d in choice.devices]
            picked = choose(f"Which {choice.label}?", opts, stdin=self.stdin, stdout=self.stdout,
                            allow_back=True)
            if picked is _BACK:
                raise _BackSignal
            if picked is _QUIT:
                raise _QuitSignal
            return picked
        return None

    # -- scan + device pick (D7b) -------------------------------------------------------------
    def _scan_and_pick(self, backend, caps, choice: BackendChoice):
        from . import cli
        while True:
            rows = self._scan_rows(backend, caps)
            if not rows:
                self.say("  (nothing on the protocol)")
                return None
            options = []
            for row in rows:
                name = row.get("name") or "(unnamed)"
                addr = row.get("addr", "")
                rssi = row.get("rssi")
                extra = f"  {addr}" + (f"  rssi {rssi}" if rssi is not None else "")
                options.append((row, f"{name}{extra}".rstrip()))
            self._teach(self._scan_argv(choice))
            picked = choose(f"Devices on {caps.protocol}:", options,
                            stdin=self.stdin, stdout=self.stdout,
                            allow_back=True, allow_rescan=True)
            if picked is _RESCAN:
                continue
            if picked is _BACK:
                raise _BackSignal
            if picked is _QUIT:
                raise _QuitSignal
            return picked

    def _scan_rows(self, backend, caps):
        from . import cli
        proto = caps.protocol
        if proto == "jtag":
            from .protocols import jtag
            return jtag.scan_rows(backend)
        if proto == "spi":
            from .protocols import spi
            return spi.scan_rows(backend)
        secs = cli._scan_seconds(_ScanArgs(), self.cfg)
        return cli._scan_rows(backend.scan(seconds=secs, count=None))

    def _scan_argv(self, choice: BackendChoice) -> list:
        argv = ["--backend", choice.name]
        argv += ["scan"]
        return argv

    # -- caps-driven action menus (D7c) -------------------------------------------------------
    def _actions(self, backend, caps, choice: BackendChoice, target) -> None:
        proto = caps.protocol
        if proto == "ble" and "gatt" in caps.verbs:
            return self._ble_actions(backend, caps, choice, target)
        if proto == "can":
            return self._can_actions(backend, caps, choice, target)
        if caps.shape == "stream" and "uart" in caps.verbs:
            return self._stream_actions(backend, caps, choice, target)
        if caps.shape == "transaction":
            return self._bus_actions(backend, caps, choice, target)
        self.say("  (no guided actions for this protocol yet - use a verb directly)")

    def _base_argv(self, choice: BackendChoice, target) -> list:
        argv = ["--backend", choice.name]
        if target:
            argv += ["--target", str(target)]
        return argv

    # BLE ------------------------------------------------------------------------------------
    def _ble_actions(self, backend, caps, choice, target) -> None:
        from . import cli
        from .protocols import ble
        while True:
            chars = [c for c in (ble.gatt_enum(backend).get("characteristics") or [])
                     if isinstance(c, dict)]
            if not chars:
                self.say("  (no characteristics)")
                return
            options = []
            for c in chars:
                from .core.fields import as_int
                handle = as_int(c.get("handle", 0), "gatt handle")
                label = char_label(c)
                props = c.get("props", "")
                options.append((c, f"{label:<22} [{props}]  handle 0x{handle:04x}"))
            picked = choose(f"Characteristics on {target or caps.protocol}:", options,
                            stdin=self.stdin, stdout=self.stdout, allow_back=True, allow_rescan=True)
            if picked is _RESCAN:
                continue
            if picked is _BACK:
                raise _BackSignal
            if picked is _QUIT:
                raise _QuitSignal
            self._ble_char_action(backend, choice, target, picked)

    def _ble_char_action(self, backend, choice, target, char) -> None:
        from . import cli
        from .core.fields import as_int
        from .protocols import ble
        handle = as_int(char.get("handle", 0), "gatt handle")
        props = str(char.get("props", "")).lower()
        acts = []
        if "read" in props:
            acts.append(("read", "read this characteristic"))
        if "write" in props:
            acts.append(("write", "write this characteristic"))
        if not acts:
            self.say(f"  {char_label(char)} advertises no read/write ({props})")
            return
        picked = choose(f"{char_label(char)} 0x{handle:04x}:", acts,
                        stdin=self.stdin, stdout=self.stdout, allow_back=True)
        if picked is _QUIT:
            raise _QuitSignal
        if picked is _BACK:
            return
        if picked == "read":
            self.say(f"Reading {char_label(char)}...")
            self._teach(self._base_argv(choice, target) + ["gatt", "read", f"0x{handle:04x}"])
            res = ble.gatt_read(backend, handle)
            err = ble.att_error(res)
            if err is not None:
                self.say(f"  {err}")
                return
            if not isinstance(res, dict) or "value" not in res:
                self.say(f"  no such handle 0x{handle:04x} (handle not readable)")
                return
            self.say("  value: " + cli._fmt_value(res.get("value", ""), "gatt.read value"))
        elif picked == "write":
            value = self.ask("Hex value to write (e.g. 01)")
            if not value:
                self.say("  (nothing to write)")
                return
            self._teach(self._base_argv(choice, target) + ["gatt", "write", f"0x{handle:04x}", value])
            try:
                res = ble.gatt_write(backend, handle, value)
            except Exception as e:                             # noqa: BLE001
                self.say(f"  {e}")
                return
            err = ble.att_error(res)
            if err is not None:
                self.say(f"  {err}")
                return
            try:
                cli._report_write(res, "write")
            except cli.ProbeError as e:
                self.say(f"  {e}")

    # CAN ------------------------------------------------------------------------------------
    def _can_actions(self, backend, caps, choice, target) -> None:
        from . import cli
        from .protocols import can
        while True:
            acts = []
            if "sniff" in caps.verbs:
                acts.append(("dump", "capture CAN frames to a pcap"))
            if "inject" in caps.verbs:
                acts.append(("send", "send a CAN frame"))
            if not acts:
                self.say("  (no CAN actions advertised)")
                return
            picked = choose("CAN actions:", acts, stdin=self.stdin, stdout=self.stdout,
                            allow_back=True)
            if picked is _QUIT:
                raise _QuitSignal
            if picked is _BACK:
                return
            if picked == "dump":
                path = self.ask("Write pcap to", default="can.pcap")
                secs = self.ask("Capture seconds", default="3")
                self._teach(self._base_argv(choice, target) + ["can", "dump", "-w", path, "-t", secs])
                try:
                    n = backend.sniff(path, seconds=float(secs))
                    self.say(f"  captured {n} frame(s) -> {path}")
                except Exception as e:                         # noqa: BLE001
                    self.say(f"  {e}")
            elif picked == "send":
                can_id = self.ask("Arbitration id (e.g. 0x7DF)")
                data = self.ask("Hex payload (e.g. 0201)")
                self._teach(self._base_argv(choice, target) + ["can", "send", can_id, data])
                try:
                    can.send(backend, cli._parse_int(can_id, "arbitration id"), data)
                    self.say("  sent")
                except Exception as e:                         # noqa: BLE001
                    self.say(f"  {e}")

    # stream (uart) --------------------------------------------------------------------------
    def _stream_actions(self, backend, caps, choice, target) -> None:
        from . import cli
        from .core import console
        from .protocols import uart
        while True:
            acts = [("console", "interactive terminal (detach: Ctrl-])"),
                    ("send", "one-shot send-then-read")]
            picked = choose("UART actions:", acts, stdin=self.stdin, stdout=self.stdout,
                            allow_back=True)
            if picked is _QUIT:
                raise _QuitSignal
            if picked is _BACK:
                return
            if picked == "console":
                self._teach(self._base_argv(choice, target) + ["uart", "console"])
                if not sys.stdin.isatty():
                    self.say("  console needs an interactive terminal")
                    continue
                banner = f"[probe] attached to {target or 'target'} (uart, {self.baud} baud) - escape: Ctrl-]"
                channel = backend.stream_open("duplex")
                console.run_console(channel, local_echo=False, eol="cr", attach_banner=banner)
            elif picked == "send":
                text = self.ask("Text to send")
                self._teach(self._base_argv(choice, target) + ["uart", "send", text])
                try:
                    resp = uart.send(backend, text.encode() + b"\r")
                    self.say("  " + resp.decode(errors="replace"))
                except Exception as e:                         # noqa: BLE001
                    self.say(f"  {e}")

    # transaction bus (jtag/spi) -------------------------------------------------------------
    def _bus_actions(self, backend, caps, choice, target) -> None:
        from . import cli
        proto = caps.protocol
        while True:
            acts = [("id", "read the device/chain id"),
                    ("read", "read memory/flash"),
                    ("dump", "dump a range to a file")]
            picked = choose(f"{proto} actions:", acts, stdin=self.stdin, stdout=self.stdout,
                            allow_back=True)
            if picked is _QUIT:
                raise _QuitSignal
            if picked is _BACK:
                return
            if picked == "id":
                verb = "scan-chain" if proto == "jtag" else "id"
                self._teach(self._base_argv(choice, target) + [proto, verb])
                for row in self._scan_rows(backend, caps):
                    self.say(f"  {row.get('name', '')}  {row.get('addr', '')}".rstrip())
            elif picked == "read":
                addr = self.ask("Address (hex or int)", default="0x0")
                length = self.ask("Length in bytes", default="16")
                self._bus_read(backend, proto, choice, target, addr, length)
            elif picked == "dump":
                addr = self.ask("Start address (hex or int)", default="0x0")
                length = self.ask("Length in bytes", default="256")
                path = self.ask("Write binary to", default=f"{proto}.bin")
                self._bus_dump(backend, proto, choice, target, addr, length, path)

    def _bus_read(self, backend, proto, choice, target, addr, length) -> None:
        from . import cli
        try:
            a = cli._parse_int(addr, "address")
            if proto == "jtag":
                from .protocols import jtag
                words = max(1, cli._parse_int(length, "length") // 4)
                self._teach(self._base_argv(choice, target) + ["jtag", "read", "--addr", addr,
                                                               "--words", str(words)])
                for i, w in enumerate(jtag.read_words(backend, a, count=words)):
                    self.say(f"  0x{a + i * 4:08x}: 0x{w:08x}")
            else:
                from .protocols import spi
                n = cli._parse_int(length, "length")
                self._teach(self._base_argv(choice, target) + ["spi", "read", "--addr", addr,
                                                               "--len", length])
                self.say("  " + cli._fmt_value(spi.read(backend, a, n).get("data", ""), "spi.read data"))
        except Exception as e:                                 # noqa: BLE001
            self.say(f"  {e}")

    def _bus_dump(self, backend, proto, choice, target, addr, length, path) -> None:
        from . import cli
        try:
            a = cli._parse_int(addr, "address")
            n = cli._parse_int(length, "length")
            if proto == "jtag":
                from .protocols import jtag
                self._teach(self._base_argv(choice, target) + ["jtag", "dump", "--addr", addr,
                                                               "--len", length, "-w", path])
                count = jtag.dump(backend, a, n, path)
            else:
                from .protocols import spi
                self._teach(self._base_argv(choice, target) + ["spi", "dump", "--addr", addr,
                                                               "--len", length, "-w", path])
                count = spi.dump(backend, n, path, addr=a)
            self.say(f"  dumped {count} byte(s) -> {path}")
        except Exception as e:                                 # noqa: BLE001
            self.say(f"  {e}")

    # -- config save (D11) --------------------------------------------------------------------
    def _offer_save(self, name, target) -> None:
        detail = name + (f" + {target}" if target else "")
        try:
            ans = self.ask(f"Save {detail} as your defaults so 'probe scan' just works? [y/N]",
                           default="N")
        except EOFError:
            return
        if ans.strip().lower() in ("y", "yes"):
            updates = {"backend": name}
            if target:
                updates["target"] = str(target)
            config.save(updates)
            self.say(f"  saved to {config.config_path()}")


@dataclass
class _ScanArgs:
    """A tiny stand-in so the wizard can reuse `cli._scan_seconds` (flag layer = None here)."""

    seconds: float | None = None
    count: int | None = None


def run(cfg: dict, stdin=None, stdout=None) -> int:
    """Entry point used by `cli.main` (bare `probe` on a tty, or `probe wizard`)."""
    return Wizard(cfg, stdin=stdin, stdout=stdout).run()
