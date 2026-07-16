"""The guided wizard: the menu primitive, passive detection, the non-tty guards, and that the
wizard DRIVES the real protocol functions (not a reimplementation) while echoing the equivalent
CLI command.

No real tty and no hardware: the menu step is a pure function fed a scripted `io.StringIO`, and
the backend is a recording stub returned by a monkeypatched `cli._make_backend`. The BLE WRITE
path is exercised only against this in-process stub (never a real peripheral).
"""

import io
import shlex
import sys

import pytest

from espilon_probe import cli, config, wizard
from espilon_probe.core.backend import Capabilities


# --- the menu primitive `choose` (D14) ---------------------------------------------------------
def test_choose_returns_the_picked_tag():
    opts = [("a", "Apple"), ("b", "Banana")]
    assert wizard.choose("pick", opts, stdin=io.StringIO("2\n"), stdout=io.StringIO()) == "b"


def test_choose_reprompts_on_out_of_range():
    out = io.StringIO()
    tag = wizard.choose("pick", [("a", "A")], stdin=io.StringIO("9\n1\n"), stdout=out)
    assert tag == "a"
    assert "enter a number" in out.getvalue()


def test_choose_quit_back_rescan_tokens():
    io0 = io.StringIO
    assert wizard.choose("p", [("a", "A")], stdin=io0("0\n"), stdout=io0()) is wizard._QUIT
    assert wizard.choose("p", [("a", "A")], stdin=io0("b\n"), stdout=io0(),
                         allow_back=True) is wizard._BACK
    assert wizard.choose("p", [("a", "A")], stdin=io0("r\n"), stdout=io0(),
                         allow_rescan=True) is wizard._RESCAN


def test_choose_eof_raises_eoferror():
    with pytest.raises(EOFError):
        wizard.choose("p", [("a", "A")], stdin=io.StringIO(""), stdout=io.StringIO())


def test_choose_empty_line_takes_default():
    tag = wizard.choose("p", [("a", "A"), ("b", "B")], stdin=io.StringIO("\n"),
                        stdout=io.StringIO(), default=2)
    assert tag == "b"


def test_choose_keyboardinterrupt_propagates():
    class _KbStdin:
        def readline(self):
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        wizard.choose("p", [("a", "A")], stdin=_KbStdin(), stdout=io.StringIO())


# --- passive auto-detect (D8) ------------------------------------------------------------------
def test_virtual_is_always_offered(monkeypatch):
    monkeypatch.setattr(wizard.glob, "glob", lambda pat: [])
    monkeypatch.setattr(wizard.importlib.util, "find_spec", lambda name: None)
    assert [c.name for c in wizard.detect_backends({})] == ["virtual"]


def test_serial_detected_from_tty_glob(monkeypatch):
    def fake_glob(pat):
        return ["/dev/ttyUSB0"] if "ttyUSB" in pat else []
    monkeypatch.setattr(wizard.glob, "glob", fake_glob)
    monkeypatch.setattr(wizard.importlib.util, "find_spec", lambda name: None)
    names = [c.name for c in wizard.detect_backends({})]
    assert names == ["serial", "virtual"]


def test_socketcan_detected_from_arphrd_can(monkeypatch, tmp_path):
    typef = tmp_path / "net" / "vcan0" / "type"
    typef.parent.mkdir(parents=True)
    typef.write_text("280\n")

    def fake_glob(pat):
        return [str(typef)] if "net" in pat else []
    monkeypatch.setattr(wizard.glob, "glob", fake_glob)
    monkeypatch.setattr(wizard.importlib.util, "find_spec", lambda name: None)
    choices = wizard.detect_backends({})
    assert [c.name for c in choices] == ["socketcan", "virtual"]
    assert choices[0].devices == ["vcan0"]


def test_hci_needs_bleak_and_a_sysfs_adapter(monkeypatch):
    monkeypatch.setattr(wizard.glob, "glob",
                        lambda pat: ["/sys/class/bluetooth/hci0"] if "bluetooth" in pat else [])
    monkeypatch.setattr(wizard.importlib.util, "find_spec", lambda name: object())  # bleak present
    assert "hci" in [c.name for c in wizard.detect_backends({})]
    monkeypatch.setattr(wizard.importlib.util, "find_spec", lambda name: None)      # bleak absent
    assert "hci" not in [c.name for c in wizard.detect_backends({})]


# --- non-tty guards (D6) -----------------------------------------------------------------------
def test_bare_probe_non_tty_prints_help_and_never_blocks(monkeypatch, capsys):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False, raising=False)
    # No stdin data supplied: if it tried input() this would not return 0.
    assert cli.main([]) == 0
    out = capsys.readouterr().out
    assert "guided wizard" in out and "probe scan" in out


def test_wizard_subcommand_non_tty_is_a_clean_error(monkeypatch):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False, raising=False)
    with pytest.raises(SystemExit) as ei:
        cli.main(["wizard"])
    assert "interactive terminal" in str(ei.value)


# --- the wizard drives the REAL protocol code paths --------------------------------------------
class _RecordingBackend:
    """A stub Backend that records the ops the wizard drives (proves reuse, not reimplementation)."""

    def __init__(self, caps, scan_rows=None, enum=None):
        self._caps = caps
        self._scan_rows = scan_rows or []
        self._enum = enum or {"characteristics": []}
        self.scan_calls = 0
        self.reads = []
        self.writes = []
        self.opened = 0
        self.closed = 0

    def open(self):
        self.opened += 1

    def close(self):
        self.closed += 1

    def capabilities(self):
        return self._caps

    def scan(self, seconds=None, count=None):
        self.scan_calls += 1
        return list(self._scan_rows)

    def op(self, verb, **kw):
        if verb == "gatt.enum":
            return self._enum
        if verb == "gatt.read":
            self.reads.append(kw["handle"])
            return {"value": b"LOCKED".hex()}
        if verb == "gatt.write":
            self.writes.append((kw["handle"], kw["value"]))
            return {"ok": True}
        return {}


_BLE_CAPS = Capabilities(protocol="ble", transport="virtual", shape="transaction",
                         verbs=["scan", "gatt"], channels=[])
_BLE_ENUM = {"characteristics": [
    {"handle": 0x0011, "uuid": "fff1", "props": "read,notify"},
    {"handle": 0x0014, "uuid": "fff2", "props": "write"},
]}


def _drive(fake, script, monkeypatch):
    monkeypatch.setattr(wizard, "detect_backends",
                        lambda cfg: [wizard.BackendChoice("virtual", "Virtual lab target")])
    monkeypatch.setattr(cli, "_make_backend", lambda name, target, baud=115200: fake)
    out = io.StringIO()
    rc = wizard.run({}, stdin=io.StringIO(script), stdout=out)
    return rc, out.getvalue()


def test_wizard_ble_read_then_write_drives_the_gatt_functions(monkeypatch):
    fake = _RecordingBackend(_BLE_CAPS,
                             scan_rows=[{"name": "MOCK-DEV", "addr": "AA:BB", "rssi": -40}],
                             enum=_BLE_ENUM)
    # backend, endpoint, device, save?no, char1->read, char2->write 01, quit
    script = "\n".join(["1", "tcp://h:1", "1", "N", "1", "1", "2", "1", "01", "0"]) + "\n"
    rc, out = _drive(fake, script, monkeypatch)
    assert rc == 0
    assert fake.scan_calls >= 1                        # the wizard called the real scan()
    assert fake.reads == [0x0011]                      # ...and the real gatt.read on the picked char
    assert fake.writes == [(0x0014, "01")]             # ...and the real gatt.write
    assert "value: LOCKED" in out                      # rendered through cli._fmt_value
    assert "status (fff1)" in out and "command (fff2)" in out   # role-from-props labels


def test_wizard_echoes_the_equivalent_command_and_it_round_trips(monkeypatch):
    fake = _RecordingBackend(_BLE_CAPS,
                             scan_rows=[{"name": "MOCK-DEV", "addr": "AA:BB", "rssi": -40}],
                             enum=_BLE_ENUM)
    script = "\n".join(["1", "tcp://h:1", "1", "N", "1", "1", "0"]) + "\n"
    _, out = _drive(fake, script, monkeypatch)
    parser = cli.build_parser()
    echoes = [ln.strip() for ln in out.splitlines() if "# same as: probe " in ln]
    assert echoes, "the wizard must echo the equivalent command"
    for ln in echoes:
        argv = shlex.split(ln.split("# same as: probe ", 1)[1])
        parser.parse_args(argv)                        # must parse cleanly (echo != drift)
    assert any("gatt read 0x0011" in ln for ln in echoes)


def test_wizard_save_prompt_writes_only_on_yes(monkeypatch):
    fake = _RecordingBackend(_BLE_CAPS,
                             scan_rows=[{"name": "MOCK-DEV", "addr": "AA:BB"}], enum=_BLE_ENUM)
    # ...device, save?YES, then quit
    script = "\n".join(["1", "tcp://h:1", "1", "y", "0"]) + "\n"
    _drive(fake, script, monkeypatch)
    assert config.load() == {"backend": "virtual", "target": "tcp://h:1"}


def test_wizard_save_prompt_no_leaves_config_untouched(monkeypatch):
    fake = _RecordingBackend(_BLE_CAPS,
                             scan_rows=[{"name": "MOCK-DEV", "addr": "AA:BB"}], enum=_BLE_ENUM)
    script = "\n".join(["1", "tcp://h:1", "1", "N", "0"]) + "\n"
    _drive(fake, script, monkeypatch)
    assert config.load() == {}


def test_stream_shape_skips_the_scan_step(monkeypatch):
    caps = Capabilities(protocol="uart", transport="virtual", shape="stream",
                        verbs=["uart"], channels=[])
    fake = _RecordingBackend(caps)
    # backend, endpoint, save?no, then straight into UART actions -> quit
    script = "\n".join(["1", "tcp://h:1", "N", "0"]) + "\n"
    rc, out = _drive(fake, script, monkeypatch)
    assert rc == 0
    assert fake.scan_calls == 0                         # step (b) skipped for a stream backend
    assert "UART actions" in out                        # went straight to the stream action menu


def test_open_failure_returns_to_the_backend_menu(monkeypatch):
    # A backend whose open() fails must NOT crash the wizard: report + back to the menu, then quit.
    class _BadBackend(_RecordingBackend):
        def open(self):
            raise OSError("no such device")

    fake = _BadBackend(_BLE_CAPS)
    monkeypatch.setattr(wizard, "detect_backends",
                        lambda cfg: [wizard.BackendChoice("virtual", "Virtual lab target")])
    monkeypatch.setattr(cli, "_make_backend", lambda name, target, baud=115200: fake)
    out = io.StringIO()
    # pick backend, endpoint (open fails -> back to backend menu), then quit
    rc = wizard.run({}, stdin=io.StringIO("1\ntcp://h:1\n0\n"), stdout=out)
    assert rc == 0
    assert "cannot open" in out.getvalue()
