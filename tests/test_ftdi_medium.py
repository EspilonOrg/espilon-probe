"""Hardware-free unit tests for the real ftdi SPI medium (bridges/media/ftdi.py).

These never touch an FT232H and never require `pyftdi` to be installed: a FAKE `pyftdi.spi` module
is injected into `sys.modules` so `SpiFtdiMedium.open()`'s lazy `from pyftdi.spi import SpiController`
picks it up. That lets the whole read-path op surface be proven against a MOCK, with the EXACT MPSSE
command bytes the medium clocks out asserted, per the spec's test strategy
(docs/design/real-bus-backends.md section 8) and the pilot rule that the suite stays green with no
silicon.

Three layers:
  - the pure helper `_jedec_meta` is tested directly (no pyftdi);
  - the op/scan/caps surface is driven against a fake SpiController, asserting `port.exchange`'s exact
    (out_bytes, readlen) and the result-dict shapes the protocol module requires;
  - the capability gate (convention C1) is proven END TO END over the real client + the real
    `_serve_op` bridge against the fake controller: an unadvertised bus (`jtag`), the relay verbs, and
    the wrong-op refusals all exit clean, and `spi id`/`spi read`/`scan` round-trip real result bytes.

On-hardware smoke (a real ESP32 flash dump over a SOIC-8 clip on an FT232H) is DEFERRED to an adapter
and is not run here; no real-silicon claim is made by this file.
"""

import socket
import sys
import threading
import types

import pytest

from espilon_probe import cli
from espilon_probe.backends.virtual import VirtualBackend
from espilon_probe.bridges.media import ftdi
from espilon_probe.bridges.server import BridgeServer
from espilon_probe.core import wire

# A deterministic backing flash for the fake adapter: a Winbond W25Q32 (JEDEC 0xEF4016) plus 4 KiB of
# reproducible content, so a read returns known bytes and the JEDEC name table is exercised.
_FAKE_ID = bytes([0xEF, 0x40, 0x16])
_FAKE_FLASH = bytes((i * 7) & 0xFF for i in range(0x20000))     # 128 KiB, covers a 3-octet address


# --- fake pyftdi ----------------------------------------------------------------------------------

class _FakePort:
    def __init__(self, cs, freq, mode):
        self.cs, self.freq, self.mode = cs, freq, mode
        self.exchanges = []      # (out_bytes, readlen) for every exchange, the MPSSE oracle
        self.freqs = []          # set_frequency() calls
        self.short = False       # when True, return one byte fewer than asked (short-read repro)

    def exchange(self, out, readlen=0, start=True, stop=True, duplex=False):
        out = bytes(out)
        self.exchanges.append((out, readlen))
        if out[:1] == b"\x9f":                       # RDID
            data = _FAKE_ID[:readlen]
        elif out and out[0] == 0x03:                 # READ + 24-bit addr
            addr = int.from_bytes(out[1:4], "big")
            data = _FAKE_FLASH[addr:addr + readlen]
        else:
            data = b"\x00" * readlen
        return data[:-1] if self.short and data else data

    def set_frequency(self, freq):
        self.freqs.append(freq)


class _FakeFtdi:
    is_connected = True


class _FakeSpiController:
    instances = []

    def __init__(self):
        self.configured = None
        self.ports = {}
        self.terminated = False
        self.ftdi = _FakeFtdi()
        _FakeSpiController.instances.append(self)

    def configure(self, url):
        self.configured = url

    def get_port(self, cs=0, freq=None, mode=0):
        p = self.ports.get(cs)
        if p is None:
            p = _FakePort(cs, freq, mode)
            self.ports[cs] = p
        return p

    def terminate(self):
        self.terminated = True


@pytest.fixture
def fake_pyftdi(monkeypatch):
    """Inject a fake `pyftdi.spi` so the medium's lazy import resolves with no adapter or pip dep."""
    pkg = types.ModuleType("pyftdi")
    spimod = types.ModuleType("pyftdi.spi")
    spimod.SpiController = _FakeSpiController
    pkg.spi = spimod
    monkeypatch.setitem(sys.modules, "pyftdi", pkg)
    monkeypatch.setitem(sys.modules, "pyftdi.spi", spimod)
    _FakeSpiController.instances = []
    yield


def _open(endpoint=None):
    m = ftdi.SpiFtdiMedium(endpoint)
    m.open()
    return m


# --- pure helper (no pyftdi) ----------------------------------------------------------------------

def test_jedec_meta_known_part_and_manufacturer():
    meta = ftdi._jedec_meta(bytes([0xEF, 0x40, 0x16]))
    assert meta == {"manufacturer": "winbond", "name": "W25Q32", "capacity": "4MiB"}


def test_jedec_meta_known_mfg_unknown_part_degrades_to_manufacturer_only():
    # Winbond manufacturer byte (authoritative JEDEC id) but an unlisted device -> name/capacity
    # omitted, never guessed.
    meta = ftdi._jedec_meta(bytes([0xEF, 0x99, 0x99]))
    assert meta == {"manufacturer": "winbond"}
    assert "name" not in meta and "capacity" not in meta


def test_jedec_meta_fully_unknown_is_empty():
    # An unknown manufacturer id yields just the number upstream: no descriptive metadata at all.
    assert ftdi._jedec_meta(bytes([0x00, 0x00, 0x00])) == {}


# --- op / scan / caps against the fake controller -------------------------------------------------

def test_open_configures_the_url_and_caps_advertise_only_spi(fake_pyftdi):
    m = _open("ftdi://ftdi:232h/2")
    try:
        assert _FakeSpiController.instances[-1].configured == "ftdi://ftdi:232h/2"
        caps = m.caps()
        assert caps["shape"] == "transaction"
        assert caps["protocol"] == "spi"
        assert caps["verbs"] == ["scan", "spi"]           # the whole spi group, nothing else
        for relay in ("sniff", "inject", "replay"):
            assert relay not in caps["verbs"]
        assert caps["meta"]["adapter"] == "ft232h"
        assert caps["meta"]["url"] == "ftdi://ftdi:232h/2"
    finally:
        m.close()


def test_default_url_when_no_target(fake_pyftdi):
    m = _open(None)
    try:
        assert _FakeSpiController.instances[-1].configured == ftdi.DEFAULT_URL
    finally:
        m.close()


def test_spi_id_issues_rdid_and_returns_jedec_and_name(fake_pyftdi):
    m = _open()
    try:
        res = m.op("spi.id", {})
        # EXACT MPSSE: opcode 0x9F clocked out, 3 id bytes read back.
        assert m._ports[0].exchanges == [(b"\x9f", 3)]
        assert res["jedec_id"] == 0xEF4016
        assert res["manufacturer"] == "winbond"
        assert res["name"] == "W25Q32"
        assert res["capacity"] == "4MiB"
    finally:
        m.close()


def test_spi_read_issues_read_opcode_plus_24bit_addr_and_returns_exact_len(fake_pyftdi):
    m = _open()
    try:
        res = m.op("spi.read", {"addr": 0x0102FF, "len": 8})
        # EXACT MPSSE: 0x03 then the big-endian 24-bit address, then read exactly `len` bytes.
        assert m._ports[0].exchanges == [(bytes([0x03, 0x01, 0x02, 0xFF]), 8)]
        data = bytes.fromhex(res["data"])
        assert len(data) == 8
        assert data == _FAKE_FLASH[0x0102FF:0x0102FF + 8]
    finally:
        m.close()


def test_spi_read_short_read_is_a_hard_error(fake_pyftdi):
    # A bad clip contact (fewer bytes than asked) must be a hard error, never a padded/short result.
    m = _open()
    try:
        m._port(0).short = True
        with pytest.raises(RuntimeError) as ei:
            m.op("spi.read", {"addr": 0, "len": 16})
        assert "short read" in str(ei.value)
    finally:
        m.close()


def test_spi_read_coerces_untrusted_args_authoritatively(fake_pyftdi):
    # addr/len/cs arrive off the wire: a non-numeric value must raise (clean wire ERROR upstream),
    # never a guessed byte on the bus.
    m = _open()
    try:
        for bad in ({"addr": "zz", "len": 4}, {"addr": 0, "len": "zz"}, {"addr": 0, "len": 4, "cs": "zz"}):
            with pytest.raises(Exception):
                m.op("spi.read", bad)
        # a negative / out-of-24-bit address is refused loud
        with pytest.raises(ValueError):
            m.op("spi.read", {"addr": 0x1000000, "len": 4})
        with pytest.raises(ValueError):
            m.op("spi.read", {"addr": 0, "len": 0})
    finally:
        m.close()


def test_deferred_ops_refuse_loud_not_fabricate(fake_pyftdi):
    # spi.write/reg/xfer are advertised as part of the group but not implemented on this real medium
    # yet: each must refuse LOUD, never return a fabricated result.
    m = _open()
    try:
        for verb in ("spi.write", "spi.reg", "spi.xfer"):
            with pytest.raises(RuntimeError) as ei:
                m.op(verb, {})
            assert "not implemented" in str(ei.value)
        with pytest.raises(ValueError):
            m.op("spi.frobnicate", {})
    finally:
        m.close()


def test_scan_returns_one_jedec_row(fake_pyftdi):
    m = _open()
    try:
        rows = m.scan()
        assert rows == [{"name": "W25Q32", "addr": "0xef4016", "cs": 0}]
    finally:
        m.close()


def test_apply_config_sets_spi_clock_and_ignores_junk(fake_pyftdi):
    m = _open()
    try:
        m.op("spi.id", {})                       # creates the cs=0 port
        m.apply_config({"spi_hz": 8_000_000})
        assert m._ports[0].freqs == [8_000_000.0]
        # non-positive / wrong-type / bool are ignored (default kept), never guessed
        for junk in ({"spi_hz": 0}, {"spi_hz": -1}, {"spi_hz": "fast"}, {"spi_hz": True}, {"baud": 115200}):
            m.apply_config(junk)
        assert m._ports[0].freqs == [8_000_000.0]
    finally:
        m.close()


def test_close_terminates_the_controller_and_alive_flips(fake_pyftdi):
    m = _open()
    ctrl = _FakeSpiController.instances[-1]
    assert m.alive() is True
    m.close()
    assert ctrl.terminated is True
    assert m.alive() is False


# --- end-to-end capability gate (C1) over the real client + real _serve_op bridge ------------------

def _serve(medium):
    """Run a real BridgeServer against `medium` on a loopback port, in a daemon thread. The fake
    pyftdi lives in THIS process, so the in-process bridge exercises the real _serve_op transaction
    path with no adapter (the hardware-free equivalent of `probe --backend ftdi`)."""
    server = BridgeServer(medium, host="127.0.0.1", port=0)
    server._control_timeout = 1.0
    port = server.bind()
    threading.Thread(target=lambda: server.serve_forever(idle_timeout=None), daemon=True).start()
    return server, port


@pytest.fixture
def ftdi_bridge(fake_pyftdi):
    m = ftdi.SpiFtdiMedium(None)
    m.open()
    server, port = _serve(m)
    try:
        yield port
    finally:
        server.close()
        m.close()


def _run(argv, port, capsys, monkeypatch):
    monkeypatch.setenv("ESP_PROBE", f"tcp://127.0.0.1:{port}")
    cli.main(argv)
    return capsys.readouterr().out


def test_caps_over_the_wire_gate_out_jtag_and_relay(ftdi_bridge):
    with VirtualBackend(f"tcp://127.0.0.1:{ftdi_bridge}") as b:
        caps = b.capabilities()
    assert caps.shape == "transaction"
    assert caps.verbs == ["scan", "spi"]
    for gated in ("jtag", "sniff", "inject", "replay", "gatt"):
        assert gated not in caps.verbs


def test_cli_jtag_on_ftdi_refuses_clean_c1(ftdi_bridge, capsys, monkeypatch):
    # `probe ... jtag halt` against the SPI medium: the unadvertised bus is refused by the single
    # capability gate before any routing, with the C1 message, never a traceback.
    with pytest.raises(SystemExit) as ei:
        _run(["jtag", "halt"], ftdi_bridge, capsys, monkeypatch)
    assert "'jtag' is not supported on protocol 'spi'" in str(ei.value)
    assert "supported: scan, spi" in str(ei.value)


@pytest.mark.parametrize("gated", ["sniff", "inject", "replay"])
def test_cli_relay_verbs_on_ftdi_refuse_clean_c1(gated, ftdi_bridge, capsys, monkeypatch, tmp_path):
    if gated == "sniff":
        argv = ["sniff", "-w", str(tmp_path / "x.pcap"), "-c", "1"]
    elif gated == "inject":
        argv = ["inject", "--hex", "00"]
    else:
        argv = ["replay", "-r", str(tmp_path / "x.pcap")]
    with pytest.raises(SystemExit) as ei:
        _run(argv, ftdi_bridge, capsys, monkeypatch)
    assert f"'{gated}' is not supported on protocol 'spi'" in str(ei.value)


def test_cli_spi_id_and_read_round_trip_real_bytes(ftdi_bridge, capsys, monkeypatch):
    out = _run(["spi", "id"], ftdi_bridge, capsys, monkeypatch)
    assert "jedec=0xef4016" in out
    assert "W25Q32" in out and "winbond" in out
    out = _run(["spi", "read", "--addr", "0x10", "--len", "4"], ftdi_bridge, capsys, monkeypatch)
    assert _FAKE_FLASH[0x10:0x14].hex() in out


def test_cli_scan_on_ftdi_enumerates_jedec(ftdi_bridge, capsys, monkeypatch):
    out = _run(["scan"], ftdi_bridge, capsys, monkeypatch)
    assert "0xef4016" in out and "W25Q32" in out


def test_cli_spi_dump_over_ftdi_writes_exact_bytes(ftdi_bridge, capsys, monkeypatch, tmp_path):
    out_bin = tmp_path / "flash.bin"
    out = _run(["spi", "dump", "--addr", "0", "--len", "256", "-w", str(out_bin)],
               ftdi_bridge, capsys, monkeypatch)
    assert "dumped 256 byte(s)" in out
    assert out_bin.read_bytes() == _FAKE_FLASH[:256]


def test_cli_spi_write_over_ftdi_refuses_loud_deferred(ftdi_bridge, capsys, monkeypatch):
    # spi.write is advertised in the group but deferred on the real medium: the op refuses loud and
    # the client exits nonzero, never a silent or fabricated success.
    with pytest.raises(SystemExit) as ei:
        _run(["spi", "write", "--addr", "0", "--hex", "aa"], ftdi_bridge, capsys, monkeypatch)
    assert "not implemented" in str(ei.value)
