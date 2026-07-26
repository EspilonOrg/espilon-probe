"""Hardware-free unit tests for the real hci BLE medium (bridges/media/hci.py).

These never touch a Bluetooth adapter and never require `bleak` to be installed: a FAKE `bleak`
module is injected into `sys.modules` so `HciMedium.__init__`'s lazy `import bleak` picks it up. That
lets the whole op/scan/error-map surface - INCLUDING the write path - be proven against a MOCK, per
the pilot's hard rule that the real PROTO-7 lock is never written during development and the suite
stays green with no real BLE.

The pure helpers (`_encode_mfg`, `_att_code`) are tested directly (no bleak, no loop).
"""

import asyncio
import struct
import sys
import threading
import types

import pytest

from espilon_probe.bridges.media import hci


class _DBusErr(Exception):
    """A stand-in for bleak's BleakDBusError: carries a `dbus_error` name attribute."""

    def __init__(self, name):
        super().__init__(name)
        self.dbus_error = name


# --- pure helpers (no bleak, no event loop) -------------------------------------------------------

def test_encode_mfg_reconstructs_company_id_and_payload():
    # company 0xFFFF + the PROTO-FOB <IHH> payload: the raw on-air bytes, company id LE first.
    payload = struct.pack("<IHH", 0x52320001, 0x0153, 0x8CA2)
    got = hci._encode_mfg({0xFFFF: payload})
    assert got == ("ffff" + payload.hex())
    # a caller recovers the company id from the first 2 bytes (LE) and the vendor payload after.
    raw = bytes.fromhex(got)
    assert struct.unpack("<H", raw[:2])[0] == 0xFFFF
    assert struct.unpack("<IHH", raw[2:]) == (0x52320001, 0x0153, 0x8CA2)


def test_encode_mfg_empty_is_blank():
    assert hci._encode_mfg(None) == ""
    assert hci._encode_mfg({}) == ""


def test_att_code_permission_is_context_sensitive():
    err = _DBusErr("org.bluez.Error.NotPermitted")
    assert hci._att_code(err, is_write=False) == 0x02   # read of a write-only char
    assert hci._att_code(err, is_write=True) == 0x03     # write of a read-only char


def test_att_code_maps_only_crisp_names_else_none():
    assert hci._att_code(_DBusErr("org.bluez.Error.InvalidValueLength"), False) == 0x0D
    assert hci._att_code(_DBusErr("org.bluez.Error.NotSupported"), False) == 0x06
    # An unrecognized fault must NOT be guessed into an ATT code: None -> a clean wire ERROR.
    assert hci._att_code(RuntimeError("bluetooth stack exploded"), False) is None
    assert hci._att_code(_DBusErr("org.bluez.Error.Failed"), False) is None


def test_att_code_ignores_free_text_message_tokens():
    # The structured `dbus_error` attribute is the ONLY authoritative source. A plain exception whose
    # free-text MESSAGE merely mentions a bluez error name must NOT be scraped into an ATT code -
    # doing so would silent-pass a fabricated code the conformance diff could not catch.
    exc = RuntimeError("write failed near org.bluez.Error.InvalidValueLength in some log line")
    assert hci._att_code(exc, is_write=True) is None
    assert hci._att_code(exc, is_write=False) is None


# --- op/scan surface against a FAKE bleak ---------------------------------------------------------

class _FakeChar:
    def __init__(self, handle, uuid, properties):
        self.handle, self.uuid, self.properties = handle, uuid, properties


class _FakeService:
    def __init__(self, characteristics):
        self.characteristics = characteristics


class _FakeDBusError(Exception):
    def __init__(self, dbus_error):
        super().__init__(dbus_error)
        self.dbus_error = dbus_error


class _FakeClient:
    connect_calls = 0

    # read-only 0x0014 -> value; write-only 0x000f -> a read raises NotPermitted; a write to a
    # read-only handle raises NotPermitted (drives the 0x02/0x03 mapping).
    _VALUES = {0x0011: b"CHAL t=1 fmt=u16", 0x0014: b"LOCKED"}
    _READ_ONLY = {0x0011, 0x0014}
    _WRITE_ONLY = {0x000f}

    def __init__(self, device, **kw):
        self.device = device
        self._connected = False
        self.writes = []

    async def connect(self, timeout=None):
        type(self).connect_calls += 1
        self._connected = True

    async def disconnect(self):
        self._connected = False

    @property
    def is_connected(self):
        return self._connected

    @property
    def services(self):
        return [_FakeService([
            _FakeChar(0x000f, "4d420000-726f-6c6c-6761-746500000012", ["write-without-response", "write"]),
            _FakeChar(0x0011, "4d420000-726f-6c6c-6761-746500000013", ["read", "notify"]),
            _FakeChar(0x0014, "4d420000-726f-6c6c-6761-746500000014", ["read"]),
        ])]

    async def read_gatt_char(self, spec):
        if spec in self._WRITE_ONLY:
            raise _FakeDBusError("org.bluez.Error.NotPermitted")
        return bytearray(self._VALUES[spec])

    async def write_gatt_char(self, spec, data, response=True):
        if spec in self._READ_ONLY:
            raise _FakeDBusError("org.bluez.Error.NotPermitted")
        self.writes.append((spec, bytes(data), response))


class _FakeAdv:
    def __init__(self, local_name, manufacturer_data, rssi):
        self.local_name, self.manufacturer_data, self.rssi = local_name, manufacturer_data, rssi


class _FakeDevice:
    def __init__(self, address, name):
        self.address, self.name = address, name


class _FakeScanner:
    adverts: list = []

    def __init__(self, detection_callback=None):
        self._cb = detection_callback

    async def start(self):
        for dev, adv in self.adverts:
            self._cb(dev, adv)

    async def stop(self):
        pass

    @staticmethod
    async def find_device_by_name(name, timeout=None):
        for dev, adv in _FakeScanner.adverts:
            if dev.name == name:
                return dev
        return None


@pytest.fixture
def fake_bleak(monkeypatch):
    """Inject a fake `bleak` module and shrink the scan window so the medium runs hardware-free."""
    mod = types.ModuleType("bleak")
    mod.BleakClient = _FakeClient
    mod.BleakScanner = _FakeScanner
    monkeypatch.setitem(sys.modules, "bleak", mod)
    monkeypatch.setattr(hci, "_SCAN_WINDOW", 0.01)
    _FakeClient.connect_calls = 0
    _FakeScanner.adverts = []
    yield mod


def _open(endpoint):
    m = hci.HciMedium(endpoint)
    m.open()
    return m


def test_scan_accumulates_distinct_advertisements_by_address_and_mfg(fake_bleak):
    fob10 = struct.pack("<IHH", 0x52320001, 0x0150, 0x1111)
    fob11 = struct.pack("<IHH", 0x52320001, 0x0151, 0x2222)
    _FakeScanner.adverts = [
        # same fob, two presses: distinct address AND distinct payload -> two rows
        (_FakeDevice("F0:0B:A2:0F:01:50", "PROTO-FOB"), _FakeAdv("PROTO-FOB", {0xFFFF: fob10}, -60)),
        (_FakeDevice("F0:0B:A2:0F:01:51", "PROTO-FOB"), _FakeAdv("PROTO-FOB", {0xFFFF: fob11}, -61)),
        # a stationary beacon re-advertising identical data collapses to ONE row
        (_FakeDevice("11:22:33:44:55:66", "BEACON"), _FakeAdv("BEACON", {0x004C: b"\x02\x15"}, -70)),
        (_FakeDevice("11:22:33:44:55:66", "BEACON"), _FakeAdv("BEACON", {0x004C: b"\x02\x15"}, -70)),
        # the lock: no manufacturer data at all
        (_FakeDevice("68:09:47:86:21:6A", "PROTO-7"), _FakeAdv("PROTO-7", None, -76)),
    ]
    m = _open(hci.NO_TARGET)
    try:
        rows = m.scan()
    finally:
        m.close()
    fobs = [r for r in rows if r["name"] == "PROTO-FOB"]
    assert len(fobs) == 2
    assert fobs[0]["mfg"] == "ffff" + fob10.hex()
    assert fobs[1]["mfg"] == "ffff" + fob11.hex()
    assert [r["name"] for r in rows].count("BEACON") == 1     # deduped
    lock = [r for r in rows if r["name"] == "PROTO-7"][0]
    assert lock["mfg"] == ""                                   # no manufacturer data surfaced


def test_gatt_enum_lists_handle_uuid_props(fake_bleak):
    m = _open("68:09:47:86:21:6A")
    try:
        chars = m.op("gatt.enum", {})["characteristics"]
    finally:
        m.close()
    handles = [c["handle"] for c in chars]
    assert handles == [0x000f, 0x0011, 0x0014]
    status = next(c for c in chars if c["handle"] == 0x0011)
    assert status["uuid"] == "4d420000-726f-6c6c-6761-746500000013"
    assert status["props"] == "read,notify"


def test_gatt_read_returns_value_and_reuses_one_persistent_connection(fake_bleak):
    m = _open("68:09:47:86:21:6A")
    try:
        assert bytes.fromhex(m.op("gatt.read", {"handle": 0x0011})["value"]) == b"CHAL t=1 fmt=u16"
        assert bytes.fromhex(m.op("gatt.read", {"handle": 0x0014})["value"]) == b"LOCKED"
        m.op("gatt.enum", {})
    finally:
        m.close()
    # Three ops, ONE connect: the medium holds a single persistent BleakClient (section 4.3).
    assert _FakeClient.connect_calls == 1


def test_gatt_read_of_write_only_maps_to_att_0x02(fake_bleak):
    m = _open("68:09:47:86:21:6A")
    try:
        assert m.op("gatt.read", {"handle": 0x000f}) == {"error": 0x02}
    finally:
        m.close()


def test_gatt_write_ack_and_response_flag_against_the_mock(fake_bleak):
    # The write path proven against a MOCK (never PROTO-7): a write to the RX handle acks, and the
    # response/no-response flag reaches bleak's `response=` argument.
    m = _open("68:09:47:86:21:6A")
    try:
        assert m.op("gatt.write", {"handle": 0x000f, "value": "01020304"}) == {"ok": True}
        assert m.op("gatt.write",
                    {"handle": 0x000f, "value": "aa", "response": False}) == {"ok": True}
        client = m._client
    finally:
        m.close()
    assert client.writes == [(0x000f, b"\x01\x02\x03\x04", True), (0x000f, b"\xaa", False)]


def test_gatt_write_of_read_only_maps_to_att_0x03(fake_bleak):
    m = _open("68:09:47:86:21:6A")
    try:
        assert m.op("gatt.write", {"handle": 0x0014, "value": "01"}) == {"error": 0x03}
    finally:
        m.close()


def test_gatt_op_on_scan_only_target_fails_loud(fake_bleak):
    # A scan-only spawn (NO_TARGET) has no peripheral; a gatt op must refuse loud, never silently.
    m = _open(hci.NO_TARGET)
    try:
        with pytest.raises(RuntimeError):
            m.op("gatt.read", {"handle": 0x0011})
    finally:
        m.close()


def test_unknown_gatt_verb_raises(fake_bleak):
    m = _open("68:09:47:86:21:6A")
    try:
        with pytest.raises(ValueError):
            m.op("gatt.frobnicate", {})
    finally:
        m.close()


async def _pending_tasks_excluding_self():
    me = asyncio.current_task()
    return [t for t in asyncio.all_tasks() if t is not me]


def test_run_timeout_drains_the_cancelled_task(fake_bleak):
    # A timed-out _run must DRAIN the cancellation on the loop, not just request it: otherwise the
    # underlying asyncio Task is left pending and Python leaks a "Task was destroyed but it is
    # pending" warning onto the daemon stderr when the loop is later stopped.
    m = _open("68:09:47:86:21:6A")
    try:
        started = threading.Event()
        cancelled = {"v": False}

        async def hang():
            started.set()
            try:
                await asyncio.sleep(30)
            except asyncio.CancelledError:
                cancelled["v"] = True
                raise

        with pytest.raises(RuntimeError):
            m._run(hang(), timeout=0.05)
        # The drain waited for the loop to actually deliver+process the cancellation.
        assert cancelled["v"] is True
        # No task is left pending on the loop after the drain.
        fut = asyncio.run_coroutine_threadsafe(_pending_tasks_excluding_self(), m._loop)
        assert fut.result(timeout=2.0) == []
    finally:
        m.close()
