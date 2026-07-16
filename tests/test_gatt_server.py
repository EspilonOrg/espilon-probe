"""Unit tests for the flag-free GattServer reference model (the transaction twin of UdsEcu tests).

Model-level (no socket, no bridge): enumerate/read/write, the static permission ATT errors, and the
unlock->secret value-change gate. The load-bearing anti-leak assertion is that `secret` is the LOCKED
sentinel before a correct-key write and the staged value only after - never the value before the gate.
"""

from conformance import ble_attrs
from conformance.gatt_server import AttError, GattServer


def test_enumerate_is_the_pinned_characteristic_table():
    chars = GattServer().enumerate()
    assert [(a.handle, a.props) for a in chars] == [
        (ble_attrs.H_FW_VERSION, "read"),
        (ble_attrs.H_UNLOCK, "write"),
        (ble_attrs.H_SECRET, "read"),
    ]
    assert [a.uuid for a in chars] == [ble_attrs.uuid(0x0002), ble_attrs.uuid(0x0011),
                                       ble_attrs.uuid(0x0012)]


def test_read_fw_version_is_the_banner_analogue():
    assert GattServer().read(ble_attrs.H_FW_VERSION) == ble_attrs.FW_VERSION


def test_read_write_only_unlock_is_att_read_not_permitted():
    res = GattServer().read(ble_attrs.H_UNLOCK)
    assert res == AttError(ble_attrs.ATT_READ_NOT_PERMITTED)
    assert res.code == 0x02


def test_write_read_only_fw_version_is_att_write_not_permitted():
    res = GattServer().write(ble_attrs.H_FW_VERSION, b"\x01")
    assert res == AttError(ble_attrs.ATT_WRITE_NOT_PERMITTED)
    assert res.code == 0x03


def test_write_read_only_secret_is_att_write_not_permitted():
    assert GattServer().write(ble_attrs.H_SECRET, b"\x01") == \
        AttError(ble_attrs.ATT_WRITE_NOT_PERMITTED)


def test_unknown_handle_is_att_invalid_handle_both_directions():
    g = GattServer()
    assert g.read(0x00FF) == AttError(ble_attrs.ATT_INVALID_HANDLE)
    assert g.write(0x00FF, b"\x01") == AttError(ble_attrs.ATT_INVALID_HANDLE)


def test_secret_is_locked_sentinel_before_any_unlock():
    g = GattServer()
    assert g.unlocked is False
    assert g.read(ble_attrs.H_SECRET) == ble_attrs.LOCKED_SENTINEL
    # the sentinel is NOT the staged value - the gate cannot be a no-op
    assert ble_attrs.LOCKED_SENTINEL != ble_attrs.SECRET_VALUE


def test_correct_key_write_unlocks_and_serves_the_staged_value():
    g = GattServer()
    assert g.write(ble_attrs.H_UNLOCK, ble_attrs.UNLOCK_KEY) is None   # ATT Write ack, no error
    assert g.unlocked is True
    assert g.read(ble_attrs.H_SECRET) == ble_attrs.SECRET_VALUE


def test_wrong_key_write_neither_errors_nor_unlocks_then_retry_works():
    g = GattServer()
    # wrong key: ATT Write ack (None), no state change, still locked
    assert g.write(ble_attrs.H_UNLOCK, b"\xaa\xbb\xcc\xdd") is None
    assert g.unlocked is False
    assert g.read(ble_attrs.H_SECRET) == ble_attrs.LOCKED_SENTINEL
    # the seed-equivalent stays valid: a subsequent CORRECT key still unlocks (retry path)
    assert g.write(ble_attrs.H_UNLOCK, ble_attrs.UNLOCK_KEY) is None
    assert g.read(ble_attrs.H_SECRET) == ble_attrs.SECRET_VALUE


def test_secret_never_leaks_the_staged_value_before_the_gate():
    # Adversarial: read the secret handle repeatedly before any write - it must never be the value.
    g = GattServer()
    for _ in range(5):
        assert g.read(ble_attrs.H_SECRET) != ble_attrs.SECRET_VALUE
        assert g.read(ble_attrs.H_SECRET) == ble_attrs.LOCKED_SENTINEL


def test_idle_surfaces_exclude_the_staged_secret_value():
    surfaces = GattServer().idle_surfaces()
    assert ble_attrs.FW_VERSION in surfaces
    assert ble_attrs.LOCKED_SENTINEL in surfaces
    assert ble_attrs.SECRET_VALUE not in surfaces      # the gated value is never an idle surface
