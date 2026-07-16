"""A minimal, flag-free GATT reference model - the TRANSACTION twin of console.py / uds_ecu.py.

The SAME model bound two ways (docs/design/ble-gatt.md sections 3, 4): served in-process behind
the virtual GattOpMedium, and (on the gated real leg) reproduced by the ESP32 GATT-server firmware -
the peripheral IS the responder, so there is no separate responder process twin. Because both
terminations serve the identical `ble_attrs` table, any attribute/value difference the conformance
diff observes is a TRANSPORT difference, which is what the diff is there to catch.

Deliberately minimal: two vendor services, three characteristics, and an unlock->secret value-change
gate (the ATT/BLE analogue of UdsEcu's SecurityAccess gate and the labs' payload()-after-emit()
staging). The gate is a VALUE change, NOT an auth error, because the pilot excludes SMP/pairing (real
ATT 0x05 Insufficient Authentication needs an encryption permission the pilot does not implement) -
faithful to the large class of UNAUTHENTICATED BLE locks. ATT error coverage comes free from the
STATIC permissions: writing the read-only fw_version -> 0x03, reading the write-only unlock -> 0x02.

NO flag, NO challenge content. Single-characteristic scope only (every value <= 20 bytes; no Read
Blob, no notifications/CCCD, no SMP). The full kit GattServer (author-declared tables, emit/payload
flag staging, assert_clean, SMP) is a SEPARATE follow-up.

Model contract (delivery-agnostic, mirrors Console/UdsEcu): `enumerate()/read()/write()` hold the
`unlocked` state across calls; NO GATT-PDU and NO L2CAP here - the medium/firmware owns handle
assignment and PDU framing, and this model answers at the attribute level, exactly as UdsEcu answers
at the UDS-PDU level.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import ble_attrs


@dataclass(frozen=True)
class AttError:
    """An ATT error outcome from a read/write (an ATT Error Response code). Distinct from a returned
    value so callers pattern-match on the type, never on a sentinel that could collide with a real
    value."""

    code: int


class GattServer:
    def __init__(self):
        self.unlocked = False

    def enumerate(self) -> list[ble_attrs.Attribute]:
        """The pinned characteristic table (handle, uuid, props) `gatt enum` discovers."""
        return list(ble_attrs.CHARACTERISTICS)

    def read(self, handle: int) -> bytes | AttError:
        """Read a characteristic value, or an ATT error code. Holds no PDU/L2CAP framing."""
        if handle == ble_attrs.H_FW_VERSION:
            return ble_attrs.FW_VERSION
        if handle == ble_attrs.H_UNLOCK:
            # A read of the WRITE-ONLY unlock characteristic: static permission error 0x02.
            return AttError(ble_attrs.ATT_READ_NOT_PERMITTED)
        if handle == ble_attrs.H_SECRET:
            # The value-change gate: the staged value ONLY after a correct-key unlock, else the
            # LOCKED sentinel - never the value before the gated write (the anti-leak invariant).
            return ble_attrs.SECRET_VALUE if self.unlocked else ble_attrs.LOCKED_SENTINEL
        # A handle outside the pinned table: authoritative ATT Invalid Handle, never a guessed value.
        return AttError(ble_attrs.ATT_INVALID_HANDLE)

    def write(self, handle: int, value: bytes) -> None | AttError:
        """Write a characteristic value; return None on an ATT Write ack, or an ATT error code. A
        correct-key write to `unlock` flips `unlocked`."""
        value = bytes(value)
        if handle == ble_attrs.H_UNLOCK:
            if value == ble_attrs.UNLOCK_KEY:
                self.unlocked = True
            # A WRONG key does NOT unlock and does NOT error: the ATT Write Response still succeeds,
            # the app no-ops, and the seed-equivalent stays valid so a subsequent correct-key write
            # still unlocks - the "retry with the right key" path (UdsEcu's invalid-key branch shape),
            # proven over two terminations.
            return None
        if handle in (ble_attrs.H_FW_VERSION, ble_attrs.H_SECRET):
            # A write to a READ-ONLY characteristic: static permission error 0x03.
            return AttError(ble_attrs.ATT_WRITE_NOT_PERMITTED)
        return AttError(ble_attrs.ATT_INVALID_HANDLE)

    def idle_surfaces(self) -> list[bytes]:
        """Non-secret surfaces for a future assert_clean audit (banner-equivalent). This pilot model
        stages no flag, so every surface here is non-secret by construction; notably the staged
        SECRET_VALUE is NOT listed (it is the gated value), while the LOCKED sentinel is. The real
        audit lands with the kit GattServer."""
        return [ble_attrs.FW_VERSION, ble_attrs.LOCKED_SENTINEL]
