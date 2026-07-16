"""The ONE shared BLE GATT attribute table both terminations serve (twin of can_isotp.py).

Declared implementation-neutrally as data so neither side hand-models the layout: the virtual
`GattServer` (conformance/gatt_server.py) reads it today, and the ESP-IDF GATT-server firmware will
read the identical spec on the real leg. Because both serve THIS table, any attribute difference the
conformance diff observes is a TRANSPORT difference, exactly as for the CAN/UART twins.

The table (docs/design/ble-gatt.md section 3.1): two vendor primary services, three
characteristics, and an "unlock then read the secret" value-change gate (NO SMP/pairing - the gate
flips the returned VALUE, faithful to the large class of UNAUTHENTICATED BLE locks). Static
permissions give the ATT error path for free: a write to the read-only `fw_version` -> 0x03, a read
of the write-only `unlock` -> 0x02.

HANDLES: on real silicon a GATT handle is SERVER-assigned (the ESP-IDF stack + any auto-registered
GAP 0x1800 / GATT 0x1801 boilerplate decide it), NOT client-chosen like a CAN frame's bytes. So the
handle layout below is an EXPLICIT pilot layout; the hardware leg RE-RECORDS it (run `probe gatt enum`
against the flashed ESP32 once, encode the exact discovered (handle, uuid, props) here -
record-then-encode, docs/design/ble-gatt.md section 3.4) and the virtual model reproduces the
silicon. Handles are IN comparison scope (the comparator's default is handle-exact; a uuid+props-keyed
fallback normalizes them out).

SINGLE-CHARACTERISTIC SCOPE ONLY: every value is <= 20 bytes (one ATT Read Response at the 23-byte
default MTU), so no Read Blob / long reads; NO notifications/CCCD, NO SMP, no multi-service beyond the
two vendor services. Multi-char / Read Blob / notifications / SMP are the kit follow-up.
"""

from __future__ import annotations

from dataclasses import dataclass

# 128-bit vendor UUID base; the 16-bit short field distinguishes each attribute. The tail encodes
# "probe" so a capture is obviously ours and never collides with an adopted 16-bit UUID.
_UUID_TMPL = "0000{:04x}-e5b1-4f00-9c00-70726f626500"


def uuid(short: int) -> str:
    return _UUID_TMPL.format(short)


# --- handle layout (explicit pilot layout; the hardware leg re-records against the ESP32) ---------
H_SVC_DEVINFO = 0x0001     # Primary Service "Device Info" (svc declaration)
H_FW_VERSION_DECL = 0x0002  # fw_version characteristic declaration
H_FW_VERSION = 0x0003      # fw_version characteristic VALUE (Read)
H_SVC_LOCK = 0x0004        # Primary Service "Lock" (svc declaration)
H_UNLOCK_DECL = 0x0005     # unlock characteristic declaration
H_UNLOCK = 0x0006          # unlock characteristic VALUE (Write)
H_SECRET_DECL = 0x0007     # secret characteristic declaration
H_SECRET = 0x0008          # secret characteristic VALUE (Read)

# --- characteristic property strings (as `gatt enum` renders them) --------------------------------
READ = "read"
WRITE = "write"

# --- ATT permission error codes (static; the crisp part of the ATT error path) --------------------
ATT_INVALID_HANDLE = 0x01
ATT_READ_NOT_PERMITTED = 0x02
ATT_WRITE_NOT_PERMITTED = 0x03

# --- values (NO flag, NO challenge content) -------------------------------------------------------
FW_VERSION = b"pilot-1"             # the banner-analogue, always-readable, non-secret
LOCKED_SENTINEL = b"\x00\x00\x00\x00"  # what `secret` returns UNTIL the correct-key unlock write
SECRET_VALUE = b"pilot-secret"      # the staged value served AFTER unlock (<= 20 bytes; non-secret)
UNLOCK_KEY = b"\x01\x02\x03\x04"    # the correct unlock key; course-visible, IN diff scope (like the
#                                     fixed UDS seed) - NOT normalized out


@dataclass(frozen=True)
class Attribute:
    """One discovered attribute: (handle, 128-bit uuid, property string). `props` is "" for a
    service/declaration attribute and "read"/"write" for a characteristic value."""

    handle: int
    uuid: str
    props: str


# The three characteristic VALUE attributes `gatt enum` lists (characteristic discovery). The service
# and declaration handles above pin the layout but are not the fidelity-bearing rows the pilot diffs.
CHARACTERISTICS = [
    Attribute(handle=H_FW_VERSION, uuid=uuid(0x0002), props=READ),
    Attribute(handle=H_UNLOCK, uuid=uuid(0x0011), props=WRITE),
    Attribute(handle=H_SECRET, uuid=uuid(0x0012), props=READ),
]
