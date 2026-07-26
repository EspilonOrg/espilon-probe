"""ESP protocol: ESP32 eFuse / secure-boot / flash-encryption transactions over Backend.op.

Shape: TRANSACTION + read-only CONSOLE (the composite `op_console` medium, see
docs/protocols/esp.md). The `esp` verbs are DOWNLOAD-mode transactions (burn eFuses / key
blocks, set read-protection, write/read flash, reboot); the boot BANNER is the read-only serial
console reached by the existing `uart` verbs (`probe uart read`). So this module carries only the
download-mode transactions; the banner needs no code here (the client already speaks the raw
stream for `uart read`, and the bridge serves both surfaces on one op_console device).

Every verb travels over the existing `op()` carrier as `OP{verb:"esp.<sub>", args}`, identical to
jtag/spi/ble, so the same `probe esp *` commands drive this simulated chip today and a real serial
backend speaking the esptool ROM protocol later - only the backend swaps. `scan` is the generic
bus enumerate (part name / chip id / boot mode via the SCAN wire verb, like ble), not an op.

This module carries NO device/challenge/flag/verdict knowledge and does NO crypto: the real
espsecure.py key-gen / sign / encrypt runs OFF-DEVICE on the player's host (Model B); the medium
only stores and compares the burned bytes. The client validates operator input (hex, key-block
names) and shapes the request; the device owns the verdict and the flag.
"""

from __future__ import annotations

from ..core.backend import Backend
from ..core.errors import ProbeError
from ..core.frame import DLT_USER_PROBE_ESP

PROTOCOL = "esp"
VERBS = ["scan", "esp", "uart"]
PCAP_DLT = DLT_USER_PROBE_ESP           # 150, optional transaction pcap only

# The six one-time-programmable key blocks on an ESP32-S3-class part. A block name is a HARDWARE
# fact (not challenge knowledge), so validating it client-side is a clean generalist check: it
# rejects an operator typo with a named error rather than shipping a nonsense block to the device.
KEY_BLOCKS = ("key0", "key1", "key2", "key3", "key4", "key5")


def _result(backend: Backend, verb: str, **kwargs) -> dict:
    """Call `op()` and guarantee a dict result (see jtag._result for the rationale).

    A null or non-dict result is a clean `ProbeError`, never an AttributeError from `.get()`.
    """
    res = backend.op(verb, **kwargs)
    if res is None:
        raise ProbeError(f"backend returned a null result for {verb}")
    if not isinstance(res, dict):
        raise ProbeError(f"backend returned a non-object result for {verb}: {res!r}")
    return res


def _hex_arg(data: str, field: str) -> str:
    """Validate operator-supplied hex and return it normalised (no spaces, lowercase).

    The key/digest/image bytes are produced OFF-DEVICE (espsecure.py) and pasted as hex; a typo
    must fail loud with a named `ProbeError` here rather than reach the device as junk. We return
    the canonical hex string (what the op carries), not bytes, so the wire stays hex end to end.
    """
    if not isinstance(data, str):
        raise ProbeError(f"{field} must be a hex string (got {type(data).__name__})")
    cleaned = data.strip().replace(" ", "")
    try:
        raw = bytes.fromhex(cleaned)
    except (ValueError, TypeError):
        raise ProbeError(f"invalid {field} {data!r} (expected hex bytes, e.g. deadbeef)")
    return raw.hex()


def _validate_block(block: str) -> str:
    """A key-block name must be one of key0..key5 (an ESP32 hardware fact), else a clean error."""
    name = str(block).lower()
    if name not in KEY_BLOCKS:
        known = ", ".join(KEY_BLOCKS)
        raise ProbeError(f"unknown key block {block!r} (expected one of: {known})")
    return name


def _parse_value(value, field: str) -> int:
    """Coerce an operator eFuse value (int, or 0x../decimal string) to int, else a clean error."""
    if isinstance(value, bool):
        raise ProbeError(f"invalid {field} {value!r} (expected an integer)")
    if isinstance(value, int):
        return value
    try:
        return int(str(value), 0)
    except (ValueError, TypeError):
        raise ProbeError(f"invalid {field} {value!r} (expected an integer, e.g. 1 or 0x1)")


# named transactions (used by the CLI dispatch and by tests/scripts)
def summary(backend: Backend) -> dict:
    """`esp summary` -> the eFuse/key-block/flash/boot state (espefuse.py summary analogue)."""
    return _result(backend, "esp.summary")


def burn_key(backend: Backend, block: str, purpose: str, data_hex: str) -> dict:
    """`esp burn-key <block> <purpose> --data <hex>` -> `{ok, ...}`.

    `block` is key0..key5; `purpose` is a named eFuse key purpose (xts_aes_128,
    secure_boot_digest0..2, user, ...) passed through to the device; `data_hex` is the key/digest
    bytes produced off-device. Write-once - the device refuses an already-burned/write-protected
    block cleanly."""
    return _result(backend, "esp.burn_key",
                   block=_validate_block(block), purpose=str(purpose),
                   data=_hex_arg(data_hex, "burn-key --data"))


def burn_efuse(backend: Backend, field: str, value) -> dict:
    """`esp burn-efuse <field> <value>` -> `{ok, field, old, new}`.

    `field` is a named eFuse field (SECURE_BOOT_EN, SPI_BOOT_CRYPT_CNT, DIS_PAD_JTAG, ...) passed
    through; the burn is monotonic per bit (0->1) at the device. A blank field name is refused."""
    name = str(field).strip()
    if not name:
        raise ProbeError("burn-efuse needs a field name (e.g. SECURE_BOOT_EN)")
    return _result(backend, "esp.burn_efuse", field=name, value=_parse_value(value, "value"))


def read_protect(backend: Backend, block: str) -> dict:
    """`esp read-protect <block>` -> `{ok, block}`; sets RD_DIS so summary/read redacts it."""
    return _result(backend, "esp.read_protect", block=_validate_block(block))


def write_flash(backend: Backend, region: str, data_hex: str, encrypt: bool = False) -> dict:
    """`esp write-flash [--encrypt] <region> <data>` -> `{ok, region, bytes, encrypted, signed}`.

    `region` names a declared flash region (bootloader/app/nvs/...); `data_hex` is the image the
    player built/signed/encrypted off-device; `--encrypt` marks it for on-the-fly encryption."""
    name = str(region).strip()
    if not name:
        raise ProbeError("write-flash needs a region name (e.g. bootloader or app)")
    return _result(backend, "esp.write_flash",
                   region=name, data=_hex_arg(data_hex, "write-flash data"),
                   encrypt=bool(encrypt))


def read_flash(backend: Backend, region: str) -> dict:
    """`esp read-flash <region>` -> `{region, data, opaque}`.

    `opaque` is True when the region reads back as ciphertext (flash-encryption active and the XTS
    key read-protected); the client renders it as opaque bytes, never interpreting them."""
    name = str(region).strip()
    if not name:
        raise ProbeError("read-flash needs a region name (e.g. bootloader or app)")
    return _result(backend, "esp.read_flash", region=name)


def reboot(backend: Backend) -> dict:
    """`esp reboot` -> `{banner, verdict}`; recomputes the boot verdict and rewrites the banner.

    This is the gated action: a qualifying reboot stages the earned flag into the banner, which the
    player then reads with `probe uart read`. The client only relays the request and shows the
    returned banner - the verdict/flag logic lives entirely on the device."""
    return _result(backend, "esp.reboot")
