# Protocol: ESP (ESP32 eFuse / secure-boot / flash-encryption)

**Status:** shape `op_console` (transaction surface + a read-only boot-log console on ONE
device). The `virtual` backend works today; the real serial backend (esptool ROM protocol) is
not built yet, but the same `probe esp *` and `probe uart read` commands drive it unchanged.

Read `../protocol-conventions.md` first. This doc specifies `protocols/esp.py` and what a virtual
backend must simulate.

## 1. What it models

An operator hardening an ESP32 over the USB-UART, in DOWNLOAD mode, with `espefuse.py` /
`esptool.py`, plus reading the boot log in NORMAL mode with a serial terminal:

- burn key blocks (secure-boot public-key digest, XTS flash-encryption key),
- burn named eFuse fields (SECURE_BOOT_EN, SPI_BOOT_CRYPT_CNT, DIS_PAD_JTAG, ...),
- set read-protection (RD_DIS) on a key block,
- write/read flash images (bootloader / app / nvs), with on-the-fly encryption,
- reboot and watch the boot banner report secure-boot verify + flash-encryption status.

The keys are generated and the images signed / encrypted OFF-DEVICE with your own
`espsecure.py` (Model B); `probe esp *` only burns / flashes / verifies the RESULTS on the chip.
The medium does NO crypto - it compares digests and booleans only, exactly like the real ROM.

## 2. Shape and verb set

Shape: `op_console`. Two channels on one physical UART:

- DOWNLOAD mode -> the `esp` transactions run over `OP{verb:"esp.<sub>"}` (request/response),
  identical to jtag/spi.
- NORMAL boot -> the ROM/2nd-stage bootloader prints a boot log; you read it with the existing
  `uart` verbs (`probe uart read`), the read-only console stream. Flags surface here after a
  qualifying `esp reboot`.

Core verbs:

| Core verb | ESP | Reason |
|---|---|---|
| `scan` | OFFERED | enumerate the chip (part / chip id / boot mode) |
| `sniff` / `inject` / `replay` | GATED OUT | download mode is request/response, not a frame bus |
| `uart read` | OFFERED | the read-only boot banner (the reveal stream) |

## 3. The `esp` verbs

| Verb | Wire op | Result |
|---|---|---|
| `esp summary` | `esp.summary` | eFuse fields, key blocks, flash/secure-boot booleans, boot verdict |
| `esp burn-key <block> <purpose> --data <hex>` | `esp.burn_key` | `{ok, block, purpose}` (write-once) |
| `esp burn-efuse <field> <value>` | `esp.burn_efuse` | `{ok, field, old, new}` (monotonic per bit) |
| `esp read-protect <block>` | `esp.read_protect` | `{ok, block}` (sets RD_DIS) |
| `esp write-flash [--encrypt] <region> <data>` | `esp.write_flash` | `{ok, region, bytes, encrypted, signed}` |
| `esp read-flash <region>` | `esp.read_flash` | `{region, data, opaque}` |
| `esp reboot` | `esp.reboot` | `{banner, verdict}` (recompute + rewrite the banner) |

- `block` is `key0..key5`; `purpose` is a named eFuse key purpose (`xts_aes_128`,
  `secure_boot_digest0..2`, `user`, ...).
- `summary` redacts a read-protected key block as `[read-protected]` and never prints its raw
  key/digest bytes; a write-protected field shows `(wp)`.
- `read-flash` returns `opaque:true` (ciphertext) when the region is encrypted, flash-encryption
  is active, and its XTS key block is read-protected; else `opaque:false` (plaintext recon).
- `esp reboot` is the gated action: a qualifying reboot stages the earned flag into the banner,
  which you then read with `probe uart read`.

## 4. espefuse.py / esptool.py <-> probe esp mapping

The mechanical course rewrite: keep your espefuse/esptool exposition and add the probe equivalent.

| host tool command | probe verb |
|---|---|
| `espefuse.py summary` | `probe esp summary` |
| `espefuse.py burn_key BLOCK_KEY0 xts.bin XTS_AES_128_KEY` | `probe esp burn-key key0 xts_aes_128 --data <hex>` |
| `espefuse.py burn_key BLOCK_KEY0 sb_digest.bin SECURE_BOOT_DIGEST0` | `probe esp burn-key key0 secure_boot_digest0 --data <hex>` |
| `espefuse.py burn_efuse SECURE_BOOT_EN 1` | `probe esp burn-efuse SECURE_BOOT_EN 1` |
| `espefuse.py burn_efuse SPI_BOOT_CRYPT_CNT 1` | `probe esp burn-efuse SPI_BOOT_CRYPT_CNT 1` |
| `espefuse.py burn_efuse DIS_PAD_JTAG 1` | `probe esp burn-efuse DIS_PAD_JTAG 1` |
| `espefuse.py burn_efuse DIS_DOWNLOAD_MANUAL_ENCRYPT 1` | `probe esp burn-efuse DIS_DOWNLOAD_MANUAL_ENCRYPT 1` |
| `espefuse.py read_protect_efuse BLOCK_KEY0` | `probe esp read-protect key0` |
| `esptool.py write_flash 0x0 bootloader-signed.bin` | `probe esp write-flash bootloader <hex>` |
| `esptool.py write_flash --encrypt 0x10000 app.bin` | `probe esp write-flash --encrypt app <hex>` |
| `esptool.py read_flash 0x10000 0x4000 out.bin` | `probe esp read-flash app` |
| power-cycle / `esptool.py run` | `probe esp reboot` |
| `screen /dev/ttyUSB0 115200` (boot log) | `probe uart read` |

The name / purpose / field strings are the real ones, so the mental model transfers straight to
hardware. Only the backend swaps: `virtual` today, a serial ROM backend later.

## 5. Client / device boundary

Stays on YOUR host (real `espsecure.py`, no probe involvement):

- `espsecure.py generate_signing_key` + `digest_sbv2_public_key` -> the digest you `burn-key`,
- `espsecure.py generate_flash_encryption_key` -> the XTS key you `burn-key`,
- `espsecure.py sign_data` -> sign the bootloader/app you `write-flash`,
- `espsecure.py encrypt_flash_data` -> encrypt an image for a first plaintext-less flash.

Handled by the chip (`probe esp`): store the burned bytes, burn eFuse bits, set RD_DIS, store
flash bytes, return plaintext/opaque flash, and compute the boot verdict + banner. The boundary is
exactly the real-hardware one.
