"""Client-side esp verb coverage against a scripted mock bridge.

Drives the `probe esp *` transactions (summary / burn-key / burn-efuse / read-protect /
write-flash / read-flash / reboot) through the CLI and the protocol module, asserting the wire
shape (`OP{verb:"esp.<sub>"}`) and the operator-facing rendering, plus the client-side input
validation (hex, key-block names) that fails loud before anything reaches the wire.
"""

import os

import pytest

from espilon_probe import cli
from espilon_probe.core import wire
from espilon_probe.core.errors import ProbeError
from espilon_probe.protocols import esp

from _mock_bridge import serve_mock

ESP_CAPS = {"protocol": "esp", "channels": [],
            "verbs": ["scan", "sniff", "inject", "replay", "esp", "uart"],
            "shape": "op_console", "pcap_dlt": 150, "meta": {}}


def _esp_respond(captured_ops):
    """A tiny scripted esp device: records each OP and returns a plausible result per verb."""
    def respond(msg):
        if msg.get("t") != wire.OP:
            return wire.error("unhandled")
        verb = msg.get("verb")
        args = msg.get("args") or {}
        captured_ops.append((verb, args))
        if verb == "esp.summary":
            return {"t": wire.OP_RESULT, "result": {
                "efuses": [{"name": "SECURE_BOOT_EN", "value": 1, "writeprot": True,
                            "readprot": False}],
                "blocks": [{"name": "key0", "purpose": "secure_boot_digest0",
                            "readable": True, "writeprot": True, "digest": "aabb"},
                           {"name": "key1", "purpose": "xts_aes_128",
                            "readable": False, "writeprot": True}],
                "flash_encryption": True, "secure_boot": True, "crypt_cnt": 1,
                "boot": {"verdict": "enabled_verified", "summary": "Secure Boot v2 enabled"}}}
        if verb == "esp.burn_key":
            return {"t": wire.OP_RESULT, "result": {
                "ok": True, "block": args.get("block"), "purpose": args.get("purpose")}}
        if verb == "esp.burn_efuse":
            return {"t": wire.OP_RESULT, "result": {
                "ok": True, "field": args.get("field"), "old": 0, "new": args.get("value")}}
        if verb == "esp.read_protect":
            return {"t": wire.OP_RESULT, "result": {"ok": True, "block": args.get("block")}}
        if verb == "esp.write_flash":
            return {"t": wire.OP_RESULT, "result": {
                "ok": True, "region": args.get("region"), "bytes": 4,
                "encrypted": bool(args.get("encrypt")), "signed": True}}
        if verb == "esp.read_flash":
            opaque = args.get("region") == "app"
            data = "c0ffee00" if opaque else "68656c6c6f"      # "hello" plaintext otherwise
            return {"t": wire.OP_RESULT, "result": {
                "region": args.get("region"), "data": data, "opaque": opaque}}
        if verb == "esp.reboot":
            return {"t": wire.OP_RESULT, "result": {
                "banner": "ESP-ROM boot\r\nSecure Boot v2 enabled\r\n",
                "verdict": {"secure_boot": "enabled_verified", "summary": "verified"}}}
        return wire.error("unhandled")
    return respond


def _backend(port):
    from espilon_probe.backends.virtual import VirtualBackend
    b = VirtualBackend(f"tcp://127.0.0.1:{port}")
    b.open()
    return b


def _serve(captured_ops):
    return serve_mock(ESP_CAPS, _esp_respond(captured_ops))


def _run(argv, port, capsys):
    os.environ["ESP_PROBE"] = f"tcp://127.0.0.1:{port}"
    cli.main(argv)
    return capsys.readouterr().out


# --- protocol-module wire shape ------------------------------------------------------------
def test_esp_verbs_emit_the_right_op():
    ops = []
    srv, port = _serve(ops)
    try:
        b = _backend(port)
        esp.summary(b)
        esp.burn_key(b, "key0", "secure_boot_digest0", "AA BB")   # spaces tolerated
        esp.burn_efuse(b, "SECURE_BOOT_EN", 1)
        esp.read_protect(b, "key1")
        esp.write_flash(b, "app", "deadbeef", encrypt=True)
        esp.read_flash(b, "app")
        esp.reboot(b)
        b.close()
    finally:
        srv.shutdown()
        srv.server_close()
    verbs = [v for v, _ in ops]
    assert verbs == ["esp.summary", "esp.burn_key", "esp.burn_efuse", "esp.read_protect",
                     "esp.write_flash", "esp.read_flash", "esp.reboot"]
    # hex is normalised (spaces stripped, lowercased) before it hits the wire.
    assert ops[1][1]["data"] == "aabb"
    assert ops[4][1] == {"region": "app", "data": "deadbeef", "encrypt": True}


# --- client-side validation (fails loud, before the wire) ----------------------------------
def test_burn_key_rejects_unknown_block():
    with pytest.raises(ProbeError):
        esp.burn_key(None, "key9", "user", "aa")


def test_burn_key_rejects_bad_hex():
    with pytest.raises(ProbeError):
        esp.burn_key(None, "key0", "user", "zz")


def test_burn_efuse_rejects_non_int_value():
    with pytest.raises(ProbeError):
        esp.burn_efuse(None, "SECURE_BOOT_EN", "notanint")


# --- CLI rendering -------------------------------------------------------------------------
def test_cli_summary_redacts_read_protected_block(capsys):
    ops = []
    srv, port = _serve(ops)
    try:
        out = _run(["esp", "summary"], port, capsys)
    finally:
        srv.shutdown()
        srv.server_close()
    assert "SECURE_BOOT_EN = 0x1  (wp)" in out
    assert "key0" in out and "aabb" in out                 # readable block shows its digest
    assert "[read-protected]" in out                        # key1 is redacted
    assert "flash_encryption=True" in out and "secure_boot=True" in out


def test_cli_read_flash_marks_opaque(capsys):
    ops = []
    srv, port = _serve(ops)
    try:
        out_app = _run(["esp", "read-flash", "app"], port, capsys)
        out_nvs = _run(["esp", "read-flash", "nvs"], port, capsys)
    finally:
        srv.shutdown()
        srv.server_close()
    assert "[opaque" in out_app                              # ciphertext rendered opaque
    assert "hello" in out_nvs                                # plaintext recon decoded


def test_cli_reboot_prints_banner_and_verdict(capsys):
    ops = []
    srv, port = _serve(ops)
    try:
        out = _run(["esp", "reboot"], port, capsys)
    finally:
        srv.shutdown()
        srv.server_close()
    assert "Secure Boot v2 enabled" in out
    assert "verdict: verified" in out


def test_cli_write_flash_reports_ok(capsys):
    ops = []
    srv, port = _serve(ops)
    try:
        out = _run(["esp", "write-flash", "--encrypt", "app", "deadbeef"], port, capsys)
    finally:
        srv.shutdown()
        srv.server_close()
    assert out.startswith("ok")
    assert ops[-1][1]["encrypt"] is True
