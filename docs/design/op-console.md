# Design note: the `op_console` composite shape

**Status:** implemented (bridge-server only; zero `core/wire.py` change). Serves the `esp` medium
(`docs/protocols/esp.md`); generic to any bootloader/console-style target.

## Why

An ESP32 hardening workflow uses two channels on the SAME physical UART: DOWNLOAD-mode
request/response transactions (`espefuse.py` / `esptool.py`) AND a NORMAL-boot log the ROM prints
as a byte stream. So the medium must expose BOTH a transaction OP surface AND a read-only console
stream on one target. The existing shapes serve exactly one each: `packet` (framed OP/scan/sniff)
rejects `STREAM_ATTACH`, and `stream` (a raw duplex byte pipe) rejects `OP`.

## The shape

`shape = "op_console"`: a transaction OP surface plus a read-only console stream. It is advertised
in `capabilities().shape`, but nothing on the client DATA PATH branches on the shape name - the
client already speaks both `OP` (for the `esp` verbs) and `STREAM_ATTACH` (for `probe uart read`),
and each `probe` invocation is its own connection against the one persistent device. So the client
stays 100% generic; this is a bridge-server change only.

On the bridge (`espilon_probe_bridge.server`):

- the framed handshake loop serves `OP` / `SCAN` exactly as a packet device (the `esp.*`
  transactions); INJECT/REPLAY/SNIFF get the ordinary clean refusal (an op_console medium
  implements no `on_frame`/`feed`);
- on `STREAM_ATTACH` the connection upgrades to a raw pipe and runs a READ-ONLY banner pump
  (`_serve_op_console`): it sends `STREAM_READY`, forwards the device's boot banner
  (`stream_read`), and DROPS any client bytes (a boot log has no write surface). The banner
  surface is NON-DESTRUCTIVE (re-reading returns the current banner again), so the pump forwards
  only the growth past what it has already sent - the banner is delivered once per attach (no flood
  from re-reading a non-destructive buffer), and a concurrent reboot that appends new banner bytes
  streams through.

## Deviation from the original contract sketch

The design sketch suggested the read pump reuse the existing duplex `_pump(mode="read")`. That
loop re-polls `stream_read()` and forwards whatever it returns every cycle; with a NON-DESTRUCTIVE
banner (which the kit `BootConsole` is, by contract, so `probe uart read` is re-readable) that
would re-send the whole banner every poll - a flood. The read-only banner pump therefore tracks
the bytes already forwarded and sends only the delta, which delivers the banner once and still
streams any live growth. Same functional contract (STREAM_READY, read-only, client writes ignored),
flood-safe for a non-destructive log.
