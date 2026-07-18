"""probe CLI - parse, select a backend, dispatch verbs, print results.

Target selection:
  - default backend `virtual`, reading the target endpoint from ESP_PROBE (tcp://host:port)
  - `--backend socketcan|serial|hci` selects a real adapter (implemented)
  - `--backend killerbee|sdr|openocd|ftdi` selects a real adapter (planned)

Core verbs: info, scan, sniff, inject, replay
Protocol verbs: gatt (BLE), can, uart, jtag, spi, subghz
"""

from __future__ import annotations

import argparse
import math
import os
import struct
import sys

from . import config
from .core import wire
from .core.backend import UART_READ_TIMEOUT_DEFAULT
from .core.errors import ProbeError

# The known backend names (same list `--backend` documents), used for the `use` positional's
# choices. Only virtual/hci/serial/socketcan are implemented; the rest are advertised targets.
_BACKEND_NAMES = ["virtual", "hci", "killerbee", "sdr", "serial", "openocd", "ftdi", "socketcan"]


def _add_radio_args(p: argparse.ArgumentParser) -> None:
    """sub-GHz radio params that extend the core verbs (rather than adding new ones).

    `--freq` accepts 433.92M / 868.3M / a raw Hz int; `--mod` in {ook, ask, 2fsk, gfsk};
    `--rate` is the symbol rate. They are ignored by non-radio protocols.
    """
    p.add_argument("--freq", help="sub-GHz center frequency (e.g. 433.92M or a raw Hz int)")
    p.add_argument("--mod", help="sub-GHz modulation: ook | ask | 2fsk | gfsk")
    p.add_argument("--rate", type=int, help="sub-GHz symbol/baud rate (default per band)")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="probe", description="One CLI for the physical layer.")
    # These three default to a None SENTINEL so the config layer can sit BETWEEN env and the
    # built-in default (resolved in _resolve_config_defaults). A None here means "the user did not
    # pass the flag"; with no config file the resolved values are byte-identical to the historical
    # env-or-default behaviour (the regression contract).
    p.add_argument("--backend", default=None,
                   help="virtual (default) | hci | killerbee | sdr | serial | openocd | ftdi | socketcan "
                        "(default also from $ESP_PROBE_BACKEND, then `probe use`)")
    p.add_argument("--target", default=None,
                   help="backend endpoint (default: $ESP_PROBE_TARGET, then `probe use`, "
                        "or $ESP_PROBE for virtual)")
    p.add_argument("--baud", type=int, default=None,
                   help="UART line rate (default 115200, or `probe use`; no env var). On a real "
                        "line a wrong baud is physically garbage; the virtual backend models it.")
    sub = p.add_subparsers(dest="verb", required=False)

    u = sub.add_parser("use", help="persist default backend/target/baud/scan-secs "
                                   "(client-only; opens no backend)")
    u.add_argument("use_backend", nargs="?", metavar="BACKEND", choices=_BACKEND_NAMES,
                   help="backend to remember (optional; omit to set only --target/--baud/--scan-secs)")
    u.add_argument("--target", dest="use_target", metavar="X", help="endpoint to remember")
    u.add_argument("--baud", dest="use_baud", type=int, help="UART line rate to remember")
    u.add_argument("--scan-secs", dest="use_scan_secs", type=float,
                   help="default scan listen window (seconds) to remember")
    ug = u.add_mutually_exclusive_group()
    ug.add_argument("--show", dest="use_show", action="store_true",
                    help="print the config path, stored keys, and the effective value + source per key")
    ug.add_argument("--clear", dest="use_clear", action="store_true",
                    help="remove the config file (idempotent)")

    sub.add_parser("wizard", help="launch the interactive guided wizard (needs a terminal)")

    sub.add_parser("demo", help="run a zero-setup tour against a bundled toy target (no hardware)")

    sub.add_parser("info", help="show backend, protocol, channels, capabilities")
    scn = sub.add_parser("scan", help="enumerate what is on the protocol")
    scn.add_argument("--band", help="sub-GHz: ISM band to sweep (e.g. 433|868|915)")
    scn.add_argument("-t", "--seconds", type=float,
                     help="how long to listen, in seconds (packet media: BLE/CAN/...). Precedence: "
                          "this flag > $ESP_PROBE_SCAN_SECS > the medium's own default. A quick look "
                          "is `-t 2`; a long rotating-address collection run is `-t 15`. Ignored by "
                          "the transaction bus-enumerate scans (jtag/spi) which are instantaneous.")
    scn.add_argument("-c", "--count", type=int,
                     help="stop early once this many distinct devices/advertisements are seen "
                          "(a cheaper 'quick look' than a full window; the window still bounds it)")

    sn = sub.add_parser("sniff",
                        help="capture frames to a standard pcap "
                             "(client-bounded; default ceiling 30s if no -c/-t given)")
    sn.add_argument("-w", "--write", required=True, metavar="PCAP")
    sn.add_argument("-c", "--count", type=int)
    sn.add_argument("-t", "--seconds", type=float)
    sn.add_argument("--channel", type=int)
    _add_radio_args(sn)

    inj = sub.add_parser("inject", help="transmit one raw frame")
    g = inj.add_mutually_exclusive_group(required=True)
    g.add_argument("--hex")
    g.add_argument("-r", "--read", metavar="FRAME")
    inj.add_argument("--channel", type=int, help="channel to transmit on (protocols that support it)")
    _add_radio_args(inj)

    rp = sub.add_parser("replay", help="re-transmit frames from a pcap (pre-filter with tshark -w)")
    rp.add_argument("-r", "--read", required=True, metavar="PCAP")
    _add_radio_args(rp)

    gt = sub.add_parser("gatt", help="BLE GATT operations")
    gs = gt.add_subparsers(dest="gatt_cmd", required=True)
    gs.add_parser("enum", help="list services/characteristics")
    gr = gs.add_parser("read", help="read a characteristic")
    gr.add_argument("handle", help="handle (e.g. 0x0011) or uuid")
    gw = gs.add_parser("write", help="write a characteristic")
    gw.add_argument("handle", help="handle (e.g. 0x0014) or uuid (e.g. fff2)")
    gw.add_argument("value", help="hex value (e.g. 01)")
    gw.add_argument("--no-response", action="store_true",
                    help="use an ATT Write Command (write-without-response) instead of the default "
                         "Write Request (write-with-response)")

    cn = sub.add_parser("can", help="CAN bus operations")
    cs = cn.add_subparsers(dest="can_cmd", required=True)
    csend = cs.add_parser("send", help="send a CAN frame")
    csend.add_argument("id", help="arbitration id (e.g. 0x7DF)")
    csend.add_argument("data", help="hex payload (e.g. 0201)")
    cdump = cs.add_parser("dump", help="capture CAN frames to a pcap")
    cdump.add_argument("-w", "--write", required=True, metavar="PCAP")
    cdump.add_argument("-c", "--count", type=int)
    cdump.add_argument("-t", "--seconds", type=float)

    ut = sub.add_parser("uart", help="UART console operations")
    us = ut.add_subparsers(dest="uart_cmd", required=True)
    uw = us.add_parser("write", help="send text to the line")
    uw.add_argument("data", help="text to send")
    ur = us.add_parser("read", help="read available output")
    ur.add_argument("-t", "--timeout", type=float, default=UART_READ_TIMEOUT_DEFAULT,
                    help="seconds to wait for the FIRST byte before draining the line "
                         "(default %(default)s; 0 = quick bounded poll)")
    uc = us.add_parser("console",
                       help="interactive terminal on the raw byte pipe (screen/picocom-grade). "
                            "Detach with Ctrl-]. NOTE: Ctrl-C/Ctrl-D are forwarded to the DEVICE "
                            "as bytes, not local signals; needs an interactive tty.")
    uc.add_argument("--local-echo", action="store_true",
                    help="also echo forwarded input locally (for a genuinely SILENT device; on an "
                         "echoing device this doubles - default OFF)")
    uc.add_argument("--eol", choices=["cr", "lf", "crlf"], default="cr",
                    help="map Enter on the INPUT path only: cr (default, pass-through) | lf | crlf")
    uc.add_argument("--replay-buffer", action="store_true",
                    help="print the pre-attach backlog before going live (default: discard it, "
                         "like screen attaching to a live line)")
    usnd = us.add_parser("send",
                         help="one-shot atomic send-then-drain on a SINGLE duplex connection "
                              "(the scriptable sibling of console; deterministic on any bridge)")
    usnd.add_argument("text", help="text to send (UTF-8); the --eol terminator is appended")
    usnd.add_argument("-t", "--timeout", type=float, default=UART_READ_TIMEOUT_DEFAULT,
                      help="seconds to wait for the FIRST response byte before draining "
                           "(default %(default)s; 0 = quick bounded poll)")
    usnd.add_argument("--eol", choices=["cr", "lf", "crlf"], default="cr",
                      help="line terminator appended to <text>: cr (default) | lf | crlf")
    usnd.add_argument("--expect", metavar="REGEX",
                      help="exit 0 iff the drained response matches this regex, else nonzero")
    usnd.add_argument("--no-read", action="store_true",
                      help="send only; read and print nothing (a bare atomic write + terminator)")

    jt = sub.add_parser("jtag", help="JTAG TAP operations (transaction protocol)")
    js = jt.add_subparsers(dest="jtag_cmd", required=True)
    js.add_parser("scan-chain", help="enumerate the scan chain (TAPs + IDCODEs)")
    ji = js.add_parser("idcode", help="read a TAP's IDCODE")
    ji.add_argument("--tap", type=int, default=0)
    jh = js.add_parser("halt", help="halt the core")
    jh.add_argument("--tap", type=int, default=0)
    jr = js.add_parser("resume", help="resume the core")
    jr.add_argument("--tap", type=int, default=0)
    jr.add_argument("--addr", help="resume at address (hex or int)")
    jrd = js.add_parser("read", help="read memory words")
    jrd.add_argument("--addr", required=True, help="address (hex or int)")
    jrd.add_argument("--words", type=int, default=1)
    jw = js.add_parser("write", help="write a memory word")
    jw.add_argument("--addr", required=True, help="address (hex or int)")
    jw.add_argument("--word", required=True, help="value (hex or int)")
    jrg = js.add_parser("reg", help="read CPU register(s)")
    jrg.add_argument("--name", help="register name (omit for all)")
    jd = js.add_parser("dump", help="dump a memory range to a raw binary image")
    jd.add_argument("--addr", required=True, help="start address (hex or int)")
    jd.add_argument("--len", required=True, help="length in bytes (hex or int)")
    jd.add_argument("-w", "--write", required=True, metavar="BIN")
    jd.add_argument("--pcap", metavar="PCAP", help="also write an optional transaction pcap")

    sp = sub.add_parser("spi", help="SPI master operations (transaction protocol)")
    sps = sp.add_subparsers(dest="spi_cmd", required=True)
    spi_id = sps.add_parser("id", help="read the JEDEC ID (RDID)")
    spi_id.add_argument("--cs", type=int, default=0)
    spr = sps.add_parser("read", help="read bytes from the device")
    spr.add_argument("--addr", required=True, help="address (hex or int)")
    spr.add_argument("--len", required=True, help="length in bytes (hex or int)")
    spr.add_argument("--cs", type=int, default=0)
    spw = sps.add_parser("write", help="write bytes to the device (page program)")
    spw.add_argument("--addr", required=True, help="address (hex or int)")
    spw.add_argument("--hex", required=True, help="hex payload")
    spw.add_argument("--cs", type=int, default=0)
    spg = sps.add_parser("reg", help="read/write a register (e.g. status)")
    spg.add_argument("name", help="register name (e.g. status)")
    spg.add_argument("--read", action="store_true", help="read the register (default)")
    spg.add_argument("--write", metavar="HEX", help="write the register with a hex value")
    spg.add_argument("--cs", type=int, default=0)
    spx = sps.add_parser("xfer", help="raw full-duplex transaction (clock MOSI, capture MISO)")
    spx.add_argument("--hex", required=True, help="MOSI hex bytes")
    spx.add_argument("--cs", type=int, default=0)
    spd = sps.add_parser("dump", help="dump a flash range to a raw binary image")
    spd.add_argument("--addr", default="0", help="start address (hex or int, default 0)")
    spd.add_argument("--len", required=True, help="length in bytes (hex or int)")
    spd.add_argument("--cs", type=int, default=0)
    spd.add_argument("-w", "--write", required=True, metavar="BIN")
    spd.add_argument("--pcap", metavar="PCAP", help="also write an optional transaction pcap")

    sg = sub.add_parser("subghz", help="sub-GHz radio hints (modulation/bands)")
    sgs = sg.add_subparsers(dest="subghz_cmd", required=True)
    sgd = sgs.add_parser("demod", help="modulation/bitrate HINT for a capture (not a decoder)")
    sgd.add_argument("-r", "--read", metavar="PCAP", help="capture to analyse")
    sgs.add_parser("bands", help="list the ISM bands")
    return p


def _make_backend(name: str, target: str | None, baud: int = 115200):
    if name == "virtual":
        from .backends.virtual import VirtualBackend
        return VirtualBackend(target, baud=baud)
    if name == "socketcan":
        from .backends.socketcan import CanBackend
        return CanBackend(target, baud=baud)
    if name == "serial":
        from .backends.serial import SerialBackend
        return SerialBackend(target, baud=baud)
    if name == "hci":
        # The real BLE leg: a loopback launcher that spawns the `probe-bridge --medium hci` daemon
        # (bleak over BlueZ, behind the `[hci]` extra) and holds ONE persistent BLE connection to the
        # peripheral across the per-verb `probe gatt` processes (docs/design/ble-gatt.md
        # sections 2, 4.3). bleak is imported LAZILY inside the medium, so selecting hci without the
        # extra fails with one clear line; the client core stays stdlib-only.
        from .backends.hci import HciBackend
        return HciBackend(target, baud=baud)
    raise SystemExit(f"probe: backend '{name}' is not implemented yet (planned hardware backends = killerbee/sdr/openocd/ftdi).")


def _parse_int(text: str, what: str = "value") -> int:
    """Parse an operator-supplied integer (accepts 0x.. hex or decimal), failing clean.

    A malformed numeric argument is a `ProbeError` (rendered `probe: ...`), never a traceback;
    these are addresses/words/lengths only the protocol layer can judge."""
    try:
        return int(str(text), 0)
    except (ValueError, TypeError):
        raise ProbeError(f"invalid {what} {text!r} (expected an int, e.g. 0x20000000 or 12)")


def _parse_hex(text: str, what: str = "hex") -> bytes:
    """Parse an operator-supplied hex string to bytes, failing clean.

    Malformed operator hex (`probe inject --hex zz`, `probe spi write --hex zz`) is a
    `ProbeError` rendered `probe: invalid hex ...`, matching the address-error wording, never
    the bare `non-hexadecimal number found in fromhex()` text from `bytes.fromhex`."""
    try:
        return bytes.fromhex(str(text))
    except (ValueError, TypeError):
        raise ProbeError(f"invalid {what} {text!r} (expected hex bytes, e.g. 0201 or deadbeef)")


def _require_positive_seconds(val: float, label: str) -> float:
    """A `-t/--seconds` window must be a POSITIVE, FINITE number of seconds, else a clean ProbeError.

    Rejects <= 0, nan, and inf. A non-positive value silently captures nothing (`elapsed >= seconds`
    is true at once, or never for a wall guard), and nan/inf never satisfy the stop conditions and
    leak a raw stdlib error (e.g. `settimeout` on a nan/inf deadline). All three fail loud here
    instead so an operator who fat-fingered the window is told, not left with a silent empty
    capture."""
    if math.isnan(val) or math.isinf(val) or val <= 0:
        raise ProbeError(f"{label} must be a positive number of seconds (got {val:g})")
    return val


def _require_positive_count(val: int, label: str) -> int:
    """A `-c/--count` early-stop must be > 0, else a clean ProbeError. A non-positive count stops the
    capture before the first frame (`n >= count` holds at n=0), silently capturing nothing."""
    if val <= 0:
        raise ProbeError(f"{label} must be > 0 (got {val})")
    return val


def _capture_bounds(args) -> tuple[float | None, int | None]:
    """Validate the `-t/--seconds` and `-c/--count` bounds a capture (`sniff` / `can dump`) was
    given, returning the (seconds, count) to hand the backend. Either may be omitted (None); a value
    that is present must be positive and finite, matching how `scan` validates its window, so a
    non-positive / nan / inf bound fails loud rather than silently capturing nothing."""
    seconds = getattr(args, "seconds", None)
    count = getattr(args, "count", None)
    if seconds is not None:
        seconds = _require_positive_seconds(seconds, "-t/--seconds")
    if count is not None:
        count = _require_positive_count(count, "-c/--count")
    return seconds, count


def _scan_seconds(args, cfg: dict | None = None) -> float | None:
    """Resolve the scan listen window: the `-t/--seconds` flag, else `$ESP_PROBE_SCAN_SECS`, else
    the config file's `scan_secs`, else None (the medium's own default). Precedence is
    flag > env > config > medium default.

    A malformed or non-positive value from the FLAG or the ENV is a clean `ProbeError`, never a
    silent fallback: an operator who asked for a specific window per-invocation must not have a typo
    quietly swallowed. A bad `scan_secs` in the CONFIG file is the operator's own persisted default
    (not a per-invocation typo), so it degrades to the medium default with a one-line warning rather
    than aborting the command (consistent with config.load's degrade-not-crash rule). This is
    operator config, not attacker input; the wire-side bound (server clamps `seconds` to a hard
    ceiling) is what stays conservative against a hostile value.
    """
    val = getattr(args, "seconds", None)
    src = "--seconds"
    if val is None:
        raw = os.environ.get("ESP_PROBE_SCAN_SECS")
        if raw is not None and raw != "":
            src = "ESP_PROBE_SCAN_SECS"
            try:
                val = float(raw)
            except ValueError:
                raise ProbeError(f"invalid {src} {raw!r} (expected seconds, e.g. 3 or 1.5)")
        else:
            return _cfg_scan_seconds(cfg)
    return _require_positive_seconds(val, src)


def _cfg_scan_seconds(cfg: dict | None) -> float | None:
    """The config-file scan window, degrading a bad stored value to the medium default + warning."""
    cv = (cfg or {}).get("scan_secs")
    if cv is None:
        return None
    try:
        val = float(cv)
    except (ValueError, TypeError):
        val = 0.0
    if val <= 0:
        print(f"probe: ignoring invalid config scan_secs {cv!r}; using the medium default",
              file=sys.stderr)
        return None
    return val


def _scan_rows(items) -> list[dict]:
    """Normalize the generic `scan` result for the display loop, matching jtag/spi.scan_rows.

    The packet protocols (ble/zigbee/subghz) route `scan` through the generic SCAN wire verb,
    whose `items` are backend-supplied. A non-list `items` is a clean `ProbeError` (we do not
    guess a shape we cannot read), and individual non-dict rows are skipped rather than crashing
    the display loop on `.get()` (which used to leak `'NoneType' object has no attribute 'get'`).
    """
    if items is None:
        return []
    if not isinstance(items, list):
        raise ProbeError(f"backend returned non-list scan items {items!r}")
    return [it for it in items if isinstance(it, dict)]


def _hex_field(value, field: str) -> bytes:
    """Coerce a backend hex string to bytes for display, or raise a clean `ProbeError`.

    Reuses spi's guarded `_hex_bytes` so a bad backend hex value (spi read / gatt read display)
    gives `backend returned malformed hex for <field>` instead of leaking
    `non-hexadecimal number found in fromhex()`. spi.dump already routes through this path;
    this makes the interactive read display consistent."""
    from .protocols.spi import _hex_bytes
    return _hex_bytes(value if value else "", field)


def _dropped_note(b) -> str:
    """A ` (N malformed frame(s) dropped)` suffix for the capture line, or "" when none dropped.

    Surfaces the skip-and-count total from the last `sniff` so the operator knows a hostile
    target sent frames that were dropped rather than the capture silently missing them."""
    dropped = getattr(b, "dropped_frames", 0) or 0
    if dropped:
        return f" ({dropped} malformed frame(s) dropped)"
    return ""


def _report_write(res, what: str = "write") -> None:
    """Render a protocol write result, or raise a clean `ProbeError` on a rejected write.

    A successful write prints `ok` (plus any extra fields the backend returned). A rejected
    write used to be dumped as a raw Python dict (`{'ok': False, 'addr': 1073741828}`); instead
    we raise a one-line operator error (`write rejected at 0x40000004`, plus a reason when the
    backend supplies one) so the CLI exits nonzero with an honest message rather than leaking a
    repr. A non-dict result is refused loud, never coerced.
    """
    if not isinstance(res, dict):
        raise ProbeError(f"backend returned a non-object {what} result: {res!r}")
    if res.get("ok"):
        extra = {k: val for k, val in res.items() if k != "ok"}
        print("ok" + (f" {extra}" if extra else ""))
        return
    from .core.fields import as_int
    msg = f"{what} rejected"
    addr = res.get("addr")
    if addr is not None:
        try:
            msg += f" at 0x{as_int(addr, 'addr'):08x}"
        except ProbeError:
            msg += f" at {addr!r}"
    reason = res.get("reason") or res.get("error") or res.get("msg")
    if reason:
        msg += f" ({reason})"
    raise ProbeError(msg)


def _fmt_value(hexstr, field: str = "value") -> str:
    raw = _hex_field(hexstr, field)
    try:
        s = raw.decode()
        if s.isprintable():
            return s
    except Exception:
        pass
    return raw.hex()


# CLI verb -> the top-level capability verb it requires. `info` is never gated: it is the
# operator-visible gate display itself. `can`/`gatt`/`uart` map to their group name, matching
# how those verbs appear in `capabilities().verbs`.
_VERB_REQUIRES = {
    "scan": "scan",
    "sniff": "sniff",
    "inject": "inject",
    "replay": "replay",
    "gatt": "gatt",
    "uart": "uart",
    "jtag": "jtag",
    "spi": "spi",
    "subghz": "subghz",
}
# `can` is sugar over the core verbs (send -> inject, dump -> sniff), so its sub-commands
# gate on the underlying core verb rather than a "can" group that backends do not advertise.
_CAN_REQUIRES = {"send": "inject", "dump": "sniff"}

# Each protocol's own action-verb group, as the CLI exposes it. `probe info` renders this
# verb alongside the core verbs so the surface is uniform across protocols; a protocol with
# no group verb (zigbee is pure packet) simply has no entry here.
_PROTOCOL_VERB = {
    "ble": "gatt",
    "can": "can",
    "uart": "uart",
    "jtag": "jtag",
    "spi": "spi",
    "subghz": "subghz",
}


def _info_verbs(caps) -> list[str]:
    """The verb list `probe info` prints: deduplicated, with the protocol's own verb present.

    The advertised `caps.verbs` can arrive with duplicates (a sloppy bridge once sent
    `scan,...,scan,jtag`) or missing the protocol's group verb (a CAN bridge advertises only
    the core verbs, yet `probe can` is a real command). We render a stable, honest surface:
    keep the advertised order, drop repeats, and append the protocol's own action verb when it
    is not already listed. This is a display normalization only; the capability gate
    (`_require_verb`) still runs against the raw advertised verbs.
    """
    verbs: list[str] = []
    for v in caps.verbs:
        if v not in verbs:
            verbs.append(v)
    own = _PROTOCOL_VERB.get(caps.protocol)
    if own and own not in verbs:
        verbs.append(own)
    return verbs


def _require_verb(caps, verb: str) -> None:
    """Hard-error clean if `verb` is not advertised by the protocol's capabilities.

    This is the single capability gate (convention C1). It runs BEFORE any protocol verb is
    routed, so an unsupported verb is a clean `ProbeError`, never a traceback from a backend
    that does not implement it.

    `caps.verbs` MUST be a list for membership to be authoritative: a bare string would make
    `verb in caps.verbs` a SUBSTRING test (`"uart" in "scan,uart"`), so a lying bridge could pass
    the gate for a verb it never advertised. The virtual backend already coerces this to a list, but
    the gate re-checks defensively - a non-list means "nothing advertised", refuse loud - so no
    backend can ever route a verb past a substring accident.
    """
    verbs = caps.verbs if isinstance(caps.verbs, list) else []
    if verb not in verbs:
        supported = ", ".join(str(x) for x in verbs) or "(none)"
        raise ProbeError(
            f"'{verb}' is not supported on protocol '{caps.protocol}' (supported: {supported})")


def _dispatch(args, b) -> int:
    from .protocols import ble
    v = args.verb
    if v == "can":
        required = _CAN_REQUIRES.get(args.can_cmd)
    else:
        required = _VERB_REQUIRES.get(v)
    if required is not None:
        _require_verb(b.capabilities(), required)
    if v == "info":
        c = b.capabilities()
        print(f"backend: {c.transport}   protocol: {c.protocol}   shape: {c.shape}   "
              f"channels: {','.join(map(str, c.channels))}   verbs: {','.join(_info_verbs(c))}")
    elif v == "scan":
        # For the transaction protocols, `scan` is repurposed as a bus enumerate routed
        # through op() (jtag scan-chain / spi JEDEC-ID), so the protocol module produces the
        # rows; every other protocol uses the generic SCAN wire verb.
        caps = b.capabilities()
        proto = caps.protocol
        if proto == "jtag":
            from .protocols import jtag
            items = jtag.scan_rows(b)
        elif proto == "spi":
            from .protocols import spi
            items = spi.scan_rows(b)
        else:
            items = _scan_rows(b.scan(seconds=_scan_seconds(args, getattr(args, "_cfg", None)),
                                      count=args.count))
            if getattr(args, "band", None):
                items = _filter_band(items, caps, args.band)
        if not items:
            print("(nothing on the protocol)")
        else:
            for it in items:
                cols = [str(it.get(k, "")) for k in ("name", "addr", "rssi")]
                # `mfg` is the raw advertising manufacturer_data (company id LE + payload) as hex; a
                # BLE advertiser can leak data ONLY here, so render it explicitly rather than folding
                # it into the generic extra dict (docs/design/ble-gatt.md section 6).
                mfg = it.get("mfg")
                extra = {k: x for k, x in it.items()
                         if k not in ("name", "addr", "rssi", "mfg")}
                line = "  ".join(c for c in cols if c)
                if mfg:
                    line += f"  mfg={mfg}"
                print(line + (f"   {extra}" if extra else ""))
    elif v == "sniff":
        # sub-GHz tunes the capture by frequency: --freq resolves to the int-channel field.
        channel = _radio_channel(args) if getattr(args, "freq", None) else args.channel
        seconds, count = _capture_bounds(args)
        n = b.sniff(args.write, count=count, seconds=seconds, channel=channel)
        print(f"captured {n} frame(s) -> {args.write}{_dropped_note(b)}")
    elif v == "inject":
        frame, channel = _build_inject(b, args)
        b.inject(frame, channel=channel)
        print("injected")
    elif v == "replay":
        print(f"replayed {b.replay(args.read)} frame(s)")
    elif v == "can":
        from .protocols import can
        if args.can_cmd == "send":
            can_id = _parse_int(args.id, "arbitration id")
            _parse_hex(args.data, "hex payload")   # validate operator hex at source, clean error
            can.send(b, can_id, args.data)
            print("sent")
        elif args.can_cmd == "dump":
            seconds, count = _capture_bounds(args)
            n = b.sniff(args.write, count=count, seconds=seconds)
            print(f"captured {n} frame(s) -> {args.write}{_dropped_note(b)}")
    elif v == "uart":
        from .protocols import uart
        if args.uart_cmd == "write":
            n = uart.write(b, args.data.encode())
            print(f"wrote {n} byte(s)")
        elif args.uart_cmd == "read":
            _uart_read(b, args.timeout)
        elif args.uart_cmd == "console":
            return _uart_console(b, args)
        elif args.uart_cmd == "send":
            return _uart_send(b, args)
    elif v == "gatt":
        if args.gatt_cmd == "enum":
            from .core.fields import as_int
            # Each characteristic is backend-supplied: skip non-dict rows and coerce `handle`
            # through as_int so a `handle:"0x11"` string cannot leak a format/`int()` error, and
            # a missing uuid/props renders empty rather than raising KeyError.
            for c in ble.gatt_enum(b).get("characteristics", []) or []:
                if not isinstance(c, dict):
                    continue
                handle = as_int(c.get("handle", 0), "gatt handle")
                print(f"0x{handle:04x}  {c.get('uuid', '')}  {c.get('props', '')}".rstrip())
        elif args.gatt_cmd == "read":
            h = _resolve_handle(b, args.handle)
            res = ble.gatt_read(b, h)
            # An ATT error (a static permission error, ...) renders deterministically and exits
            # nonzero, the way UDS renders an NRC - checked BEFORE the value gate, since an error
            # result carries no `value` key (docs/design/ble-gatt.md section 5).
            err = ble.att_error(res)
            if err is not None:
                raise err
            # An unreadable/unknown handle must not print a silent empty line. We require an
            # authoritative `value` key: a result that omits it is refused loud rather than
            # rendered as an empty read (which is indistinguishable from a real empty value).
            if not isinstance(res, dict) or "value" not in res:
                raise ProbeError(f"no such handle 0x{h:04x} (handle not readable)")
            print(_fmt_value(res.get("value", ""), "gatt.read value"))
        elif args.gatt_cmd == "write":
            h = _resolve_handle(b, args.handle)
            res = ble.gatt_write(b, h, args.value, response=not args.no_response)
            # A write to a read-only characteristic returns an ATT error (0x03); render it the same
            # deterministic way, before the generic write-reject rendering.
            err = ble.att_error(res)
            if err is not None:
                raise err
            _report_write(res, "write")
    elif v == "jtag":
        _dispatch_jtag(args, b)
    elif v == "spi":
        _dispatch_spi(args, b)
    elif v == "subghz":
        _dispatch_subghz(args, b)
    return 0


_EOL_TERMINATOR = {"cr": b"\r", "lf": b"\n", "crlf": b"\r\n"}


def _require_stream(caps, verb: str) -> None:
    """Gate `uart console`/`uart send` on a stream shape (docs/design/uart-console.md section 6),
    in addition to the `uart`-in-verbs gate. These are byte-pipe verbs; a packet/transaction backend
    has no raw stream to attach, so refuse loud rather than attempt a stream upgrade it cannot honour.
    """
    if caps.shape != "stream":
        raise ProbeError(
            f"'uart {verb}' needs a stream protocol, but '{caps.protocol}' is shape "
            f"'{caps.shape}' (not a byte stream)")


def _uart_console(b, args) -> int:
    """`probe uart console`: hand a duplex StreamChannel to the generic console loop."""
    import sys

    from .core import console
    caps = b.capabilities()
    _require_stream(caps, "console")
    # Refuse a non-tty stdin BEFORE attaching (a console session holds the bridge exclusively).
    if not sys.stdin.isatty():
        raise ProbeError(console.NO_TTY_MESSAGE)
    target = args.target or caps.meta.get("port") or "target"
    banner = f"[probe] attached to {target} (uart, {args.baud} baud) - escape: Ctrl-]"
    channel = b.stream_open("duplex")
    return console.run_console(channel, local_echo=args.local_echo, eol=args.eol,
                               replay_buffer=args.replay_buffer, attach_banner=banner)


def _uart_read(b, timeout) -> None:
    """`probe uart read`: stream the drained line to stdout INCREMENTALLY.

    The read is already size-bounded at the backend (see StreamChannel.drain_into), but we also
    avoid materializing-then-decoding one giant buffer: each drained chunk is decoded through an
    incremental UTF-8 decoder (errors=replace) and written as it arrives. The incremental decoder is
    load-bearing for correctness, not just memory: a multi-byte UTF-8 character split across two recv
    chunks would be corrupted by a naive per-chunk `.decode()`, but the incremental decoder carries
    the partial bytes across chunks and flushes any trailing incomplete sequence at the end -
    byte-for-byte the same text the old whole-buffer `.decode(errors="replace")` produced."""
    import codecs

    from .protocols import uart
    decoder = codecs.getincrementaldecoder("utf-8")("replace")

    def sink(chunk: bytes) -> None:
        text = decoder.decode(chunk)
        if text:
            sys.stdout.write(text)

    uart.read_into(b, sink, timeout)
    tail = decoder.decode(b"", final=True)
    if tail:
        sys.stdout.write(tail)
    sys.stdout.flush()


def _uart_send(b, args) -> int:
    """`probe uart send`: atomic send-then-drain on one duplex connection, byte-faithful stdout."""
    from .protocols import uart
    caps = b.capabilities()
    _require_stream(caps, "send")
    if args.no_read and args.expect is not None:
        raise ProbeError("--expect cannot be combined with --no-read (nothing is read to match)")
    payload = args.text.encode() + _EOL_TERMINATOR[args.eol]
    resp = uart.send(b, payload, timeout=args.timeout, read=not args.no_read)
    if not args.no_read:
        import os
        import sys
        # Byte-faithful: write the raw response bytes to stdout so a redirected capture gets the
        # exact device bytes, with no text-mode newline mangling (unlike print()).
        sys.stdout.flush()
        _write_stdout_bytes(resp)
        if args.expect is not None:
            import re
            if re.search(args.expect, resp.decode(errors="replace")) is None:
                raise ProbeError(f"expected pattern {args.expect!r} not found in the response")
    return 0


def _write_stdout_bytes(data: bytes) -> None:
    import os
    view = memoryview(data)
    while view:
        view = view[os.write(1, view):]


def _filter_band(items, caps, band: str):
    """Restrict sub-GHz scan rows to a named ISM band (client-side, using caps.meta.bands).

    A band the protocol does not advertise is a clean `ProbeError` rather than a silent
    empty result. Rows whose `freq` falls in [lo, hi] are kept; rows without a `freq` pass
    through unfiltered (we do not drop data we cannot authoritatively place)."""
    bands = {str(x.get("name")): x for x in caps.meta.get("bands", [])}
    spec = bands.get(str(band))
    if spec is None:
        known = ", ".join(bands) or "(none advertised)"
        raise ProbeError(f"unknown sub-GHz band {band!r} (known: {known})")
    lo, hi = spec.get("lo"), spec.get("hi")
    if lo is None or hi is None:
        return items
    out = []
    for it in items:
        f = it.get("freq")
        if f is None or lo <= f <= hi:
            out.append(it)
    return out


def _radio_channel(args) -> int | None:
    """Resolve sub-GHz `--freq` to the int-channel field (center frequency in Hz)."""
    from .protocols import subghz
    if getattr(args, "freq", None):
        return subghz.parse_freq(args.freq)
    return args.channel


def _build_inject(b, args) -> tuple[bytes, int | None]:
    """Build the frame and channel for `inject`.

    On a sub-GHz (PACKET radio) protocol, `--freq`/`--mod` build the 8-byte pseudo-header
    around the `--hex` payload so the transmitted frame self-describes its radio params; the
    frequency also resolves to the int-channel. On every other protocol the bytes are injected
    verbatim (`--hex` or a frame file)."""
    proto = b.capabilities().protocol
    if proto == "subghz" and getattr(args, "freq", None):
        from .protocols import subghz
        if not args.hex:
            raise ProbeError("subghz inject needs --hex <payload> together with --freq")
        if not args.mod:
            raise ProbeError("subghz inject needs --mod (ook|ask|2fsk|gfsk) together with --freq")
        rate = args.rate if args.rate is not None else subghz.DEFAULT_RATE
        frame = subghz.encode_frame(_parse_hex(args.hex, "inject --hex"), args.freq, args.mod, rate)
        return frame, subghz.parse_freq(args.freq)
    if args.hex:
        return _parse_hex(args.hex, "inject --hex"), args.channel
    with open(args.read, "rb") as fh:
        return fh.read(), args.channel


def _dispatch_jtag(args, b) -> None:
    from .protocols import jtag
    from .core.fields import as_int
    cmd = args.jtag_cmd
    if cmd == "scan-chain":
        for tap in jtag.taps(b):           # already coerced + malformed rows dropped
            print(f"[{tap['index']}] idcode=0x{tap['idcode']:08x}  "
                  f"irlen={tap['irlen']}  {tap['name']}".rstrip())
    elif cmd == "idcode":
        r = jtag.idcode(b, tap=args.tap)
        print(f"idcode=0x{as_int(r.get('idcode', 0), 'idcode'):08x}  "
              f"mfg={r.get('manufacturer', '')}  part={r.get('part', '')}  "
              f"name={r.get('name', '')}")
    elif cmd == "halt":
        r = jtag.halt(b, tap=args.tap)
        pc = r.get("pc")
        print(f"state={r.get('state', '')}"
              + (f"  pc=0x{as_int(pc, 'pc'):08x}" if pc is not None else ""))
    elif cmd == "resume":
        addr = _parse_int(args.addr, "address") if args.addr is not None else None
        print(f"state={jtag.resume(b, tap=args.tap, addr=addr).get('state', '')}")
    elif cmd == "read":
        addr = _parse_int(args.addr, "address")
        for i, w in enumerate(jtag.read_words(b, addr, count=args.words)):
            print(f"0x{addr + i * 4:08x}: 0x{w:08x}")
    elif cmd == "write":
        addr = _parse_int(args.addr, "address")
        word = _parse_int(args.word, "word")
        _report_write(jtag.write(b, addr, word), "write")
    elif cmd == "reg":
        r = jtag.reg(b, name=args.name)
        regs = r.get("regs")
        if isinstance(regs, dict):
            for name, val in regs.items():
                print(f"{name} = 0x{as_int(val, f'reg {name}'):08x}")
        else:
            print(f"{r.get('name', '')} = 0x{as_int(r.get('value', 0), 'reg value'):08x}")
    elif cmd == "dump":
        addr = _parse_int(args.addr, "address")
        length = _parse_int(args.len, "length")
        n = jtag.dump(b, addr, length, args.write, pcap_path=args.pcap)
        print(f"dumped {n} byte(s) -> {args.write}"
              + (f" (pcap -> {args.pcap})" if args.pcap else ""))


def _dispatch_spi(args, b) -> None:
    from .protocols import spi
    cmd = args.spi_cmd
    if cmd == "id":
        from .core.fields import as_int
        r = spi.device_id(b, cs=args.cs)
        jedec = r.get("jedec_id", 0)
        jedec_s = jedec if isinstance(jedec, str) else f"0x{as_int(jedec, 'jedec_id'):06x}"
        print(f"jedec={jedec_s}  mfg={r.get('manufacturer', '')}  "
              f"capacity={r.get('capacity', '')}  name={r.get('name', '')}")
    elif cmd == "read":
        addr = _parse_int(args.addr, "address")
        length = _parse_int(args.len, "length")
        print(_fmt_value(spi.read(b, addr, length, cs=args.cs).get("data", ""), "spi.read data"))
    elif cmd == "write":
        addr = _parse_int(args.addr, "address")
        _parse_hex(args.hex, "spi write --hex")     # validate operator hex at source, clean error
        _report_write(spi.write(b, addr, args.hex, cs=args.cs), "write")
    elif cmd == "reg":
        if args.write is not None:
            _report_write(spi.reg(b, args.name, value_hex=args.write, cs=args.cs), "register write")
        else:
            r = spi.reg(b, args.name, cs=args.cs)
            print(f"{r.get('name', args.name)} = {r.get('value', '')}")
    elif cmd == "xfer":
        print(spi.xfer(b, args.hex, cs=args.cs).get("miso", ""))
    elif cmd == "dump":
        addr = _parse_int(args.addr, "address")
        length = _parse_int(args.len, "length")
        n = spi.dump(b, length, args.write, addr=addr, cs=args.cs, pcap_path=args.pcap)
        print(f"dumped {n} byte(s) -> {args.write}"
              + (f" (pcap -> {args.pcap})" if args.pcap else ""))


def _dispatch_subghz(args, b) -> None:
    from .protocols import subghz
    cmd = args.subghz_cmd
    if cmd == "demod":
        r = subghz.demod(b, capture=args.read)
        print(f"modulation={r.get('modulation', '')}  bitrate={r.get('bitrate', '')}  "
              f"encoding={r.get('encoding', '')}  confidence={r.get('guess_conf', '')}")
    elif cmd == "bands":
        for band in subghz.band_list(b):           # coerced; non-dict rows dropped
            print(f"{band.get('name', '')}: {band.get('lo', '')}..{band.get('hi', '')} Hz  "
                  f"default={band.get('default', '')}")


def _resolve_handle(b, arg: str) -> int:
    """Accept a numeric handle (0x0011 / 17) or a characteristic uuid (fff1)."""
    try:
        return int(arg, 0)
    except ValueError:
        from .core.fields import as_int
        from .protocols import ble
        for c in ble.gatt_enum(b).get("characteristics", []) or []:
            if not isinstance(c, dict):
                continue
            if str(c.get("uuid", "")).lower() == arg.lower():
                return as_int(c.get("handle", 0), "gatt handle")
        raise SystemExit(f"probe: no characteristic with handle/uuid {arg!r}")


def _layer(flag, env, conf, default):
    """First non-empty of flag > env > config, else the built-in default, with its SOURCE label.

    Returns `(value, source)` where `source` is one of "flag" / "env" / "config" / "default".
    The source is load-bearing, not cosmetic: a value that resolved from the CONFIG FILE is
    surfaced to the operator before a backend opens (see _config_source_notice), so a stale
    `probe use` default can never silently redirect an expected-virtual write onto real hardware.
    """
    if flag is not None and flag != "":
        return flag, "flag"
    if env is not None and env != "":
        return env, "env"
    if conf is not None and conf != "":
        return conf, "config"
    return default, "default"


def _resolve_config_defaults(args, cfg: dict) -> None:
    """Fold flag > env > config file > built-in default into `args`, in place.

    `args.<x>` is None iff the user did not pass the flag (the sentinel defaults). With NO config
    file present this reproduces the historical env-or-default behaviour exactly (regression
    contract): the config layer only ever fills a slot both the flag and the env left empty.

    The SOURCE of the resolved backend/target is stashed on `args` (`_backend_source` /
    `_target_source`) so the opener can name a config-sourced value to the operator. Tracking the
    source changes no resolved VALUE, so the no-config path stays byte-identical to before.
    """
    args.backend, args._backend_source = _layer(
        args.backend, os.environ.get("ESP_PROBE_BACKEND"), cfg.get("backend"), "virtual")
    args.target, args._target_source = _layer(
        args.target, os.environ.get("ESP_PROBE_TARGET"), cfg.get("target"), None)
    if args.baud is None:
        args.baud = cfg.get("baud", 115200)
    # Stash for _dispatch's scan-seconds resolution (config sits below $ESP_PROBE_SCAN_SECS).
    args._cfg = cfg


def _config_source_notice(args) -> None:
    """Warn on stderr, BEFORE a backend opens, when the resolved backend/target came from the
    CONFIG FILE, or when $ESP_PROBE is set but will be ignored because a config value shadowed it.

    This is the anti-surprise guard for the redirect hazard behind the BLOCKER: a stale
    `probe use` default (e.g. `{"backend":"hci","target":"my-lock"}`) silently shadows an operator
    who exported `ESP_PROBE=tcp://...` expecting the virtual endpoint, so a `gatt write` they
    believe hits the in-process virtual model instead writes a real peripheral's RX with no signal.
    Naming the source + path makes that redirect impossible to miss.

    It fires ONLY on a config-sourced backend/target (or a config value that shadows $ESP_PROBE),
    so a run with NO config file emits nothing and stays byte-identical to before (the regression
    contract). Flags and $ESP_PROBE_*/env are explicit per-invocation/per-shell operator intent and
    are deliberately NOT nagged about. Called on every verb that actually opens a backend to talk to
    a target (info included, as the diagnostic); `use`/`wizard` return before this and stay quiet.
    """
    path = config.config_path()
    backend_src = getattr(args, "_backend_source", None)
    target_src = getattr(args, "_target_source", None)

    from_config = []
    if backend_src == "config":
        from_config.append(f"backend {args.backend!r}")
    if target_src == "config":
        from_config.append(f"target {args.target!r}")
    if from_config:
        print(f"probe: using {' '.join(from_config)} from {path} "
              f"(override with --backend/--target or 'probe use --clear')", file=sys.stderr)

    # $ESP_PROBE (the documented virtual endpoint) is read by VirtualBackend ONLY when the backend
    # is virtual AND no target was resolved above it. If it is set but a CONFIG value steered us off
    # that path, say so explicitly rather than silently ignoring the endpoint the operator exported.
    esp_probe = os.environ.get("ESP_PROBE")
    if not esp_probe:
        return
    if args.backend == "virtual" and args.target is None:
        return                                  # $ESP_PROBE is actually in use; nothing to warn
    if args.backend != "virtual" and backend_src == "config":
        why = f"config sets backend {args.backend!r} (not virtual)"
    elif args.backend == "virtual" and args.target is not None and target_src == "config":
        why = f"config sets target {args.target!r}"
    else:
        return                                  # shadowed by an explicit flag/env: intended, quiet
    print(f"probe: $ESP_PROBE is set ({esp_probe!r}) but not being used: {why} "
          f"(clear it with 'probe use --clear' or override with --backend/--target)",
          file=sys.stderr)


def _print_friendly_help() -> None:
    """Bare `probe` on a non-tty: a friendly nudge + copy-pasteable examples (never input())."""
    print("probe - one CLI for the physical layer.")
    print("Run `probe` in a terminal for a guided wizard, or use a verb directly:")
    print("  probe info                   # backend, protocol, and capabilities")
    print("  probe scan                   # see what is on the protocol")
    print("  probe use hci --target NAME  # remember a default backend/target")
    print("  probe use --show             # show the stored + effective defaults")
    print("  probe --help                 # the full command list")


def _cmd_use(args, cfg: dict) -> int:
    """`probe use`: persist/show/clear client defaults. Opens no backend, connects to nothing."""
    writes: dict = {}
    if args.use_backend is not None:
        writes["backend"] = args.use_backend
    if args.use_target is not None:
        writes["target"] = args.use_target
    if args.use_baud is not None:
        writes["baud"] = args.use_baud
    if args.use_scan_secs is not None:
        writes["scan_secs"] = args.use_scan_secs

    if (args.use_show or args.use_clear) and writes:
        raise SystemExit("probe: use --show/--clear cannot be combined with a write argument")

    if args.use_clear:
        removed = config.clear()
        print(f"cleared {config.config_path()}" if removed else "nothing to clear")
        return 0
    if args.use_show or not writes:
        # `probe use` with no write keys shows the current state (the least-surprising help for a
        # curious newbie); `--show` does the same explicitly.
        return _use_show(args, cfg)

    if "baud" in writes and writes["baud"] <= 0:
        raise SystemExit(f"probe: baud must be > 0 (got {writes['baud']})")
    if "scan_secs" in writes and writes["scan_secs"] <= 0:
        raise SystemExit(f"probe: --scan-secs must be > 0 (got {writes['scan_secs']:g})")
    config.save(writes)
    print("saved " + ", ".join(f"{k}={v}" for k, v in writes.items())
          + f" -> {config.config_path()}")
    return 0


def _use_show(args, cfg: dict) -> int:
    import json
    path = config.config_path()
    print(f"config: {path}")
    print(f"  stored: {json.dumps(cfg, sort_keys=True)}")
    print("  effective:")
    for key, value, source in config.effective(args, cfg):
        if key == "scan_secs" and source == "default":
            print(f"      {key:<9} = (medium default)")
        else:
            disp = "(none)" if value is None else value
            print(f"      {key:<9} = {str(disp):<10} ({source})")
    print("  (note: backend/target also read $ESP_PROBE_BACKEND/$ESP_PROBE_TARGET; the virtual "
          "backend falls back to $ESP_PROBE (tcp://host:port) only when no target is set above it; "
          "baud has no env var)")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = config.load()

    if args.verb is None:
        # Bare `probe`: an interactive terminal gets the wizard; a piped/CI invocation gets help.
        # Check BOTH stdin and stdout so `probe > log` never drops into a menu it cannot show, and
        # NEVER call input() on a non-tty (it would hang a pipeline).
        if sys.stdin.isatty() and sys.stdout.isatty():
            from . import wizard
            return wizard.run(cfg)
        _print_friendly_help()
        return 0

    if args.verb == "demo":
        # A self-contained onboarding tour: spins a bundled toy target and drives it. Opens no
        # user backend and needs no ESP_PROBE / hardware, so it runs straight after install.
        from . import demo
        return demo.run()

    if args.verb == "use":
        return _cmd_use(args, cfg)

    if args.verb == "wizard":
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            raise SystemExit("probe: wizard needs an interactive terminal (stdin/stdout are not a tty)")
        from . import wizard
        return wizard.run(cfg)

    _resolve_config_defaults(args, cfg)
    _config_source_notice(args)
    backend = _make_backend(args.backend, args.target, baud=args.baud)
    try:
        backend.open()
    except Exception as e:
        raise SystemExit(f"probe: cannot connect: {e}")
    try:
        return _dispatch(args, backend)
    except NotImplementedError as e:
        # A backend that defensively refused a verb the gate did not catch. Render clean.
        verb = str(e) or "operation"
        raise SystemExit(f"probe: '{verb}' is not supported by this backend")
    except (ProbeError, wire.ProtocolError, RuntimeError, OSError, ValueError,
            AttributeError, TypeError, KeyError, struct.error, OverflowError) as e:
        # AttributeError/TypeError/KeyError/struct.error/OverflowError are a backstop: a malformed
        # backend response is partly attacker-influenced with a remote target, and the protocol
        # layer must already refuse it cleanly (a hostile ts is coerced in Frame.from_msg and
        # clamped in PcapWriter, never reaching struct.pack or a float() overflow). If any future
        # path still lets a malformed value through, it surfaces here as a clean `probe: ...`
        # line, never a raw traceback.
        raise SystemExit(f"probe: {e}")
    finally:
        backend.close()


if __name__ == "__main__":
    main()
