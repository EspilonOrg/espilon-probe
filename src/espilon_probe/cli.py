"""probe CLI - parse, select a backend, dispatch verbs, print results.

Target selection:
  - default backend `virtual`, reading the target endpoint from ESP_PROBE (tcp://host:port)
  - `--backend socketcan|serial` selects a real adapter (implemented)
  - `--backend hci|killerbee|sdr|openocd|ftdi` selects a real adapter (planned)

Core verbs: info, scan, sniff, inject, replay
Protocol verbs: gatt (BLE), can, uart, jtag, spi, subghz
"""

from __future__ import annotations

import argparse

from .core import wire
from .core.errors import ProbeError


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
    p.add_argument("--backend", default="virtual",
                   help="virtual (default) | hci | killerbee | sdr | serial | openocd | ftdi | socketcan")
    p.add_argument("--target", help="backend endpoint (default: ESP_PROBE for virtual)")
    p.add_argument("--baud", type=int, default=115200,
                   help="UART line rate (default 115200). On a real line a wrong baud is "
                        "physically garbage; the virtual backend models the same effect.")
    sub = p.add_subparsers(dest="verb", required=True)

    sub.add_parser("info", help="show backend, protocol, channels, capabilities")
    scn = sub.add_parser("scan", help="enumerate what is on the protocol")
    scn.add_argument("--band", help="sub-GHz: ISM band to sweep (e.g. 433|868|915)")

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
    us.add_parser("read", help="read available output")

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
        from .backends.socketcan import SocketCanBackend
        return SocketCanBackend(target)
    if name == "serial":
        from .backends.serial import SerialBackend
        return SerialBackend(target, baud=baud)
    raise SystemExit(f"probe: backend '{name}' is not implemented yet (hardware backends = hci/sdr/openocd/ftdi).")


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
    """
    if verb not in caps.verbs:
        supported = ", ".join(caps.verbs) or "(none)"
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
            items = _scan_rows(b.scan())
            if getattr(args, "band", None):
                items = _filter_band(items, caps, args.band)
        if not items:
            print("(nothing on the protocol)")
        else:
            for it in items:
                cols = [str(it.get(k, "")) for k in ("name", "addr", "rssi")]
                extra = {k: x for k, x in it.items() if k not in ("name", "addr", "rssi")}
                line = "  ".join(c for c in cols if c)
                print(line + (f"   {extra}" if extra else ""))
    elif v == "sniff":
        # sub-GHz tunes the capture by frequency: --freq resolves to the int-channel field.
        channel = _radio_channel(args) if getattr(args, "freq", None) else args.channel
        n = b.sniff(args.write, count=args.count, seconds=args.seconds, channel=channel)
        print(f"captured {n} frame(s) -> {args.write}")
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
            n = b.sniff(args.write, count=args.count, seconds=args.seconds)
            print(f"captured {n} frame(s) -> {args.write}")
    elif v == "uart":
        from .protocols import uart
        if args.uart_cmd == "write":
            uart.write(b, args.data.encode())
            print("sent")
        elif args.uart_cmd == "read":
            print(uart.read(b).decode(errors="replace"), end="")
    elif v == "gatt":
        if args.gatt_cmd == "enum":
            for c in ble.gatt_enum(b).get("characteristics", []):
                print(f"0x{c['handle']:04x}  {c['uuid']}  {c['props']}")
        elif args.gatt_cmd == "read":
            h = _resolve_handle(b, args.handle)
            res = ble.gatt_read(b, h)
            # An unreadable/unknown handle must not print a silent empty line. We require an
            # authoritative `value` key: a result that omits it is refused loud rather than
            # rendered as an empty read (which is indistinguishable from a real empty value).
            if not isinstance(res, dict) or "value" not in res:
                raise ProbeError(f"no such handle 0x{h:04x} (handle not readable)")
            print(_fmt_value(res.get("value", ""), "gatt.read value"))
        elif args.gatt_cmd == "write":
            h = _resolve_handle(b, args.handle)
            _report_write(ble.gatt_write(b, h, args.value), "write")
    elif v == "jtag":
        _dispatch_jtag(args, b)
    elif v == "spi":
        _dispatch_spi(args, b)
    elif v == "subghz":
        _dispatch_subghz(args, b)
    return 0


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
        from .protocols import ble
        for c in ble.gatt_enum(b).get("characteristics", []):
            if str(c.get("uuid", "")).lower() == arg.lower():
                return int(c["handle"])
        raise SystemExit(f"probe: no characteristic with handle/uuid {arg!r}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
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
            AttributeError, TypeError, KeyError) as e:
        # AttributeError/TypeError/KeyError are a backstop: a malformed backend response is
        # partly attacker-influenced with a remote target, and the protocol layer must already
        # refuse it cleanly. If any future path still lets a malformed dict through, it
        # surfaces here as a clean `probe: ...` line, never a raw traceback.
        raise SystemExit(f"probe: {e}")
    finally:
        backend.close()


if __name__ == "__main__":
    main()
