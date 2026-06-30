"""probe CLI - parse, select a backend, dispatch verbs, print results.

Target selection:
  - default backend `virtual`, reading the lab endpoint from ESP_PROBE (tcp://host:port)
  - `--backend hci|killerbee|sdr|serial|openocd|ftdi|socketcan` selects a real adapter
    (not implemented yet; Phase 3+).

Core verbs: info, scan, sniff, inject, replay
Protocol verbs: gatt (BLE) - enum / read / write
"""

from __future__ import annotations

import argparse

from .core import wire
from .core.errors import ProbeError


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="probe", description="One CLI for the physical layer.")
    p.add_argument("--backend", default="virtual",
                   help="virtual (lab, default) | hci | killerbee | sdr | serial | openocd | ftdi | socketcan")
    p.add_argument("--target", help="backend endpoint (default: ESP_PROBE for virtual)")
    p.add_argument("--baud", type=int, default=115200,
                   help="UART line rate (default 115200). On a real line a wrong baud is "
                        "physically garbage; the virtual backend models the same effect.")
    sub = p.add_subparsers(dest="verb", required=True)

    sub.add_parser("info", help="show backend, protocol, channels, capabilities")
    sub.add_parser("scan", help="enumerate what is on the protocol")

    sn = sub.add_parser("sniff",
                        help="capture frames to a standard pcap "
                             "(client-bounded; default ceiling 30s if no -c/-t given)")
    sn.add_argument("-w", "--write", required=True, metavar="PCAP")
    sn.add_argument("-c", "--count", type=int)
    sn.add_argument("-t", "--seconds", type=float)
    sn.add_argument("--channel", type=int)

    inj = sub.add_parser("inject", help="transmit one raw frame")
    g = inj.add_mutually_exclusive_group(required=True)
    g.add_argument("--hex")
    g.add_argument("-r", "--read", metavar="FRAME")
    inj.add_argument("--channel", type=int, help="channel to transmit on (protocols that support it)")

    rp = sub.add_parser("replay", help="re-transmit frames from a pcap (pre-filter with tshark -w)")
    rp.add_argument("-r", "--read", required=True, metavar="PCAP")

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


def _fmt_value(hexstr: str) -> str:
    raw = bytes.fromhex(hexstr) if hexstr else b""
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
}
# `can` is sugar over the core verbs (send -> inject, dump -> sniff), so its sub-commands
# gate on the underlying core verb rather than a "can" group that backends do not advertise.
_CAN_REQUIRES = {"send": "inject", "dump": "sniff"}


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
              f"channels: {','.join(map(str, c.channels))}   verbs: {','.join(c.verbs)}")
    elif v == "scan":
        items = b.scan()
        if not items:
            print("(nothing on the protocol)")
        else:
            for it in items:
                cols = [str(it.get(k, "")) for k in ("name", "addr", "rssi")]
                extra = {k: x for k, x in it.items() if k not in ("name", "addr", "rssi")}
                line = "  ".join(c for c in cols if c)
                print(line + (f"   {extra}" if extra else ""))
    elif v == "sniff":
        n = b.sniff(args.write, count=args.count, seconds=args.seconds, channel=args.channel)
        print(f"captured {n} frame(s) -> {args.write}")
    elif v == "inject":
        if args.hex:
            frame = bytes.fromhex(args.hex)
        else:
            with open(args.read, "rb") as fh:
                frame = fh.read()
        b.inject(frame, channel=args.channel)
        print("injected")
    elif v == "replay":
        print(f"replayed {b.replay(args.read)} frame(s)")
    elif v == "can":
        from .protocols import can
        if args.can_cmd == "send":
            can.send(b, int(args.id, 0), args.data)
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
            print(_fmt_value(ble.gatt_read(b, h).get("value", "")))
        elif args.gatt_cmd == "write":
            h = _resolve_handle(b, args.handle)
            res = ble.gatt_write(b, h, args.value)
            if res.get("ok"):
                extra = {k: v for k, v in res.items() if k != "ok"}
                print("ok" + (f" {extra}" if extra else ""))
            else:
                print(str(res))
    return 0


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
    except (ProbeError, wire.ProtocolError, RuntimeError, OSError, ValueError) as e:
        raise SystemExit(f"probe: {e}")
    finally:
        backend.close()


if __name__ == "__main__":
    main()
