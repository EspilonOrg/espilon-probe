"""probe-bridge - the generic real/loopback bridge entry point (docs/design/02-bridge-contract.md).

    probe-bridge --medium serial --endpoint /dev/ttyUSB0 --listen 127.0.0.1:0

opens the medium, binds a TCP listener, announces the chosen port, then serves the wire tunnel
against that medium as a PERSISTENT daemon (docs/design/00 decision 5): it holds the medium open and its
RX FIFO across the discrete per-verb `probe` connections, retiring on an idle timeout or when the
medium goes away. Invoked two ways, same code:

  - auto-spawned + detached on loopback by `probe --backend serial --target <path>` (the first
    invocation spawns it; later invocations for the same target connect to the running one);
  - run long-lived near hardware (or for the conformance harness, over a pty).

The client never imports this; it spawns it as a subprocess (`python -m espilon_probe.bridges`),
so the client core stays stdlib-only (docs/design/02 section 4).
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .server import BridgeServer

# Emitted on stdout once the listener is bound (for a foreground/interactive run); the
# machine-readable rendezvous for a launcher is the --announce file.
READY_PREFIX = "PROBE_BRIDGE_LISTENING"

# Default daemon idle lifetime: retire after this many seconds with no client connection, so an
# auto-spawned bridge can never leak. Overridable with --idle-timeout (<=0 disables).
DEFAULT_IDLE_TIMEOUT = 120.0


def _make_medium(name: str, endpoint: str, baud: int, reset_on_open: bool = False):
    if name == "serial":
        from .media.serial import SerialMedium
        return SerialMedium(endpoint, baud=baud, reset_on_open=reset_on_open)
    if name == "socketcan":
        from .media.socketcan import CanMedium
        return CanMedium(endpoint)
    if name == "hci":
        # Real BLE central over BlueZ (bleak), behind the [hci] extra. The import of bleak is LAZY,
        # inside HciMedium, so selecting hci here without the extra installed fails with a clear,
        # actionable error and NOTHING imports bleak at module load (docs/design/ble-gatt.md
        # section 7). The medium owns an asyncio loop thread + one persistent BleakClient to the
        # target and the D-Bus-error -> ATT-code map.
        from .media.hci import HciMedium
        return HciMedium(endpoint)
    # Other hardware media (ftdi, openocd, sdr, killerbee...) land later, each importing its own
    # optional dependency lazily inside its module. Refuse clean until then.
    raise SystemExit(f"probe-bridge: medium {name!r} is not implemented yet")


def _parse_listen(listen: str) -> tuple[str, int]:
    host, _, port = listen.rpartition(":")
    if not host:
        raise SystemExit(f"probe-bridge: bad --listen {listen!r} (expected host:port)")
    try:
        return host, int(port)
    except ValueError:
        raise SystemExit(f"probe-bridge: bad --listen {listen!r} (port not a number)")


def _write_announce(path: str, port: int) -> None:
    """Atomically publish {port, pid} so a launcher can discover a running daemon by --target."""
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"port": port, "pid": os.getpid()}, fh)
    os.replace(tmp, path)


def _remove_announce(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="probe-bridge",
                                 description="Generic bridge: terminate the probe wire tunnel into a real medium.")
    ap.add_argument("--medium", required=True, help="serial (pilot) | socketcan | ftdi | ... (later)")
    ap.add_argument("--endpoint", required=True, help="device/interface (e.g. /dev/ttyUSB0, /dev/pts/3)")
    ap.add_argument("--listen", default="127.0.0.1:0", help="TCP listen address (default 127.0.0.1:0)")
    ap.add_argument("--baud", type=int, default=115200, help="line rate for a real tty (default 115200)")
    ap.add_argument("--announce", metavar="PATH",
                    help="atomically write {port,pid} here when bound (removed on exit)")
    ap.add_argument("--idle-timeout", type=float, default=DEFAULT_IDLE_TIMEOUT,
                    help="retire after N idle seconds with no connection (<=0 disables)")
    ap.add_argument("--reset-on-open", action="store_true",
                    help="pulse DTR/RTS to reset the board after opening (capture a boot-only banner)")
    args = ap.parse_args(argv)

    host, port = _parse_listen(args.listen)
    medium = _make_medium(args.medium, args.endpoint, args.baud, reset_on_open=args.reset_on_open)
    try:
        medium.open()
    except Exception as e:
        print(f"probe-bridge: {e}", file=sys.stderr, flush=True)
        return 1

    server = BridgeServer(medium, host, port)
    try:
        bound = server.bind()
    except OSError as e:
        medium.close()
        print(f"probe-bridge: cannot bind {args.listen}: {e}", file=sys.stderr, flush=True)
        return 1

    # The endpoint is already open by this point, which the conformance harness relies on for
    # ordering (it boots the device only after the bridge is up so the banner is captured, not lost
    # to a closed fd). Announce, then serve.
    if args.announce:
        _write_announce(args.announce, bound)
    print(f"{READY_PREFIX} {bound}", flush=True)

    idle_timeout = args.idle_timeout if args.idle_timeout and args.idle_timeout > 0 else None
    liveness = getattr(medium, "alive", None)
    try:
        server.serve_forever(idle_timeout=idle_timeout, liveness=liveness)
    finally:
        server.close()
        medium.close()
        if args.announce:
            _remove_announce(args.announce)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
