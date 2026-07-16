"""hci medium: real BLE GATT central over BlueZ via bleak, behind the optional [hci] extra.

The transaction-medium twin of `conformance.virtual_gatt_bridge.GattOpMedium` (docs/protocols/
ble-gatt.md sections 2, 4.3): the SAME `BridgeServer._serve_op` drives either, so virtual vs real is
a medium substitution. Here the medium drives the OS BLE stack (BlueZ, via bleak) instead of the
in-process `GattServer` model.

Two capabilities, both request/response:

  - `scan()` - an ACTIVE central scan that accumulates DISTINCT advertisements over a bounded window
    and surfaces each advertiser's manufacturer_data (company id + raw bytes). A central sees only
    advertising + its own connections; it is NOT a passive sniffer, so there is no sniff/inject/replay
    (docs/design/ble-gatt.md section 6). Advertisements are keyed by (address, manufacturer-data
    payload) so a peripheral that rotates its BLE address every event still yields one entry per
    distinct payload instead of collapsing under address-dedup.
  - `op(verb, args)` - GATT enum/read/write over ONE PERSISTENT `BleakClient`. The connection is
    established lazily on the first gatt op and HELD for the medium's lifetime, so read-STATUS ->
    write -> read-FLAG across separate `probe` processes all ride the same BLE link and the
    peripheral's per-connection state survives (docs/design/ble-gatt.md section 4.3). This is more
    load-bearing than the serial/CAN daemon persistence: the thing that persists is a live radio link.

bleak is async; this medium owns ONE asyncio event loop in a daemon thread and marshals the sync
`op()`/`scan()` calls onto it (`run_coroutine_threadsafe`), keeping the `BleakClient` alive on that
loop. bleak is imported LAZILY inside `__init__`, so:

  - the client core, the virtual bridge, and the whole virtual conformance leg never touch bleak;
  - `python -m espilon_probe.bridges --medium hci ...` selected WITHOUT the extra fails with one
    clear, actionable line instead of an ImportError traceback;
  - the test suite never needs bleak or a BlueZ stack.

ATT error CODES are the one bleak-path fidelity risk (docs/design/ble-gatt.md sections 2, 6): BlueZ
hides the raw ATT error behind D-Bus error names. The name->code map here is CONSERVATIVE - only names
we can interpret authoritatively become an ATT `{error: <code>}` (read/write NotPermitted -> 0x02/0x03
by operation context, and a small crisp set); ANY other bleak fault becomes a clean wire ERROR (never
a guessed code, never a traceback). Guessing an ATT code we cannot authoritatively derive would be a
silent-pass hazard, so unknown faults fail loud.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import re
import struct
import threading

from ...core.fields import as_int, hex_bytes
from ...protocols import ble

# The actionable hint printed when hci is selected without bleak / a BlueZ adapter.
_INSTALL_HINT = (
    "the hci BLE medium needs the optional [hci] extra: pip install 'espilon-probe[hci]' "
    "(bleak over BlueZ), a Bluetooth adapter, and the peripheral. "
    "The virtual GATT leg needs none of these - use `probe --backend virtual`.")

# The endpoint sentinel a scan-only spawn carries: `probe --backend hci scan` needs no target
# peripheral, so the backend passes this and `op()` refuses a gatt verb against it (a gatt op needs a
# real --target). scan() works regardless: it connects to nothing.
NO_TARGET = "any"

# Bounded windows/deadlines. scan listens for an active-scan window that DEFAULTS to _SCAN_WINDOW but
# the operator can override per invocation: the SCAN wire verb now carries an OPTIONAL `seconds`
# (listen window) and `count` (stop once N distinct advertisements seen), so a quick look (`scan -t 1`)
# and a long rotating-address fob-collection run (`scan -t 15`) are both possible without a code edit.
# 3.0s is the default: long enough to catch typical BLE advertising intervals (100ms-1s) yet snappy,
# where the old fixed 6s was a needless wall. The gatt op deadline is kept below the client's default
# 30s transaction timeout so the medium's own timeout fires FIRST with a clean error rather than the
# client giving up on a still-working daemon.
_SCAN_WINDOW = 3.0
_NAME_RESOLVE_TIMEOUT = 8.0
_CONNECT_TIMEOUT = 15.0
_OP_TIMEOUT = 28.0
_SCAN_MARGIN = 6.0
# How long a timed-out `_run` waits for the loop to actually retire the cancelled coroutine before
# giving up. Bounded so a BLE stack that ignores cancellation cannot re-wedge the daemon here.
_CANCEL_DRAIN_TIMEOUT = 2.0

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")

# BlueZ D-Bus GATT error name (suffix, lowercased) -> ATT code. CONSERVATIVE and authoritative: only
# names whose ATT meaning is unambiguous are here. `notpermitted` is context-sensitive (a read of a
# write-only char -> 0x02, a write of a read-only char -> 0x03), flagged with _PERM. Everything not in
# this table is surfaced as a clean wire ERROR, NEVER guessed into an ATT code.
_PERM = object()
_DBUS_ATT = {
    "notpermitted": _PERM,          # read -> 0x02 Read Not Permitted, write -> 0x03 Write Not Permitted
    "invalidhandle": 0x01,          # ATT Invalid Handle, if BlueZ ever surfaces it as a D-Bus error
    "invalidoffset": 0x07,
    "invalidvaluelength": 0x0D,
    "notsupported": 0x06,           # Request Not Supported
}


def _att_code(exc: BaseException, is_write: bool) -> int | None:
    """The ATT code for a bleak exception, or None when we cannot authoritatively derive one.

    The STRUCTURED `BleakDBusError.dbus_error` attribute is the ONLY authoritative source. A
    free-text scrape of the exception message is deliberately NOT consulted: a bleak message is
    unstructured English that could coincidentally contain an `org.bluez.Error.<Name>` token from
    an unrelated context, and mapping that into a specific ATT code would be a silent-pass hazard
    the conformance diff could not catch. A fault with no `dbus_error` attribute (or an unmapped
    name) returns None, meaning "surface a clean wire ERROR", never a fabricated ATT code."""
    name = getattr(exc, "dbus_error", None)
    if not isinstance(name, str):
        return None
    code = _DBUS_ATT.get(name.rsplit(".", 1)[-1].lower())
    if code is _PERM:
        return 0x03 if is_write else 0x02   # Write Not Permitted / Read Not Permitted (ble.ATT_ERRORS)
    return code


async def _cancel_and_wait(task) -> None:
    """Cancel `task` from within the loop and await it to a settled state, so a timed-out op never
    leaves a pending Task behind (which would leak a 'Task was destroyed but it is pending' warning
    when the loop closes). The CancelledError the await re-raises is expected and swallowed."""
    task.cancel()
    try:
        await task
    except BaseException:
        pass


def _encode_mfg(manufacturer_data: dict | None) -> str:
    """Reconstruct the raw manufacturer-data AD bytes as hex: for each company id, the 2-byte LE
    company id followed by its payload, concatenated over all company ids (sorted for determinism).

    This is the on-air manufacturer-specific data verbatim, so a caller recovers per advertisement the
    company id (first 2 bytes, LE) and the exact vendor payload. Empty when the advertiser carried no
    manufacturer data."""
    if not manufacturer_data:
        return ""
    out = bytearray()
    for cid in sorted(manufacturer_data):
        out += struct.pack("<H", int(cid) & 0xFFFF) + bytes(manufacturer_data[cid])
    return out.hex()


class HciMedium:
    """Transaction medium over the OS BLE stack (BlueZ via bleak). Owns one asyncio loop thread and,
    for gatt, one persistent BleakClient to `endpoint`."""

    shape = "transaction"

    def __init__(self, endpoint: str):
        self.endpoint = endpoint or NO_TARGET   # the peripheral address / name (or NO_TARGET for scan)
        try:
            import bleak
        except ImportError as e:
            raise SystemExit(f"probe-bridge: {_INSTALL_HINT}") from e
        self._bleak = bleak
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._client = None                     # the held BleakClient once a gatt op connects
        self._lock = threading.Lock()           # serialize op()/scan() marshalling onto the loop
        self._closed = False

    # --- lifecycle --------------------------------------------------------------------------------

    def open(self) -> None:
        """Start the asyncio event loop in a daemon thread. Does NOT connect: scan needs no target,
        and a gatt op connects lazily and then HOLDS the link (docs/design/ble-gatt.md 4.3)."""
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, name="hci-loop", daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout=5.0):
            raise RuntimeError("hci medium event loop did not start")

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.call_soon(self._ready.set)
        try:
            self._loop.run_forever()
        finally:
            self._loop.close()

    def _run(self, coro, timeout: float):
        """Marshal a coroutine onto the loop thread and wait for its result under `timeout`.

        A timeout cancels the coroutine and raises a clean RuntimeError (which _serve_op renders as a
        wire ERROR), so a wedged BLE stack fails loud instead of holding the single-serving daemon."""
        loop = self._loop
        if loop is None or not loop.is_running():
            raise RuntimeError("hci medium loop is not running")
        # Wrap the coroutine so we can expose its Task: on a timeout, cancelling the concurrent
        # future alone marks the future cancelled WITHOUT waiting for the underlying Task to unwind,
        # which leaves it pending and leaks a "Task was destroyed but it is pending" warning onto the
        # daemon stderr when the loop later closes. Holding the Task lets us cancel it and AWAIT it.
        task_ref: concurrent.futures.Future = concurrent.futures.Future()

        async def _tracked():
            task_ref.set_result(asyncio.current_task())
            return await coro

        fut = asyncio.run_coroutine_threadsafe(_tracked(), loop)
        try:
            return fut.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            fut.cancel()
            # Drain the cancellation ON the loop so the Task is actually retired before we return.
            # Bounded by _CANCEL_DRAIN_TIMEOUT so a stack that ignores cancellation cannot re-wedge
            # us; any outcome here is swallowed - we are already failing this op loud below.
            try:
                task = task_ref.result(timeout=_CANCEL_DRAIN_TIMEOUT)
                drain = asyncio.run_coroutine_threadsafe(_cancel_and_wait(task), loop)
                drain.result(timeout=_CANCEL_DRAIN_TIMEOUT)
            except BaseException:
                pass
            raise RuntimeError(f"hci operation timed out after {timeout:g}s")

    def apply_config(self, config: dict) -> None:
        # No client link params in this pilot (connection interval / MTU are BlueZ-negotiated). The
        # real medium would carry them here; kept as an explicit no-op, never guessed at.
        pass

    def alive(self) -> bool:
        """True while the loop thread runs and we are not closed. Deliberately NOT tied to the BLE
        link state: scan-only use never connects, and a held link that drops is reconnected on the
        next op rather than retiring the daemon."""
        return not self._closed and self._thread is not None and self._thread.is_alive()

    def close(self) -> None:
        self._closed = True
        loop = self._loop
        if loop is None:
            return
        try:
            if self._client is not None:
                fut = asyncio.run_coroutine_threadsafe(self._disconnect(), loop)
                try:
                    fut.result(timeout=5.0)
                except Exception:
                    pass
        finally:
            try:
                loop.call_soon_threadsafe(loop.stop)
            except RuntimeError:
                pass
            if self._thread is not None:
                self._thread.join(timeout=2.0)
            self._loop = None

    async def _disconnect(self) -> None:
        c, self._client = self._client, None
        if c is not None:
            try:
                if c.is_connected:
                    await c.disconnect()
            except Exception:
                pass

    # --- capabilities -----------------------------------------------------------------------------

    def caps(self) -> dict:
        # verbs = ["scan", "gatt"] ONLY: a central is not a sniffer, so NO sniff/inject/replay
        # (docs/design/ble-gatt.md section 6). No pcap_dlt: a GATT op produces no capture.
        target = None if self.endpoint == NO_TARGET else self.endpoint
        return {"protocol": ble.PROTOCOL, "channels": [],
                "verbs": ["scan", "gatt"], "shape": "transaction",
                "meta": {"target": target}}

    # --- scan -------------------------------------------------------------------------------------

    def scan(self, seconds: float | None = None, count: int | None = None) -> list[dict]:
        """Active scan over a listen window. `seconds` overrides the default window (None -> the
        _SCAN_WINDOW default); `count` stops early once that many DISTINCT advertisements are seen.
        Both come, already coerced and clamped, from the server's SCAN handler."""
        window = _SCAN_WINDOW if seconds is None else float(seconds)
        return self._run(self._scan(window, count), window + _SCAN_MARGIN)

    async def _scan(self, window: float, count: int | None) -> list[dict]:
        """Active scan over `window` seconds, accumulating DISTINCT advertisements. Keyed by
        (address, manufacturer-data hex) so a fob that rotates its address per press still yields one
        row per distinct payload (address-dedup alone would be wrong here). When `count` is given the
        scan returns as soon as that many distinct rows are seen, so a `scan -c 1` quick look does not
        wait out the whole window."""
        seen: dict[tuple[str, str], dict] = {}
        order: list[tuple[str, str]] = []
        enough = asyncio.Event()

        def cb(device, adv) -> None:
            mfg = _encode_mfg(getattr(adv, "manufacturer_data", None))
            key = (device.address, mfg)
            if key not in seen:
                order.append(key)
            rssi = getattr(adv, "rssi", None)
            seen[key] = {
                "name": adv.local_name or device.name or "",
                "addr": device.address,
                "rssi": rssi if isinstance(rssi, int) else "",
                "mfg": mfg,
            }
            if count is not None and len(order) >= count:
                enough.set()

        scanner = self._bleak.BleakScanner(detection_callback=cb)
        await scanner.start()
        try:
            if count is None:
                await asyncio.sleep(window)
            else:
                # Whichever comes first: `count` distinct rows, or the window elapses.
                try:
                    await asyncio.wait_for(enough.wait(), timeout=window)
                except asyncio.TimeoutError:
                    pass
        finally:
            await scanner.stop()
        return [seen[k] for k in order]

    # --- gatt op --------------------------------------------------------------------------------

    def op(self, verb: str, args: dict) -> dict:
        """Run a gatt verb against the held connection. `args` is untrusted (off the wire): every
        field is coerced AUTHORITATIVELY (as_int/hex_bytes), so an uninterpretable value raises (a
        clean wire ERROR via _serve_op), never a guessed byte. A protocol-level ATT error is NOT an
        exception: it is returned inside the result as `{error: <code>}`."""
        with self._lock:
            if verb == "gatt.enum":
                return self._run(self._enum(), _OP_TIMEOUT)
            if verb == "gatt.read":
                spec = self._char_specifier(args)
                return self._run(self._read(spec), _OP_TIMEOUT)
            if verb == "gatt.write":
                spec = self._char_specifier(args)
                value = hex_bytes(args.get("value", ""), "gatt.write value")
                response = args.get("response", True)
                if not isinstance(response, bool):
                    response = True
                return self._run(self._write(spec, value, response), _OP_TIMEOUT)
            # An unknown op verb on a GATT medium: fail loud (a wire ERROR via _serve_op), never a
            # silent empty result the client might misread as a benign answer.
            raise ValueError(f"unsupported gatt op {verb!r}")

    def _char_specifier(self, args: dict):
        """Resolve the characteristic target from untrusted args: an int handle (as sent by the CLI,
        which resolves a uuid to a handle client-side) or a uuid string. Refuse loud otherwise."""
        handle = args.get("handle")
        if handle is not None:
            return as_int(handle, "gatt handle")
        uuid = args.get("uuid")
        if isinstance(uuid, str) and uuid:
            return uuid
        raise ValueError("gatt op needs a handle or uuid")

    async def _connect(self):
        """Return a live BleakClient to `endpoint`, connecting (and HOLDING it) on first use or after
        a drop. A scan-only spawn has no target and cannot run a gatt op."""
        if self._client is not None and self._client.is_connected:
            return self._client
        if self.endpoint == NO_TARGET:
            raise RuntimeError("gatt needs a target peripheral: pass --target <address|name>")
        device = await self._resolve_device(self.endpoint)
        client = self._bleak.BleakClient(device)
        await client.connect(timeout=_CONNECT_TIMEOUT)
        self._client = client
        return client

    async def _resolve_device(self, target: str):
        """A MAC address is handed to bleak directly; a name is resolved by an active scan. A name
        that never advertises is a clean error, never a silent hang."""
        if _MAC_RE.match(target):
            return target
        device = await self._bleak.BleakScanner.find_device_by_name(
            target, timeout=_NAME_RESOLVE_TIMEOUT)
        if device is None:
            raise RuntimeError(f"no advertising BLE peripheral named {target!r} found")
        return device

    async def _enum(self) -> dict:
        client = await self._connect()
        chars = []
        for service in client.services:
            for ch in service.characteristics:
                chars.append({"handle": ch.handle, "uuid": str(ch.uuid),
                              "props": ",".join(ch.properties)})
        return {"characteristics": chars}

    async def _read(self, spec) -> dict:
        client = await self._connect()
        try:
            value = await client.read_gatt_char(spec)
        except Exception as e:
            code = _att_code(e, is_write=False)
            if code is not None:
                return {"error": code}
            raise RuntimeError(f"gatt read failed: {e}")
        return {"value": bytes(value).hex()}

    async def _write(self, spec, value: bytes, response: bool) -> dict:
        client = await self._connect()
        try:
            await client.write_gatt_char(spec, value, response=response)
        except Exception as e:
            code = _att_code(e, is_write=True)
            if code is not None:
                return {"error": code}
            raise RuntimeError(f"gatt write failed: {e}")
        return {"ok": True}
