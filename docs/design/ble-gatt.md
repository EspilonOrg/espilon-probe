# BLE GATT TRANSACTION-shape fidelity pilot - the stack-runner counterpart to UART/CAN

Internal design note. Governed by `00-architecture.md`, `01-transport.md`,
`02-bridge-contract.md`, `03-conformance.md`; extends `../protocols/ble.md` (the
per-protocol reference) into a buildable spec, exactly as `uart-console.md` extends
`../protocols/uart.md` and `can-framed.md` extends `../protocols/can.md`. Grounded in
`core/wire.py`, `core/backend.py`, `backends/virtual.py`, `protocols/ble.py`, `bridges/server.py`,
`bridges/cli.py`, and the whole `conformance/` tree (both the UART twins and the CAN twins).

This is the third pilot and the **first stack-runner** (`02` section 2, `00` decision 3). UART
proved RAW-STREAM (a byte pump), CAN proved FRAMED relay (a model-free byte mover). BLE GATT
proves the **TRANSACTION / semantic-op** surface: `gatt enum/read/write` where one wire unit is a
semantic op the bridge cannot express as a single medium frame, because on real hardware it is a
multi-PDU ATT choreography against a stateful peer that the bridge must **drive the OS stack** to
perform. Same `probe gatt` verbs drive the virtual GattServer model and the real
host-adapter/peripheral leg.

---

## 0. Load-bearing findings first (read before the decisions)

Three findings shape everything below. The honest headline is an **inversion** of the CAN result.

1. **ZERO `core/wire.py` change, and the CLIENT op path already exists end to end.** `OP` /
   `OP_RESULT` (`{verb, args}` / `{result}`) are the ORIGINAL length-prefixed-JSON wire, exactly
   like the FRAMED relay verbs were for CAN. `protocols/ble.py::gatt_enum/gatt_read/gatt_write`
   already route through `Backend.op(...)`, and `backends/virtual.py::op()` already sends
   `{t:OP, verb, args}` and reads `{result}`. So there is **no client transport work at all** - the
   `gatt` verbs travel to a bridge today; nothing was ever wired to a real one.

2. **The real work is INVERTED from CAN. For CAN the SERVE PATH was the work and the medium was a
   thin relay; for GATT the SERVE PATH is trivial and the MEDIA are the work.** `BridgeServer` has
   a stream path and a packet path; it has **no op serve path** - `_serve_packet` explicitly
   *refuses* `OP` ("op group is not supported on a packet bridge"). Adding a `_serve_op` is small
   (~20 lines: read `OP` -> `medium.op(verb, args)` -> `OP_RESULT`; answer `SCAN`; refuse the relay
   verbs). The weight is entirely in the two media it dispatches to: the **virtual `GattServer`
   model** and the **real `hci` medium that drives BlueZ**. `02` section 6 warned this: "writing a
   real BLE bridge means implementing a protocol-aware bridge over the OS stack, not relaying
   bytes." State it plainly for probe-dev: do not read this pilot as "another `socketcan.py` copy."

3. **BLE has NO software loopback medium, so unlike CAN there is NO zero-hardware virtual==real CI
   gate.** vcan (CAN) and a pty (UART) are genuine in-kernel media, so `diff-two-bridges` runs in CI
   with no hardware. There is no "vble". The **virtual leg** (GattServer over the op tunnel) is
   provable in CI immediately (the *virtual-self-consistent* bar, `00` section 3). The
   **virtual==real diff** requires real silicon (the host BLE adapter central + a reflashed reference peripheral)
   and is a **gated spot-check on the dev box, not a CI gate**. This is exactly the bound `00`
   section 3 and `ble.md` already set. (`hci_vhci` + a BlueZ example peripheral is a possible future
   hardware-free path; see section 4.6. Not built here.)

The rest of the client - the CLI verb tree, the pcap writer, the capability gate - is untouched.
`probe gatt read 0x0008` builds the same op it does today; it now reaches a bridge that answers it.

---

## 1. Decision: SHAPE and where GATT slots into `BridgeServer`

**GATT is `shape == "transaction"`. It rides the existing `OP`/`OP_RESULT` machinery with ZERO
wire change. `BridgeServer` gains a THIRD serve path `_serve_op`, dispatched on
`medium.shape == "transaction"`, and the medium surface gains one method `op(verb, args) -> dict`.
That is the entire server delta.**

- The dispatch in `_handle` today is `shape=="packet" -> _serve_packet` else `_serve_stream`. Add a
  branch: `shape=="transaction" -> _serve_op`. `_serve_op` is the transaction twin of
  `_serve_packet`, sharing `_read_control` (deadline-bounded, so a stalled op client is reaped):

  ```
  def _serve_op(self, conn, r, w):
      while True:
          msg = self._read_control(conn, r)
          if msg is None: return
          t = msg.get("t")
          if t == wire.OP:
              verb = msg.get("verb"); args = msg.get("args") or {}
              result = self.medium.op(verb, args)          # the medium RUNS THE STACK
              wire.send(w, {"t": wire.OP_RESULT, "result": result})
          elif t == wire.SCAN:
              wire.send(w, {"t": wire.SCAN_RESULT, "items": self.medium.scan()})
          else:
              wire.send(w, wire.error(f"unsupported control message {t!r} on a transaction bridge"))
  ```

- **Why a NEW path, not fold `OP` into `_serve_packet`.** `_serve_packet` is the documented
  model-free relay (`02` section 5): a byte mover carrying no protocol state. A GATT op is the
  opposite - the medium runs a stateful stack. Keeping the relay path and the op path distinct keeps
  the "generalist relay carries no model" invariant crisp, and `_serve_op` is the reusable serve
  path **SPI and JTAG** (also `shape=="transaction"`) inherit later, exactly as `_serve_packet` is
  the reusable path sub-GHz/Zigbee/BLE-relay inherit. Structural payoff, built once here.

- **This is the honest mirror-and-contrast to the CAN finding.** CAN's honest note was "the FRAMED
  serve path was the real work." GATT's is the inverse: **`_serve_op` is ~20 trivial lines; the real
  work is `medium.op`.** For the virtual bridge that is the `GattServer` model (section 3); for the
  real bridge it is driving BlueZ (section 7). The wire, the client, and the serve path are cheap;
  the stack the medium runs is not.

Confirm for probe-dev: **BLE GATT needs zero `core/wire.py` change and zero client op-path change** -
`OP`/`OP_RESULT` predate the corpus and `gatt` already routes through them, same "good news" as CAN.

---

## 2. Decision: the real backend `hci` - bleak behind the `[hci]` extra, NOT hand-rolled HCI

**Build `bridges/media/hci.py` as a thin adapter over BlueZ via `bleak`, imported lazily behind the
optional `[hci]` extra. Do NOT hand-roll a raw AF_BLUETOOTH HCI + L2CAP-CID-0x0004 + ATT central
stack. This is decisive.**

Rationale, weighed honestly against the stdlib-core rule:

- **The rule is about the client CORE, and real bridges are explicitly allowed optional deps behind
  extras.** `00` decision 8 and `02` section 4 say it in as many words: the client core stays
  stdlib-only; third-party deps live in bridge media, lazily imported, each a written justification
  scoped to its one medium. socketcan/serial *happened* to be stdlib; `hci`/`killerbee`/`sdr` were
  **always** "planned, behind extras" - `pyproject.toml` already reserves `hci = ["bleak>=0.21"]`. bleak in
  `bridges/media/hci.py` violates nothing: the client core, the virtual bridge, and the whole
  virtual leg never import it.

- **Hand-rolling an LE central is weeks of fragile, adapter-specific work that duplicates BlueZ.**
  A central-role GATT stack means: HCI LE Create Connection, LE connection parameters, L2CAP LE
  signalling, the ATT client state machine (MTU exchange, Read By Group Type / Read By Type / Find
  Information discovery, Read/Write, Error Response parsing) over a connected L2CAP CID 0x0004
  socket. Python's `socket` exposes `AF_BLUETOOTH`/`BTPROTO_L2CAP`, but binding a connection-oriented
  ATT channel to a live LE link requires taking the host BLE adapter **out of BlueZ management** (raw HCI user
  channel), which fights the very stack the box already runs. `00` decision 3 is explicit: the real
  bridge **drives the OS protocol stack (BlueZ for BLE)**. bleak is the maintained, standard Python
  BLE library over BlueZ D-Bus; it gives connect / discover / read_gatt_char / write_gatt_char /
  error surfacing directly.

- **How much ATT the pilot needs (all of it delivered BY bleak/BlueZ, none hand-built on the real
  side):** MTU exchange, primary-service discovery, characteristic discovery, descriptor discovery
  (for `gatt.enum`); ATT Read Request (for `gatt.read`); ATT Write Request (for `gatt.write`); ATT
  Error Response parsing (for the error codes). **Excluded** (single-char scope, section 3.2): Read
  Blob / long reads, Prepared/Reliable Writes, notifications/indications + CCCD, and SMP/pairing.
  bleak performs enum/read/write natively; the pilot never emits an ATT PDU by hand on the real leg.

- **The one real fidelity risk on the bleak path: ATT error CODES.** BlueZ hides the raw ATT error
  behind D-Bus error names ("org.bluez.Error.NotPermitted", "NotAuthorized", ...) surfaced by bleak
  as a `BleakError`/`BleakDBusError`. The hci medium must map those names back to ATT codes (0x02
  Read Not Permitted, 0x03 Write Not Permitted, ...) for the comparator. That map is a small, bounded
  translation table in `hci.py`, but it is the place the real leg can drift, so section 3 keeps the
  pilot's errors to **static permission errors** (0x02/0x03), which BlueZ reports crisply, and avoids
  auth (0x05, SMP-coupled) and app-specific codes (fragile through D-Bus).

- **bleak is async; the medium holds ONE asyncio loop + ONE live connection across all per-verb
  connections.** This is the substantive part of the medium (alongside the error map): a background
  loop thread owns a connected `BleakClient`; the sync `op(verb, args)` marshals onto that loop
  (`run_coroutine_threadsafe`). The connection MUST persist across the discrete `probe gatt`
  processes (section 4.3), so `asyncio.run` per op (which would tear the link down) is wrong. Flag
  this as net-new integration work, `L` effort.

---

## 3. Decision: the reference model `GattServer` (the BLE twin of `Console`/`UdsEcu`)

**Ship a minimal, secret-free `GattServer` in `conformance/gatt_server.py`, the TRANSACTION twin of
`console.py`/`uds_ecu.py`, driven off a shared attribute table in `conformance/ble_attrs.py`. A
fuller `GattServer` with author-declared attribute tables and real secret staging is a SEPARATE
content-side follow-up (`ble.md`); this pilot model carries NO secret and NO target content.**

### 3.1 The attribute table (the minimum that is a realistic write-gated secret)

Two vendor primary services; three characteristics; the "unlock then read the secret" gate mirrors
`UdsEcu`'s SecurityAccess gate. Declared implementation-neutrally as a data table both the virtual
model and the reference peripheral firmware read from:

| Handle | Attribute | UUID (128-bit vendor) | Props / Perms | Behaviour |
|---|---|---|---|---|
| (svc) | Primary Service "Device Info" | `...-0001` | - | the banner-analogue service |
| val   | char `fw_version` | `...-0002` | **Read** | fixed `b"pilot-1"` (non-secret). A WRITE -> ATT **0x03** Write Not Permitted (static) |
| (svc) | Primary Service "Lock" | `...-0010` | - | the gated service |
| val   | char `unlock` | `...-0011` | **Write** | correct key -> `unlocked=True`; wrong key -> no state change. A READ -> ATT **0x02** Read Not Permitted (static) |
| val   | char `secret` | `...-0012` | **Read** | `unlocked` -> the staged value; else the LOCKED sentinel `b"\x00\x00\x00\x00"` |

- **The gate is a value-change, not an auth error - deliberately, because the pilot excludes SMP.**
  Real ATT 0x05 Insufficient Authentication requires an encryption/pairing permission (SMP), which
  the pilot does not implement and the host-adapter/peripheral leg is not doing. So the "you must unlock first"
  gate is **application state that changes the returned VALUE** (locked sentinel vs the secret),
  faithful to the large class of *unauthenticated* BLE locks (the actual vuln class) and needing no
  app-error plumbing. This mirrors the CAN model's staging: a sentinel value until unlock.
- **Genuine ATT error-code coverage comes FREE from static permissions.** A write to the read-only
  `fw_version` returns **0x03**; a read of the write-only `unlock` returns **0x02**. BlueZ and the
  reference peripheral enforce these at the GATT layer with no app code and no SMP, and bleak surfaces them - so the
  pilot exercises the ATT error path faithfully without the fragile auth/app-code route. Richer codes
  (0x05 auth, app-specific) land with SMP and the content-side model, out of pilot scope.
- **Wrong-key write does NOT unlock and does NOT error** (the ATT Write Response still succeeds; the
  app no-ops), so a subsequent correct-key write still unlocks - the "retry with the right key" path,
  the exact shape of `UdsEcu`'s invalid-key branch, proven over two terminations.

### 3.2 Single-characteristic scope ONLY (decided, justified - the GATT analogue of CAN's SF-only)

**Every value is <= 20 bytes (fits one ATT Read Response at the default 23-byte MTU), so the pilot
needs no Read Blob / long reads; and there are NO notifications/indications, NO CCCD, NO SMP.**

- **Why single-char is enough:** the pilot's claim is "one semantic op == one client-observable
  result, byte/attribute-identical virtual vs real, and the write-gated secret behaves identically."
  Capping values at MTU-3 makes each `gatt read` exactly one ATT Read transaction and each result one
  comparable value - the purest stack-runner proof, the transaction analogue of CAN's single-frame
  scope. Long reads add ATT Read Blob fragmentation (a *model*-fidelity concern: does our reassembly
  match a real server), independent of whether the op travels faithfully.
- **Why NO notifications:** a notification is an async *server->client* delivery. The `OP`/`OP_RESULT`
  shape is request/response; carrying notifications would need a subscribe verb and a server-push
  channel over the op tunnel - a second transport concern orthogonal to the read/write/enum gate.
  Defer with SMP (both land when a lab's objective *is* pairing or a notify-driven protocol).
- **No descriptor/CCCD handles**, so the handle map is just the eight service/char-declaration/value
  handles. Multi-char, Read Blob, notifications, and SMP are the content-side follow-up; state this
  boundary plainly so nobody reads the pilot as "GATT done."

### 3.3 The model contract (delivery-agnostic, mirrors `Console`/`UdsEcu`)

```python
class GattServer:
    def enumerate(self) -> list[Attribute]:      # the pinned attribute table (handle, uuid, props)
    def read(self, handle: int) -> bytes | AttError:   # value, or an ATT error code (0x02, ...)
    def write(self, handle: int, value: bytes) -> None | AttError:  # ack, or an ATT error; may unlock
    def idle_surfaces(self) -> list[bytes]:      # non-secret surfaces
```

Holds `unlocked` state across calls; NO GATT-PDU, NO L2CAP here - the medium/firmware owns discovery
handle assignment and PDU framing; the model answers at the attribute level, exactly as `UdsEcu`
answers at the UDS-PDU level and the adapter wraps ISO-TP. The secret is a gated slot: the harness
model stages a fixed non-secret sentinel there, and a content-side model substitutes a real secret
behind the same gate. Gate invariant: `read(secret)` returns the staged value **only** after the
gated write; a pre-unlock read returns the LOCKED sentinel, never the value.

### 3.4 The same table serves BOTH terminations - and the reference peripheral is the SOURCE OF TRUTH for handles

The identical attribute spec (`ble_attrs.py`) must be servable byte/attribute-for-attribute by the
virtual `GattServer` AND the reference peripheral firmware. **The one surprise that has no CAN/UART analogue: BLE
handles are ASSIGNED BY THE SERVER, not chosen by the client.** A CAN frame's bytes are fully
client-determined, so virtual and real are identical by construction. A GATT handle is whatever the
peripheral's stack (the peripheral firmware GATT, and any auto-registered GAP 0x1800 / GATT 0x1801 boilerplate
services it prepends) assigns. Two servers can number the same logical layout differently.

**Decision: pin the model to the reference peripheral's ACTUAL discovered layout (record-then-encode).** Flash the
firmware, run `probe gatt enum` against it once, record the exact `(handle, uuid, props)` table it
produces (including where the app service actually lands above any GAP/GATT boilerplate), and encode
THAT as `ble_attrs.py`. The virtual model then reproduces real silicon exactly - the correct
direction (`00` section 3: the model must match the silicon you own, not vice-versa). Handles
are IN scope and compared exactly. If the firmware is rebuilt and handles shift, re-record (a
documented step). The comparator (section 4.4) additionally supports a **uuid+props-keyed** mode with
handles normalized out, as a documented fallback for the case where the BlueZ-central discovery and
the model disagree only on numbering; default is handle-exact.

---

## 4. Decision: the conformance harness (same model, two terminations - one in silicon)

Mirror the `conformance/` tree, following the **UART shape** (observable = stdout + exit code), NOT
the CAN shape (observable = pcap). A GATT op produces no pcap; the CLI renders the op result to
stdout and sets the exit code, so the comparator is `runner.normalize` (stdout + exit) essentially
verbatim - the enum table lines, the read value, the write ack, and the ATT error rendering.

### 4.1 New files (twins of the UART + CAN harnesses)

| New file | Twin of | Role |
|---|---|---|
| `conformance/gatt_server.py` | `console.py` / `uds_ecu.py` | the minimal `GattServer` (enumerate/read/write + unlock state), flag-free |
| `conformance/ble_attrs.py` | `can_isotp.py` | the ONE shared attribute-table spec (handles/uuids/props) both terminations use |
| `conformance/virtual_ble_bridge.py` | `virtual_bridge.py` / `virtual_can_bridge.py` | `GattOpMedium` (adapts `GattServer` to the op-medium surface) + `VirtualBleBridge` (serves it via `BridgeServer._serve_op`) |
| `conformance/hci_adapter.py` | `pty_adapter.py` / `vcan_adapter.py` | `HciRealSide`: brings up the `hci` probe-bridge on the host BLE adapter connected to the advertising reference peripheral; guards on adapter+bleak+peripheral |
| `conformance/run_ble.py` | `run.py` / `run_can.py` | same-tape-two-bridges driver + `--virtual-only`; op-result comparator (reuse `runner.normalize`) |
| `conformance/tapes/ble_gatt_smoke.json` | `tapes/uart_smoke.json` | the gatt op tape (section 4.5) |
| `conformance/hardware/gatt-server-fw/` | `hardware/uart-console-fw/` | the the peripheral firmware GATT-server firmware + README (NET-NEW; see section 8) |
| `tests/test_conformance_ble.py` | `tests/test_conformance_uart.py` | pytest wrapper: virtual-only always runs; the real diff `skipif` no hci/bleak/reference peripheral |

There is **no `ble_responder.py`** twin of `uds_responder.py`. For CAN the model runs as a separate
process on vcan; for BLE **the model IS the reference peripheral firmware** - the peripheral is the responder. That
firmware is net-new build effort (section 8), the way `uds_responder.py` was net-new for CAN.

### 4.2 `GattOpMedium` - the virtual medium (twin of `CanFrameMedium`/`ConsoleMedium`)

```python
class GattOpMedium:
    shape = "transaction"
    def apply_config(self, config): ...          # no link params in the model transport; no-op
    def op(self, verb, args) -> dict:            # gatt.enum/read/write -> {characteristics|value|ok|error}
    def scan(self) -> list[dict]:                # advertise the peripheral (fixed addr; see 4.5)
    def caps(self) -> dict                       # {protocol:"ble", shape:"transaction",
                                                 #  verbs:["scan","gatt"], meta:{...}}  NO sniff/inject/replay
    def alive(self) -> bool; def close(self): ...
```

`op` maps: `gatt.enum` -> `{characteristics:[{handle,uuid,props}...]}` from `enumerate()`; `gatt.read`
-> `{value:<hex>}` or `{error:<att_code>}`; `gatt.write` -> `{ok:true}` or `{error:<att_code>}` and
may flip `unlocked`. Holds the `GattServer` instance across ops - the persistence a write-then-read
gate needs (the virtual analogue of the persistent BLE connection, section 4.3). No pcap, no FIFO.

### 4.3 The persistent BLE CONNECTION is the load-bearing precondition (the BLE-specific gotcha)

The serial daemon persists so a device response survives between `write` and `read`; the CAN daemon
persists so a `7E8` survives between `send` and `dump`. **BLE has the same shape but the thing that
must persist is a live, stateful BLE CONNECTION plus the peripheral's `unlocked` state.** Each
`probe gatt` is a separate process => a separate connection to the BRIDGE; the bridge must hold ONE
BLE link to the reference peripheral open across all of them, because:

- the `unlocked` state lives in the PERIPHERAL (the reference peripheral / the virtual `GattServer`), and many
  peripherals reset per-connection app state on BLE disconnect - so dropping the link between the
  unlock write and the secret read would relock it;
- BLE connection setup is seconds - reconnecting per op is unusable.

So `hci.py::open` establishes AND HOLDS the connection; `serve_forever` (already persistent) keeps
it across the per-verb probe connections; the medium retires the link on idle-timeout/close. This
is the existing persistent-daemon model, but the "medium" is now a live radio link, not a port or a
socket. **This is more load-bearing for BLE than for CAN/serial - flag it prominently.**

### 4.4 The comparator (reuse the UART stdout+exit normalizer)

`run_ble` plays the SAME argv tape against the virtual bridge and the real side and diffs the
per-step `(stdout, exit_code)` via `runner.normalize`/`diff_runs` - the enum lines, the read value,
the write result, and the ATT-error rendering. Nothing wall-clock is in a GATT op result, so
normalize is near-identity, same as UART. In scope: every enum `(handle, uuid, props)` row, every
read value, every ATT error code, the exit code. Normalized out: `scan` output's random/static-random
BD_ADDR and RSSI (`00` section 4); optionally the adopted GAP 0x1800 / GATT 0x1801 boilerplate
services in `enum` (stack-assigned, not the skill - compare only the two vendor services
attribute-for-attribute). Keep the UART harness's `expect`-content check (each step's declared value
must be PRESENT on both sides) so a "both sides rendered nothing identically" regression cannot pass
green. The default enum comparison is handle-exact (section 3.4); `--key-by-uuid` normalizes handles
out as the documented fallback.

### 4.5 The tape (`ble_gatt_smoke.json`, argv-only)

```
gatt enum                         -> the pinned attribute table (both sides)
gatt read 0x0003 (fw_version)     -> "pilot-1"                    (always-readable, banner-analogue)
gatt read 0x0006 (unlock, W-only) -> ATT 0x02 Read Not Permitted  (static error; nonzero exit)
gatt write 0x0003 01 (fw, R-only) -> ATT 0x03 Write Not Permitted (static error; nonzero exit)
gatt read 0x0008 (secret, locked) -> 00000000                     (LOCKED sentinel)
gatt write 0x0006 <wrongkey>      -> ok (ATT write ack) but NO unlock
gatt read 0x0008                  -> 00000000                     (still locked)
gatt write 0x0006 <correctkey>    -> ok  -> unlock
gatt read 0x0008                  -> <secret sentinel>            (served after unlock)
```

Handles are the ones section 3.4 recorded from the actual reference peripheral (the table above is illustrative;
pin to the recorded layout). The correct key is a fixed, course-visible constant (IN diff scope, like
the fixed UDS seed - not normalized out). `expect` pins each rendered value / error string.

### 4.6 Make targets + the honest CI asymmetry vs CAN

```
conformance-ble:                # CI GATE: virtual-only self-consistency. No hci/bleak/BlueZ/hardware.
	$(PYTHON) -m conformance.run_ble --virtual-only conformance/tapes/ble_gatt_smoke.json

conformance-ble-real:           # the SPOT-CHECK: virtual == host-adapter/peripheral. Needs [hci] + reflashed reference peripheral.
	$(PYTHON) -m conformance.run_ble conformance/tapes/ble_gatt_smoke.json

conformance: conformance-uart conformance-can conformance-ble
```

- `conformance-ble` (virtual-only) is the CI gate: it proves `_serve_op` + `GattServer` end-to-end
  over the shipped client, needs nothing but stdlib, runs anywhere. This is the *virtual-self-
  consistent* bar (`00` section 3, `ble.md`).
- `conformance-ble-real` first probes prerequisites via `_has_hci()` (a BlueZ adapter present AND
  `import bleak` succeeds) AND `_peripheral_present()` (the pilot peripheral advertising / reachable). If
  any is absent it prints the setup hint and exits **77** (automake skip), never fails - the same
  clean-skip contract as `conformance-can` on a missing `vcan0`. It is NOT in the default
  `conformance` aggregate, because it needs the reflashed board and the `[hci]` extra.
- **State the asymmetry plainly:** CAN got a hardware-free virtual==real diff because vcan is a real
  in-kernel stack. BLE has no such loopback, so its CI gate is *virtual-only* and its real diff is a
  gated spot-check. `hci_vhci` (a virtual HCI controller) + a BlueZ `example-gatt-server` serving our
  exact attribute table is a possible future hardware-free real path (the vcan analogue), but it
  validates the bleak/BlueZ central path, not the reference peripheral firmware, and standing up a D-Bus peripheral
  with our table is itself real work. Note it as future; do not build it for the pilot.

---

## 5. Decision: verb surface - enum/read/write map cleanly; NO new verb, NO console

**`gatt enum`/`gatt read`/`gatt write` map onto the TRANSACTION op path with no change and no new
verb.** They already exist in `protocols/ble.py` and `cli.py` and route through `op()`; the pilot
adds nothing to the verb tree.

- **NO interactive console for GATT** (task-confirmed): GATT is request/response transactions, not a
  byte stream. `caps.shape == "transaction"`, so the `uart console`/`uart send` stream gate
  (`_require_stream`) already refuses them - correct by construction.
- **NO atomic "unlock-then-read" helper, and the reason is instructive.** UART needed atomic
  `uart send` and CAN mooted `can request` because an ASYNC response could be lost between two
  short-lived connections on a non-persistent bridge. BLE has no such async-loss: the unlock write is
  synchronously ATT-acked within its own op, and the secret read is a fresh synchronous op querying
  current peripheral state. As long as the **persistent BLE connection** (section 4.3) holds across
  the two probe processes, `gatt write` then `gatt read` is deterministic. The persistent *connection*
  solves state-persistence, so no atomic *verb* is needed - a cleaner outcome than UART/CAN. Flag the
  future only: if a peripheral resets state on every ATT connection event, an atomic `gatt
  unlock-read` on one held op could be added; the pilot does not need it.
- **The one small CLIENT change: render ATT error results deterministically.** Today `cli.py` gatt
  read treats a missing `value` key as "no such handle 0x..." - too coarse to compare 0x02 vs 0x03.
  The pilot needs the op result to carry `{error:<att_code>}` and the CLI to render it uniformly
  (e.g. `gatt read failed: ATT error 0x02 (Read Not Permitted)` to stderr, nonzero exit) via a
  code->name table in `protocols/ble.py`, IDENTICALLY for virtual and real, the way UDS NRCs render.
  Small and additive; it is the only client edit the pilot requires and it is what makes the ATT
  error path comparable in the harness.

---

## 6. Decision: SNIFF / REPLAY are OUT of this pilot (the future radio-sniffer leg)

**Explicitly out.** The the host BLE adapter is a central; it CANNOT passively sniff arbitrary BLE traffic (it is
not a sniffer - a central sees only its own connections). Passive BLE capture needs an Ubertooth /
nRF52 sniffer firmware / SDR. So:

- the pilot's BLE medium advertises `verbs = ["scan", "gatt"]` **only** - no `sniff`/`inject`/
  `replay`; the client's capability gate refuses them cleanly, and `_serve_op` refuses them as
  defence in depth.
- `scan` stays IN: central discovery of the advertising peripheral is a legitimate the host BLE adapter/bleak
  operation (active scan, not passive sniff). Its result (address, RSSI, name) is mostly
  normalized-out in the comparator (section 4.4); the fidelity-bearing tape is the gatt ops.
  The active-scan **listen window is operator-controllable**: `probe --backend hci scan -t <secs>`
  (or `ESP_PROBE_SCAN_SECS`) sets how long the central accumulates advertisements, `-c <n>` stops
  once `n` distinct advertisements are seen. The default is 3s (`_SCAN_WINDOW`) - long enough for
  typical 100ms-1s advertising intervals, but a rotating-address fob-collection run wants a longer
  window (`-t 15`) and a quick presence check wants `-t 1`. The window rides an OPTIONAL, additive
  `seconds`/`count` field on the SCAN wire message (an older bridge ignores it and applies its fixed
  window); the bridge coerces it authoritatively off the wire and clamps it to a hard ceiling so a
  hostile value cannot pin the single-serving daemon.
- the **relay surface** of BLE (raw adv / LL PDU sniff/inject/replay under DLT 256, which
  `protocols/ble.py::unlock_write_frame` already layers for offline replay) is the FUTURE
  radio-sniffer leg - sequenced with sub-GHz/Zigbee (`00` sequence 5), when a scenario needs a
  decryptable BLE capture and you have a sniffer. `protocols/ble.py`'s DLT-256 layering stays as-is (correct
  for that future leg); the pilot simply does not exercise it. State this so nobody wires the host BLE adapter
  to a `sniff` it physically cannot serve.

---

## 7. Decision: dependency / packaging impact

**Define `hci = ["bleak>=0.21"]` (currently `hci = []`), imported LAZILY inside `bridges/media/hci.py`
only. Core install stays dependency-free; the virtual leg needs neither bleak, nor BlueZ, nor an
reference peripheral, so it runs anywhere.**

- `pip install espilon-probe` - dependency-free, unchanged (`dependencies = []`). The client core,
  the virtual bridge, `GattServer`, and `_serve_op` are pure stdlib.
- `pip install espilon-probe[hci]` - adds bleak (which pulls `dbus-fast` on Linux). Required ONLY for
  the real leg (`conformance-ble-real`, real hardware). bleak is imported inside `hci.py`, never by
  `espilon_probe.cli`/`core`/`protocols` (the client core) and never by the virtual bridge - so the
  stdlib-only core invariant holds and a user who never touches BLE hardware never installs it.
- **Virtual leg needs no BlueZ at all** - the pilot's virtual side (the CI gate) runs on any box,
  including CI with no Bluetooth stack. This is the key packaging property, symmetric to the CAN
  virtual leg needing no `vcan`.
- **Written justification for bleak (scoped to the hci medium):** driving the BlueZ LE central stack
  (connect, MTU, ATT discovery/read/write, error surfacing) is precisely the "drive the OS stack"
  `00` decision 3 / `02` section 6 mandate for a stack-runner bridge; hand-rolling an LE central over
  raw HCI/L2CAP sockets would be a fragile reimplementation of BlueZ that also fights BlueZ for the
  adapter. bleak is the maintained standard Python BLE library over BlueZ D-Bus. The dependency lives
  only in `bridges/media/hci.py` behind `[hci]`; the client core and the virtual bridge stay
  stdlib-only. bleak's asyncio nature is absorbed inside the medium (a background loop thread holding
  the connection, section 2), not exposed upward.

---

## 8. Honest reuse-vs-net-new, and effort

| Piece | Reuse / net-new | Effort |
|---|---|---|
| `core/wire.py` | **reuse** (OP/OP_RESULT predate the pilot) | - |
| client op path (`protocols/ble.py` enum/read/write, `virtual.py::op`) | **reuse** (already routes through `op()`) | - |
| `cli.py` ATT-error-result rendering | **net-new, small** (code->name table, nonzero exit; the only client edit) | S |
| `bridges/server.py::_serve_op` + `medium.op` surface | **net-new, small** (~20 lines; reused later by SPI/JTAG) | S |
| `conformance/gatt_server.py` + `ble_attrs.py` (virtual model) | **net-new** (the virtual-self-consistent payoff, CI-provable immediately) | M |
| `bridges/media/hci.py` (real medium over bleak) | **net-new** (async loop + persistent connection + ATT-error map: the real integration) | **L** |
| `conformance/hardware/gatt-server-fw/` firmware | **net-new** (the peripheral firmware GATT attribute table; the board runs UART console fw today) | M |
| `conformance/{virtual_ble_bridge,hci_adapter,run_ble}.py` + tape + test + Make | **net-new** (the harness twins; comparator reuses `runner.normalize`) | M |
| content-side `GattServer` (author API, real secret staging, SMP) - **SEPARATE follow-up, NOT this pilot** | net-new | M (+ L for SMP), tracked in `ble.md` |

The honest headline (section 0.2): the serve path and the wire are cheap; **the two media are the
work, and one of them is silicon.** `_serve_op` is trivial; `GattServer` is a clean M and pays off
in CI immediately; `hci.py` is a real `L` BlueZ integration; the reference peripheral firmware is net-new and its
flashing is a separate gated step. No line-count win is claimed - the payoff is structural (`gatt`
faithful by a shared attribute table + a driven OS stack, not by per-lab hand-modeled handle dicts),
plus a reusable transaction serve path SPI/JTAG inherit.

---

## 9. Surprises to flag for probe-dev (checklist)

1. **The real work is INVERTED from CAN.** `_serve_op` is ~20 trivial lines; the weight is entirely
   in the media - the virtual `GattServer` model and the real bleak/BlueZ stack-runner. This is not a
   `socketcan.py` copy. (Section 0.2, 1.)
2. **BLE has NO software loopback - no zero-hardware virtual==real CI gate.** The CI gate is
   virtual-only; the real diff (host-adapter/peripheral) is a gated spot-check that skips (exit 77) without the
   `[hci]` extra and a reflashed board. Deliberate asymmetry vs vcan/pty. (Sections 0.3, 4.6.)
3. **BLE handles are SERVER-assigned, so "attribute-for-attribute" needs the model PINNED to the
   reference peripheral's real layout (record-then-encode), including any GAP/GATT boilerplate the firmware
   prepends.** Unlike a CAN frame (fully client-determined), a handle map is not identical by
   construction. Fallback: a uuid+props-keyed comparator with handles normalized. (Section 3.4, 4.4.)
4. **A persistent BLE CONNECTION (not just a persistent daemon) must span the per-verb `probe`
   processes**, or the peripheral relocks between the unlock write and the secret read and every
   reconnect costs seconds. `hci.py::open` holds the link; `serve_forever` keeps it. More
   load-bearing than CAN/serial persistence. (Section 4.3.)
5. **The unlock gate is a VALUE-change, not an auth error, because the pilot excludes SMP.** Real
   0x05 Insufficient Authentication needs pairing (fundamental effort, out of scope). ATT error
   coverage comes from STATIC permission errors (0x02 read-of-write-only, 0x03 write-of-read-only),
   which BlueZ/the reference peripheral give free and bleak surfaces crisply. (Sections 2, 3.1.)
6. **ATT error codes are the one bleak-path fidelity risk** - BlueZ hides them behind D-Bus error
   names; the hci medium maps names->codes. Kept to 0x02/0x03 (crisp) for the pilot; auth/app codes
   deferred. And the CLI must render `{error:<code>}` deterministically (small client edit) or the
   error path is not comparable. (Sections 2, 5.)
7. **SNIFF/REPLAY are physically impossible on the host BLE adapter** (a central is not a sniffer); the medium
   advertises `["scan","gatt"]` only. The DLT-256 relay surface is the future radio-sniffer leg.
   (Section 6.)
8. **The reference peripheral firmware is net-new and reflashing is a SEPARATE gated step** - the reference board
   runs the UART console firmware today; do not assume it flashed. The GATT-server firmware
   is the BLE "responder" (there is no `ble_responder.py` process twin; the model is the firmware).
   (Sections 4.1, 8.)
9. **Single-characteristic scope ONLY:** values <= MTU-3 (no Read Blob), no notifications/CCCD, no
   SMP, no multi-service beyond the two vendor services. The GATT analogue of CAN's SF-only. Do not
   read the pilot as "GATT done." (Section 3.2.)
</content>
</invoke>
