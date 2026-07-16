# CAN FRAMED-shape fidelity pilot - the depth counterpart to the UART RAW-STREAM pilot

Internal design note. Governed by `00-architecture.md`, `01-transport.md`,
`02-bridge-contract.md`, `03-conformance.md`; extends `../protocols/can.md` (the per-protocol
reference) into a buildable spec, exactly as `uart-console.md` extends `../protocols/uart.md`.
Grounded in `core/wire.py`, `core/backend.py`, `backends/{socketcan,serial,virtual}.py`,
`protocols/can.py`, `bridges/{server,cli}.py`, `bridges/media/serial.py`, and the whole
`conformance/` tree.

This is the FRAMED (packet) pilot: prove that a CAN workflow learned against a virtual bridge
transfers frame-for-frame to Linux in-kernel `vcan0` (a genuine SocketCAN stack, not a simulator),
driven by the **same** `probe can` verbs, with the fidelity proven by a `diff-two-bridges`
conformance loop. It is the FRAMED analogue of the UART pilot in every structural part: a virtual
bridge (simulator serving FRAMED frames over TCP), a real bridge (a TCP<->vcan daemon), one shared
device model bound onto both terminations, and a frame-tape harness that diffs the two.

---

## 0. Load-bearing findings first (read before the decisions)

Two findings shape everything below. One is good news, one is the real work.

1. **ZERO `core/wire.py` change, exactly like UART.** The RAW-STREAM pilot added `STREAM_ATTACH` /
   `STREAM_READY` because a stream *breaks* the framed codec (upgrades the socket to raw bytes).
   FRAMED breaks nothing: `INJECT`/`ACK`, `SNIFF`/`FRAME`/`SNIFF_END`, `REPLAY`/`REPLAYED`, `SCAN`,
   `OP` were the **original** length-prefixed-JSON wire and stay framed end to end. A CAN frame is
   already carried as the hex of the 16-byte SocketCAN struct in `INJECT.frame` / `FRAME.raw` /
   `REPLAY.frames[]`, built and parsed by `protocols/can.py::encode_frame`/`decode_frame` today
   (`socketcan.py` and every lab already exercise it). **The FRAMED analogue of `STREAM_ATTACH` is
   "there is none": the `HELLO`/`WELCOME` handshake is the only attach, and each verb is a
   self-contained framed transaction.** So CAN matches UART's "zero wire delta on the data path."

2. **The real work is server-side: the generic `BridgeServer` is STREAM-ONLY today.** It was built
   for the UART pilot; `BridgeServer._handle` handles only `STREAM_ATTACH` and `SCAN`, and answers
   every other control message with `unsupported control message ... on a stream bridge`. It has
   **no `INJECT`/`SNIFF`/`REPLAY` path**. The CAN pilot's substantive addition is the **generic
   FRAMED serve path** in `BridgeServer` plus a **packet-medium surface** (a `CanMedium` over
   `PF_CAN`). This is generalist infrastructure every future relay protocol (sub-GHz, Zigbee
   capture/replay, the BLE relay surface) reuses - the FRAMED counterpart of the raw pump the UART
   pilot stood up. Be honest in effort estimates: this is not "reuse `socketcan.py` unchanged"; its
   *I/O body* is reused, the *server-side FRAMED dispatch + persistent packet FIFO* is new.

The rest of the client (CLI `can send`/`can dump`, the `protocols/can.py` codec, the pcap writer,
the capability gate) is untouched. `probe can send 7E0 1003` builds the same 16-byte frame; it now
travels to a bridge instead of an in-client `PF_CAN` socket.

---

## 1. Decision: the FRAMED wire representation (no wire change)

**A CAN frame stays the classic 16-byte SocketCAN struct, hex-encoded in the existing framed
messages. No `core/wire.py` addition; no new attach handshake.**

- `struct.Struct("<IB3x8s")` (`protocols/can.py`): `can_id|flags`, `dlc`, 3 pad, `data[8]`.
  `CAN_EFF_FLAG` (extended 29-bit) and the 11/29-bit masks are packed into the id field and are
  round-tripped by the shared codec. `id`, `extended`, `dlc` (0..8, illegal-DLC rejected), and up
  to 8 data bytes are fully represented. This is the dual-purpose codec both terminations use.
- **On the wire:** `INJECT{frame: <hex16>, channel}` -> `ACK`; `SNIFF{count, seconds, channel}` ->
  `FRAME{raw:<hex16>, ts, ...}`* -> one `SNIFF_END{count}`; `REPLAY{frames:[<hex16>...]}` ->
  `REPLAYED{count}`; `SCAN` -> `SCAN_RESULT{items}`; `OP` -> clean `ERROR` (CAN has no op group).
  All of these already exist in `core/wire.py`.
- **RTR / remote frames:** `CAN_RTR_FLAG` is *defined* in `protocols/can.py` but **not plumbed**
  through `encode_frame`/`decode_frame` (they carry `extended` only). UDS uses no remote frames, so
  the pilot needs nothing here. Flag it as a known codec gap: a lab that needs RTR adds an `rtr`
  bool to the two codec functions later. Do not add it speculatively.

Confirm explicitly for probe-dev: **CAN needs zero `core/wire.py` change, same as the UART pilot's
FRAMED path.** The only additions the corpus ever made to the wire (`STREAM_ATTACH`/`STREAM_READY`)
are stream-only and irrelevant to CAN.

---

## 2. Decision: the CAN bridge medium, and whether persistence is needed

**Add `bridges/media/socketcan.py::CanMedium` wrapping the `PF_CAN` raw socket (lift the I/O body of
today's `backends/socketcan.py`), `shape = "packet"`, with a background reader thread into a frame
FIFO. Reuse the persistent-daemon machinery unchanged - CAN's connectionless nature does NOT let us
skip it.**

`CanMedium` is the packet-shape sibling of `SerialMedium`. The packet-medium surface (the contract
`BridgeServer` drives for a `shape=="packet"` medium):

```python
class CanMedium:
    shape = "packet"
    def open(self) -> None            # socket(PF_CAN, SOCK_RAW, CAN_RAW); bind((endpoint,))  [socketcan.py::open]
    def apply_config(self, config: dict) -> None   # e.g. {"can_bitrate": N}; a no-op on vcan
    def caps(self) -> dict            # {protocol:"can", channels:[], verbs:["scan","sniff","inject","replay"],
                                      #  shape:"packet", meta:{iface, pcap_dlt: 227}}
    def scan(self) -> list[dict]      # ids_seen over a short capture window  [socketcan.py::scan]
    def inject(self, frame: bytes) -> None         # send the 16-byte struct verbatim  [socketcan.py::inject]
    def take_frames(self, count: int|None, deadline: float) -> list[bytes]  # drain FIFO + live RX, bounded
    def alive(self) -> bool           # False once the reader thread stopped (socket died)
    def close(self) -> None
```

- **Background reader (load-bearing for cross-verb capture).** A daemon thread `recv`s the socket
  into a `collections.deque` of raw frames, continuously, independent of any client connection -
  the exact role `SerialMedium._read_loop` plays for the stream. `take_frames` returns buffered
  frames plus any that arrive within the bound. Rationale below.
- **Why persistence is still required, connectionless notwithstanding.** The serial daemon is
  persistent so a device response emitted *between* a `probe uart write` and a later `probe uart
  read` survives (`01` section 4). CAN has the identical hazard: a `probe can send 7E0 1003`
  (inject) then a separate `probe can dump` (sniff) are two short-lived connections; the ECU's
  `7E8` response, injected onto the bus in between, is lost if no socket is bound when it arrives.
  A **persistent** bound `PF_CAN` socket (whose reader keeps a FIFO) captures it and hands it to the
  next `dump`. So connectionless removes the "open a session to a peer" step, **not** the
  "hold RX across the discrete per-verb connections" need. Keep the daemon.
  - Honest caveat: a bound kernel `PF_CAN` socket already buffers RX in `SO_RCVBUF` with no
    userspace read, so in principle the FIFO thread is belt-and-suspenders. Use the thread anyway:
    it mirrors `SerialMedium` exactly (one persistent-medium pattern, not two), gives a clean
    `peek/count`, and avoids `SO_RCVBUF` overflow on a chatty bus.
- **Reuse the launcher and rendezvous verbatim.** `backends/serial.py::_ensure_bridge` /
  `_spawn_daemon` / `_connect_existing` are already medium-generic (they take `medium` as a
  parameter and spawn `python -m espilon_probe.bridges --medium <m> --endpoint <e>`). The CAN
  loopback backend is a ~10-line subclass of `VirtualBackend`, the twin of `SerialBackend`:

```python
class CanBackend(VirtualBackend):        # backends/socketcan.py, replacing the direct SocketCanBackend
    _transport_label = "socketcan"
    def __init__(self, target=None, baud=115200):
        super().__init__(target=None, baud=baud)
        self.endpoint = target or "vcan0"
    def open(self):
        port = _ensure_bridge("socketcan", self.endpoint, self.baud)   # reuse serial.py's rendezvous
        self.target = f"tcp://127.0.0.1:{port}"
        super().open()
```

Move the shared `_ensure_bridge` family out of `backends/serial.py` into a small
`backends/_loopback.py` (or leave it and import) so both launchers share one copy - cosmetic, not
load-bearing.

---

## 3. Decision: the reference device model (`UdsEcu`), minimal but realistic

**Ship a minimal, secret-free `UdsEcu` in the probe repo's `conformance/uds_ecu.py`, the FRAMED
twin of `conformance/console.py`. A richer UDS model with real secret staging is a SEPARATE
content-side follow-up (`can.md`); this pilot model carries NO secret and NO target content, only
enough behaviour to drive the harness.**

### 3.1 Services (the minimum that is a realistic stateful gate)

Reproduce the UDS surface `../protocols/can.md` names, nothing more:

| Req | Service | Positive response | Gating |
|---|---|---|---|
| `10 03` | DiagnosticSessionControl (extended) | `50 03 00 32 01 F4` (P2 timings) | always; opens the session |
| `27 01` | SecurityAccess requestSeed | `67 01 <seed4>` | only after `10 03`; else NRC `33` |
| `27 02 <key4>` | SecurityAccess sendKey | `67 02` | seed issued + `key == seed XOR 0xA5A5A5A5` |
| `22 F1 90` | ReadDataByIdentifier (privileged) | `62 F1 90 <value<=4>` | only once unlocked; else NRC `33` |

Negative responses (the NRC branches `03` section 5 requires):
`7F 27 35` invalidKey (wrong `27 02`), `7F 27 33` securityAccessDenied (`27 01`/`22` before its
precondition), `7F xx 12` subFunctionNotSupported / `7F xx 11` serviceNotSupported (unknown req),
`7F xx 22` conditionsNotCorrect. `responsePending 7F xx 78` is a fuller-`UdsEcu` behaviour
(retry-lockout + `0x78`) but is **out of the harness-minimal model** - it is a timing/turnaround
behaviour better proven with the full model, and it complicates the single-frame diff.

**Decisively excluded from the pilot model:** `0x31` RoutineControl and `0x2E` WriteDataByIdentifier.
They are the same "gated sub-function" shape as `0x22`/`0x27` and add coverage, not a new pattern;
they belong in the fuller `UdsEcu`. The trio `10`/`27`/`22` already exercises session state, a
seed->key security gate, a gated privileged read, and four NRCs - the entire "stateful secret behind
a request" pattern the pilot must prove over two terminations.

### 3.2 ISO-TP scope: single-frame ONLY for the pilot (decided, justified)

**Every request and response in the pilot fits one ISO-TP single frame (SF), so the pilot needs no
FlowControl, no CF ordering, no STmin.** This is deliberate and it is what keeps the pilot a clean
transport proof:

- All PDUs above are <= 6 bytes; the privileged DID value is constrained to **<= 4 bytes** precisely
  so `62 F1 90 <value>` fits an SF (3 + 4 = 7, the SF data max). SF wrap = `[PCI=0x0<len>][pdu...]`
  right-padded to DLC 8 with `0x00`; classic 11-bit addressing on `0x7E0` (request) / `0x7E8`
  (response). Both terminations use the **same** wrap, so padding/DLC are identical by construction.
- **Why SF is enough:** the FRAMED pilot's claim is "one wire unit == one real CAN frame on vcan,
  byte-identical virtual vs real, and the UDS state gate answers identically." SF makes each `can
  send` exactly one request frame and each response exactly one captured frame - the purest relay
  proof. Multi-frame ISO-TP (a 17-byte VIN, chunked FF+CF with a tester `FlowControl` frame) adds
  the **ECU-side ISO-TP state machine**, which is a *model*-fidelity concern (does our reassembly
  match a real ECU's), independent of whether the CAN frames travel faithfully. Bundling it here
  would couple the transport proof to a stateful choreography that is fragile to drive from a
  `can send`/`can dump` tape (STmin timing, CF sequence). Keep it out.
- **Multi-frame is the content-side follow-up**, landing with the full `UdsEcu` + the
  `isotp_encode`/`decode` FlowControl/STmin extension (`can.md`), and is the first real customer of
  the `can request` helper (section 5). State this boundary plainly so nobody reads the pilot as
  "ISO-TP done."

### 3.3 The model contract (delivery-agnostic, mirrors `Console`)

```python
class UdsEcu:
    def request(self, pdu: bytes) -> bytes | None:
        """Feed one UDS request PDU; return the UDS response PDU (or None for no response).
        Holds session/security state across calls. NO CAN, NO ISO-TP, NO secret here - the
        adapter wraps SF and the CAN ids."""
    def idle_surfaces(self) -> list[bytes]:
        """Non-secret surfaces (banner-equivalent)."""
```

The privileged-DID value is a gated slot: the harness model stages a non-secret sentinel (e.g.
`b"\xDE\xAD\xBE\xEF"`) in it so the diff has stable bytes to compare, exactly as `console.py`
serves non-secret command bodies. Gate invariant: `62 F1 90` returns the sentinel **only** after
the gated `27 02`; a pre-unlock read returns NRC `33`, never the value. A content-side model
substitutes a real secret behind the same gate.

---

## 4. Decision: the conformance harness for FRAMED (same model, two terminations)

Mirror the `conformance/` tree part for part. The construction that makes "virtual vs real" real:
**run the same `UdsEcu` two ways - once behind the virtual bridge over TCP, once bound onto a real
`vcan0` behind the real socketcan bridge - and diff the captured response frames.**

### 4.1 New files (twins of the UART harness)

| New file | Twin of | Role |
|---|---|---|
| `conformance/uds_ecu.py` | `console.py` | the minimal UDS state machine (`request(pdu)->pdu`), flag-free |
| `conformance/can_isotp.py` | (new, tiny) | SF wrap/unwrap + the `0x7E0/0x7E8` id map; the ONE adapter both sides use |
| `conformance/virtual_can_bridge.py` | `virtual_bridge.py` | `CanFrameMedium` (adapts `UdsEcu` to the packet-medium surface) + `VirtualCanBridge` (serves it via the generic `BridgeServer`) |
| `conformance/vcan_adapter.py` | `pty_adapter.py` | `VcanRealSide`: brings up the socketcan `probe-bridge` daemon on `vcan0` AND spawns the `UdsEcu` responder process bound to `vcan0` |
| `conformance/run_can.py` | `run.py` | the same-tape-two-bridges driver + the **pcap-frame** comparator |
| `conformance/tapes/can_uds_smoke.json` | `tapes/uart_smoke.json` | the frame tape (requests -> expected response frames) |
| `tests/test_conformance_can.py` | `tests/test_conformance_uart.py` | pytest wrapper, `skipif` no `vcan0` |

### 4.2 Same model both sides; the real side is a SEPARATE responder process (decided)

**The same `UdsEcu` class drives both terminations (a fresh instance per side, so both start from
identical state and any difference is transport). On the real side the model runs in a separate
responder process bound to `vcan0`; the generalist socketcan bridge is untouched and model-free.**
This mirrors UART, where the same `Console` runs in-process behind `ConsoleMedium` (virtual) and in
the `_PtyDevice` thread on the pty master (real).

- **Virtual side (`CanFrameMedium`, twin of `ConsoleMedium`):** `inject(frame)` decodes the request,
  feeds `can_isotp.unwrap` -> `UdsEcu.request` -> `can_isotp.wrap`, and appends the response
  frame(s) to its RX deque; `take_frames` drains that deque. **Fidelity-critical:** `inject` must
  NOT echo the injected request frame back into its own RX. A real `CAN_RAW` socket does not receive
  its own sent frames (SocketCAN default: `RECV_OWN_MSGS` off, and `socketcan.py` does not enable
  it), so the real `can dump` sees only the `7E8` response. If the virtual medium echoed the `7E0`
  request into RX, virtual would show `7E0`+`7E8` and real only `7E8` - an instant, spurious diff.
  Queue responses only.
- **Real side (`vcan_adapter.py`, twin of `pty_adapter.py::ConformanceRealSide`):** on `vcan0` there
  are **two** independent `PF_CAN` sockets, which is exactly "an ECU on the bus + the operator's CAN
  interface":
  1. the generalist socketcan `probe-bridge` daemon (spawned via the reused rendezvous, the socket
     the `probe --backend socketcan --target vcan0` client drives) - relays `INJECT` onto the bus,
     captures bus frames for `SNIFF`; **no model** (`02` section 5);
  2. the `UdsEcu` **responder process**: binds its own `PF_CAN` socket on `vcan0`, reads request
     frames (`7E0`), runs the same `can_isotp`+`UdsEcu`, writes response frames (`7E8`).
  Loop: `probe can send 7E0 1003` -> bridge injects on `vcan0` -> responder replies `7E8` -> the
  bridge's background reader buffers it -> `probe can dump` drains it. This is `02` section 5's
  "model-to-CAN adapter, relay bridge untouched," made literal. Bring-up ordering mirrors the pty
  banner rule: start the persistent bridge daemon (so a socket is bound and buffering) **before**
  the first request is injected, so no response is lost to an unbound bus.

### 4.3 The FRAMED comparator (the reserved normalizer home)

The observable for CAN is the pcap `can dump` writes, not stdout bytes. `conformance/runner.py`
today normalizes stdout only (UART). Add the FRAMED comparison `03` section 3 reserves:

- for each `can dump -w <pcap>` step, read the produced pcap (`core/frame.py::read_pcap`), extract
  the **ordered list of frame `raw` payloads**, and diff virtual-vs-real **byte-for-byte** with
  **pcap timestamps normalized out** (order is in scope, wall-clock `ts` is not - `00` section 4).
  Each side writes to its own temp pcap path.
- keep the `expect`-mode content check (a per-step list of expected response-frame hexes must be
  present on both sides) so a "both sides captured nothing identically" regression cannot pass green
  - the FRAMED echo of the UART harness's banner/response presence check.

### 4.4 The tape (`can_uds_smoke.json`), argv-only

Steps drive the shipped CLI; the happy path + every documented NRC branch. Because the pilot is SF
and the persistent bridge makes `send` then `dump` deterministic (section 5), each UDS exchange is a
`can send` followed by a `can dump -c 1`:

```
10 03  -> 50 03 ...        (open session)
27 01  -> 67 01 <seed>     (seed; fixed course seed, IN diff scope -> must match both sides)
22 F190 (before unlock) -> 7F 22 33   (privileged read denied)
27 02 <wrongkey> -> 7F 27 35           (invalid key; state must NOT advance)
27 02 <key=seed^A5A5A5A5> -> 67 02      (unlock)
22 F190 -> 62 F1 90 <sentinel>          (privileged read now served)
```

`expect` pins each response-frame hex. The seed is course-fixed, so it is asserted equal on both
terminations (a random seed would be normalized out - it is not one here).

### 4.5 Make targets (mirror `conformance-uart` / `conformance-uart-real`)

```
conformance-can:        # the pilot gate: virtual == vcan0, no hardware beyond the vcan module
	$(PYTHON) -m conformance.run_can conformance/tapes/can_uds_smoke.json

conformance: conformance-uart conformance-can
```

- `conformance-can` first checks for `vcan0` (a `_has_vcan()` probe, section 6). If absent it prints
  the one-line setup hint (`sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0`) and
  exits **77** (the automake skip code) so CI treats it as skip, not fail. A make target is an
  explicit ask, so this is a clean skip, not a silent pass.
- **No separate `-real` target for the pilot.** For UART, `-real` meant actual USB silicon; for CAN
  the "real medium" IS `vcan0` (a genuine in-kernel SocketCAN stack), so `conformance-can` over
  `vcan0` already IS the real-medium diff. A future `conformance-can-hw TARGET=can0` driving a real
  transceiver is a **spot-check, not a CI gate** (`03` section 7: "vcan is not a transceiver";
  bus-error/arbitration/bit-timing physics need real CAN hardware). Note it as future, do not build
  it now.

---

## 5. Decision: verb surface - send/dump/sniff/replay map cleanly; no new interactive verb

**`can send`/`can dump`/`sniff`/`replay` map onto FRAMED with no change and no new verb. CAN is a
packet bus, not a console - do NOT bolt an interactive verb onto it.** The mapping is the one that
already ships: `can send <id> <hex>` -> `inject`, `can dump -w` -> `sniff`; core `scan/inject/replay`
apply; `pcap_dlt = 227` so captures dissect as CAN in tshark.

**The one real gap: request-response ergonomics.** Driving UDS is "inject a request, capture the
response" - two verbs, two short-lived connections. On the **persistent** bridge the response
injected between them survives in the medium FIFO (section 2), so `can send` then `can dump -c 1` is
deterministic and the tape uses that pair. This is the same property (and the same caveat) the UART
pilot established: it works BECAUSE the daemon is persistent; on a non-persistent bridge the response
can be lost - the exact footgun that motivated the atomic `uart send`.

**Recommendation: the pilot does NOT add a request-response verb.** Single-frame + the persistent
daemon make `send`+`dump` sufficient and faithful for the pilot. Flag the future: a `probe can
request <req_id> <resp_id> <pdu> [-t N]` helper - atomic inject-then-capture-one-response on a single
held connection - is the FRAMED analogue of `uart send`, and its real payoff is **multi-frame
ISO-TP** (where the tester must interleave `FlowControl` frames with the ECU's CFs, impossible to
choreograph reliably from separate `send`/`dump` processes). Build `can request` **when the
multi-frame `UdsEcu` model lands**, not in the transport pilot. Recording the rationale prevents a
premature verb that the SF pilot does not need.

---

## 6. Test approach (stated, not designed)

- **FRAMED codec unit tests:** already covered by `tests/test_socketcan_unit.py` (encode/decode
  round-trip, EFF/DLC, illegal-DLC rejection). Unchanged; the codec does not move.
- **`UdsEcu` model unit tests (new, no socket):** the FRAMED twin of the `Console.feed` model test.
  Feed request PDUs directly to `UdsEcu.request` and assert response PDUs + NRC bytes + that a wrong
  `27 02` does **not** advance state and a pre-unlock `22 F190` returns NRC `33`. Plus a `can_isotp`
  SF wrap/unwrap round-trip test.
- **virtual == vcan fidelity (new):** `tests/test_conformance_can.py` invokes `run_can` on the smoke
  tape and asserts PASS. This is the `diff-two-bridges` proof.
- **vcan may be absent (CI):** mirror `tests/test_socketcan_live.py` exactly - a `_has_vcan()` that
  tries to `bind` a `PF_CAN` socket to `vcan0` and
  `@pytest.mark.skipif(not _has_vcan(), reason="...ip link add dev vcan0 type vcan...")`. The
  make target uses the same probe and exits skip-code 77. `03` section 7 already documents that
  vcan needs the `vcan` kernel module + a link and is CI-gated where available.
- **Low-level medium test:** `test_socketcan_live.py` currently drives the DIRECT `SocketCanBackend`.
  After the migration (section 7) re-point it at `CanMedium` (the same PF_CAN I/O, now in the
  bridge) so the medium keeps a direct unit test, and let `test_conformance_can.py` own the
  end-to-end tunnel path.

---

## 7. Migration impact (client rework)

Small and localized in the client, per `00` section 5; the weight is the generic FRAMED serve path
and the content-side model (the latter out of pilot scope).

| Layer | Change | Size |
|---|---|---|
| `core/wire.py` | **none** (FRAMED verbs predate the pilot) | - |
| `protocols/can.py` (codec + `send`/`dump` sugar) | **none** (the shared codec stays) | - |
| `cli.py` `can` verbs | **none** (`send`->inject, `dump`->sniff already) | - |
| `cli.py::_make_backend` | `--backend socketcan` -> the new `CanBackend` loopback launcher | S |
| `backends/socketcan.py` | **replace** the direct `SocketCanBackend` (PF_CAN in the client) with the `CanBackend(VirtualBackend)` launcher; its `PF_CAN` I/O moves to `CanMedium` | S |
| `bridges/media/socketcan.py` | **new** `CanMedium` (PF_CAN + background frame FIFO), lifting `socketcan.py`'s open/inject/read | S/M |
| `bridges/cli.py::_make_medium` | register `socketcan` -> `CanMedium` | S |
| `bridges/server.py` | **new** generic FRAMED serve path: dispatch on `medium.shape`; for `"packet"`, handle `INJECT`/`SNIFF`(stream frames + one `SNIFF_END`)/`REPLAY`/`SCAN`/`OP`(refuse) | **M** (the substantive shared work) |
| `backends/_loopback.py` | optional: hoist `_ensure_bridge`/`_spawn_daemon`/`_connect_existing` out of `serial.py` so both launchers share one copy | S, cosmetic |
| `conformance/*` + tape + test + Makefile | the harness twins (section 4) | M |
| **content-side model - SEPARATE follow-up, NOT this pilot** | a fuller `UdsEcu` with real secret staging; ISO-TP FlowControl/STmin | M (tracked in `can.md`) |

The `BridgeServer` FRAMED path is the reusable core: sub-GHz, Zigbee capture/replay, and the BLE
relay surface all serve `INJECT`/`SNIFF`/`REPLAY` through it later. Structural payoff, not a
line-count win: `socketcan.py` shrinks to a launcher, but the gain is `virtual == real` inherent and
one generic packet-serve path instead of a per-backend one.

---

## 8. Surprises to flag for probe-dev (checklist)

1. **The generic `BridgeServer` is STREAM-ONLY today.** It has no `INJECT`/`SNIFF`/`REPLAY` path;
   adding the FRAMED serve path is the pilot's real work, not a `socketcan.py` copy. (Section 0.2.)
2. **Zero `core/wire.py` change** - the FRAMED verbs are the original wire; there is no FRAMED
   `STREAM_ATTACH` analogue to add. Good news, symmetric to UART. (Section 1.)
3. **The virtual `CanFrameMedium` must NOT echo the injected request into its own RX.** A real
   `CAN_RAW` socket does not receive its own frames (RECV_OWN_MSGS off), so real `dump` sees only the
   `7E8` response; echoing the `7E0` request virtual-side is an instant spurious diff. (Section 4.2.)
4. **On `vcan0` there are TWO sockets** - the generalist relay bridge and the model responder - and
   that is correct: it models "an ECU on the bus + the operator's interface." The bridge stays
   model-free; the responder is the content side. (Section 4.2.)
5. **Persistence is still required though CAN is connectionless.** The `send`-then-`dump`
   determinism depends on the persistent daemon's FIFO holding the response across the two
   connections, exactly like serial write-then-read. A non-persistent bridge loses it. (Section 2, 5.)
6. **Single-frame ISO-TP ONLY** in the pilot; the privileged DID value is capped at <= 4 bytes to
   keep every PDU in one frame. Multi-frame (FF/CF/FC/STmin) + `can request` are the content-side follow-up,
   not "ISO-TP done." (Section 3.2, 5.)
7. **`RECV_OWN_MSGS` / DLC padding / seed fixedness are diff-relevant knobs.** Own-msgs stays off;
   SF pad is a fixed `0x00` to DLC 8 on both sides; the course seed is FIXED and therefore
   **in diff scope** (must match), not normalized out. (Sections 3.2, 4.4.)
8. **`conformance-can` skips (exit 77), does not fail, when `vcan0` is absent** - it needs the `vcan`
   kernel module + a link, which generic CI may lack. (Section 4.5, 6.)
