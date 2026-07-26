# 02 - The bridge contract: executor spectrum, loopback spawn, virtual vs real

Status: spec, governed by `00-architecture.md`. Grounded in `backends/{socketcan,serial}.py`
and `bridges/server.py`.

A **bridge** is a TCP endpoint that terminates the wire tunnel (`01`). The client connects to a
bridge URL and cannot tell whether the far side is a simulator or real hardware - that
indistinguishability is what makes fidelity structural. This document specifies what a bridge
must satisfy, the relay/stack **executor spectrum** (decision 3), the **loopback auto-spawn**
model for local hardware (decision 5), where the generic real bridge lives, and two concrete
walkthroughs: writing a real CAN bridge (thin relay) and a real BLE bridge (stack runner),
which show the difference the spectrum names.

---

## 1. What a bridge is (the contract)

A bridge:

1. **Speaks `core/wire.py`.** It imports the same module the client does, so it can never drift
   from the wire. The virtual bridge already does (`server.py`); the real bridge must.
2. **Answers the framed handshake.** On `HELLO` it reads `config`, then replies `WELCOME` with a
   `capabilities` dict `{protocol, channels, verbs, shape, meta}` that truthfully describes what
   it can do. `verbs` IS the gate the client enforces; a bridge must not advertise a verb it will
   not serve.
3. **Executes each wire unit** at its position on the spectrum (section 2), producing the wire
   reply the client's codec expects. For a FRAMED protocol that is `OP_RESULT` / `ACK` /
   `SCAN_RESULT` / `FRAME` + `SNIFF_END` / `REPLAYED`. For a RAW-STREAM protocol it pumps raw
   bytes after `STREAM_READY`.
4. **Bounds nothing on the client's behalf and hangs nothing.** The client owns all capture and
   read bounds (`01`). A bridge that goes silent must not be able to wedge the client (already
   guaranteed by the client-side deadlines), and a bridge must not depend on the client sending a
   stop to end a capture.
5. **Never carries content it should not.** The *virtual* bridge serves a device model (and any
   state that model needs) on the content side. The *real* bridge is generalist: it contains no
   device model and no content - it terminates the tunnel into a medium and nothing more. This
   split is the same generalist/content boundary the client keeps, one layer down.

The Backend ABC the client drives (`core/backend.py`:
`open/close/capabilities/scan/sniff/inject/replay/op` + the new `stream_read`/`stream_write`) is
the *client-side* view. A bridge implements the *server-side* half of the same message set. They
meet only at `core/wire.py`.

---

## 2. The executor spectrum (decision 3, made precise)

The framed tunnel carries **semantic ops**. How much work a bridge does to execute one op depends
on how stateful the protocol is. This is a spectrum, not two categories:

```
 RELAY end                                                            STACK end
 (stateless bus)                                                      (stateful stack)
 |------------------------------------------------------------------------------|
 CAN            sub-GHz         Zigbee            SPI / JTAG          BLE GATT
 subghz replay  fixed-code      capture/replay    command seqs        MTU/discovery/
                                (relay) +          over ftdi/openocd   ATT errors/CCCD
                                join/NWK crypto                        (drive BlueZ)
                                (stack)

 wire unit == one real frame            ...            wire unit == one semantic op
 INJECT/SNIFF/REPLAY/FRAME                              OP {verb,args} -> OP_RESULT {result}
```

**Relay end (stateless bus).** One wire unit coincides with one real frame on the medium.
`INJECT` carries a fully-formed PDU the client's codec built (`protocols/can.py`
`encode_frame`); the bridge writes those bytes to the medium verbatim. `SNIFF` puts the medium
in receive mode and emits each received frame as a `FRAME` message; the client writes them to a
pcap. `REPLAY` re-writes captured frames. The bridge holds **no protocol state** - it is a byte
mover with a receive loop. CAN is the canonical case; sub-GHz fixed-code and Zigbee
capture/replay live here too.

**Stack end (stateful stack).** One wire unit is a **semantic op** the client cannot express as a
single medium frame, because the real operation is a multi-PDU transaction against a stateful
peer. `OP {verb:"gatt.read", args:{handle}}` is not "put these bytes on the air"; on real
hardware it is: ensure a connection, exchange MTU, walk the ATT read (possibly Read Blob for a
long value), collect the response, map ATT errors. The bridge **runs the stack** to do that. The
virtual bridge simulates the stack (its `GattServer` model answers the op directly); the real
bridge drives the **OS stack** (BlueZ produces the actual ATT PDUs on air). The client sends the
same op to both and reads the same `result`, so `virtual == real` holds - but the real bridge is a
**protocol-aware executor**, not a byte relay.

**Protocols span the spectrum.** BLE has a relay surface (scan/sniff/inject of raw adv and LL
PDUs, DLT 256) AND a stack surface (`gatt.*` ops). Zigbee has a relay surface (802.15.4
capture/replay, DLT 195) AND, for a join-and-decrypt lab, a stack surface (a real NWK/APS
exchange with AES-CCM*). The spectrum runs *through* a protocol; a bridge implements each surface
at its own position. Each `protocols/*.md` states where its protocol's surfaces sit.

**Honesty the spectrum forces.** For CAN and UART, "the real bridge" is a thin, near-trivial byte
mover - which is why they are the pilots and provable with vcan/pty and zero hardware. For BLE,
Zigbee, SPI, JTAG, sub-GHz-rolling, "the real bridge" is real integration work against an OS stack
or an adapter library, and for BLE/Zigbee it is genuinely *implementing a protocol-aware bridge*.
Do not describe these as "just relaying bytes"; they are not. The matrix in `00` section 6 marks
each bridge's effort accordingly.

---

## 3. Loopback auto-spawn for local hardware (decision 5)

Everything goes over TCP, including local hardware. There are two ways a bridge is reached:

- **Remote / already-running bridge.** `probe --target tcp://host:port` (or `ESP_PROBE`) connects
  to a bridge someone started - the lab (virtual) or a real bridge running near hardware on
  another machine. `--backend virtual` (the default) means exactly "connect to the URL, spawn
  nothing."
- **Local medium, auto-spawned loopback bridge.** `probe --backend serial --target /dev/ttyUSB0`
  (or `--backend socketcan --target vcan0`) stays simple for the user, but the client:
  1. spawns `probe-bridge --medium serial --endpoint /dev/ttyUSB0 --listen 127.0.0.1:0` as a
     child process;
  2. reads back the chosen loopback port (the bridge prints it / writes it to a pipe on ready);
  3. connects to `127.0.0.1:<port>` over the ordinary tunnel;
  4. tears the child down on exit.

  The client's role here is **process orchestration with a generic string passthrough** (map
  `--backend <medium>` to `--medium <medium>`, forward `--target` as `--endpoint`). It performs
  **no medium I/O and holds no medium knowledge** - the bridge opens the port, sets termios/baud
  or binds `PF_CAN`, and runs the receive loop. One extra loopback hop is the accepted cost of
  uniformity: the same bridge contract, the same wire, whether the medium is local or across the
  room.

This is what migrates the in-client `socketcan.py` / `serial.py` syscalls out (`00` section 5):
their `PF_CAN` bind + frame I/O and their raw-fd + termios + select-drain become the CAN and
serial *media* of the generic bridge. After the migration, **adding a real medium = writing a
bridge medium, never touching the client.**

### What the client keeps vs what moves

| Concern | Before (in client) | After |
|---|---|---|
| CAN frame codec (`encode_frame`/`decode_frame`) | `protocols/can.py` | **stays** in the client (it is the shared codec both sides use) |
| CAN `PF_CAN` bind + send/recv | `backends/socketcan.py` | **moves** into the bridge's `can` medium |
| serial raw-fd + termios + select drain | `backends/serial.py` | **moves** into the bridge's `serial` medium |
| pick backend, spawn loopback bridge, connect | (n/a) | thin generic launcher in the client |
| talk the wire | `backends/virtual.py` | the one tunnel client (`backends/tunnel.py`) |

---

## 4. Where the generic real bridge lives

Decision 5 forces this: because the client must be able to auto-spawn the bridge locally, the
generic real/loopback bridge ships **in the probe repo** as a package `espilon_probe.bridges`
with a `probe-bridge` console script. It imports the same `core/wire.py`, so client and bridge
cannot drift.

Crucial boundary that keeps the client core stdlib-only (`00` decision 8):

- `espilon_probe.bridges` is a **separate import surface**. The client core (`espilon_probe.cli`,
  `espilon_probe.core`, `espilon_probe.protocols`) **never imports it**. The launcher spawns
  `probe-bridge` as a *subprocess*, it does not import bridge code in-process.
- **stdlib media (serial, socketcan) carry no third-party dependency**, so `probe --backend
  serial|socketcan` works out of the box.
- **hardware media (ftdi, openocd, hci, sdr, killerbee) carry optional deps**, installed as
  extras (`pip install espilon-probe[ftdi]`) and imported **lazily inside that medium module**.
  A user who never touches SPI never installs `pyftdi`. Each such dependency is a written
  justification scoped to its one medium (`00` decision 8); the client core stays stdlib-only
  regardless.

The **virtual** bridge is content-side and ships with the training content, not in this
generalist repo. Two bridges, two homes, one wire.

---

## 5. Walkthrough A: a real CAN bridge (thin relay)

CAN is the relay end. The bridge is a byte mover; the client's codec already produced real CAN
frames. This is the entire medium, in prose (no implementation code here):

- **Open.** Bind a `PF_CAN` raw socket to the interface named by `--endpoint` (`vcan0`, `can0`,
  `slcan0`). This is exactly the body of today's `backends/socketcan.py::open`.
- **Capabilities.** Reply `WELCOME` with `{protocol:"can", shape:"packet", verbs:["scan","sniff",
  "inject","replay"], meta:{pcap_dlt:227, iface:...}}` - the same caps `socketcan.py` returns
  today.
- **`INJECT`.** Take `msg["frame"]` (hex), decode to bytes, write the 16-byte SocketCAN struct to
  the socket, reply `ACK`. The frame is already a real CAN frame (the client built it via
  `protocols/can.py`); the bridge does not parse or reshape it. Pure relay.
- **`SNIFF`.** Read frames off the socket into `FRAME` messages until the client's bound stops the
  capture; then send exactly one `SNIFF_END`. Each `FRAME.raw` is the 16-byte frame as received.
- **`REPLAY`.** Write each hex frame from `msg["frames"]` to the socket, count them, reply
  `REPLAYED`.
- **No `op`.** CAN advertises no protocol op group; `OP` for CAN is a clean refusal.

That is the whole bridge. Because the frames on `vcan0` are byte-identical to the frames the
virtual bridge's model consumes/produces, `diff-two-bridges` over the same tape passes with zero
device knowledge in the bridge (`03`). This is the proof that "same tunnel, two terminations" is
real, and it needs no hardware (vcan is a kernel loopback).

**The UDS twist (important, and it is a model concern, not a bridge concern).** A UDS lab is
stateful (session -> seed -> key -> DID), but that state lives in the **device model** behind the
virtual bridge, and in the **real ECU** behind the real bridge - never in the CAN bridge itself.
The CAN bridge relays frames either way. So to run the conformance loop with no real ECU, bind the
*same* `UdsEcu` reference model onto vcan0 via a tiny model-to-CAN adapter (read a frame, feed the
model, write the model's response frames back), and drive it with `probe --backend socketcan`. The
relay bridge is untouched; the model is what makes both terminations answer identically. This
model-on-vcan adapter is the CAN conformance harness (`03`, `../protocols/can.md`).

---

## 6. Walkthrough B: a real BLE bridge (stack runner)

BLE spans the spectrum; the GATT ops are the stack end, and they show why a real bridge is not a
relay. Contrast every step with the CAN relay:

- **Open.** Acquire a BLE controller via the OS stack (Linux BlueZ: an HCI socket / the D-Bus
  API). This is not "open a byte pipe"; it is "attach to a protocol stack that manages
  connections, MTU, and pairing for you."
- **Capabilities.** `{protocol:"ble", shape:"packet", verbs:["scan","sniff","inject","replay",
  "gatt"], meta:{pcap_dlt:256}}`.
- **Relay surface.** `scan` -> BlueZ discovery; `sniff` -> put the controller in an observer/sniff
  mode and emit received adv/LL PDUs as `FRAME` under DLT 256; `inject` of a raw adv/LL frame ->
  transmit it (where the controller allows raw TX). These are relay-ish: frame in, frame out, the
  client's `protocols/ble.py` built the raw PDU.
- **Stack surface - this is the difference.** `OP {verb:"gatt.read", args:{handle}}` does NOT map
  to one PDU. The bridge must, using the OS stack: ensure a connection to the target peripheral,
  exchange ATT MTU, issue an ATT Read (or Read Blob for a long value), collect the response, and
  map an ATT error (`0x02` Read Not Permitted, `0x05` Insufficient Authentication, ...) into the
  op result. `gatt.write` is the same in reverse; `gatt.enum` is a full service/characteristic
  discovery (declaration + value + CCCD handles). The bridge is **running the GATT client stack**.
  The client sent one semantic op and reads one `result`; it never sees the ATT choreography - and
  that is exactly why the virtual `GattServer` (which answers the op directly) and the real BlueZ
  path are observationally equal at the op surface.

The honest consequence: the CAN bridge is a weekend of relay code over `PF_CAN` (stdlib). The BLE
bridge is a real integration against BlueZ (D-Bus/HCI), plus a dependency call (`00` decision 8),
plus - for a pairing lab - SMP, which the OS stack may or may not expose the way the lab needs.
This is why BLE sits at sequence position 4, gated on `GattServer` landing first so the model side
is proven before the stack-runner bridge is built.

---

## 7. The bridge checklist (for any new medium)

To add a real medium, implement one `probe-bridge` medium module satisfying:

1. Imports `core/wire.py`; never drifts from the client's wire.
2. Maps `--endpoint` to the device/interface; opens it; fails clean if it cannot.
3. Advertises truthful `capabilities` (protocol, shape, verbs, meta incl. `pcap_dlt` for packet
   protocols) - matching the caps the corresponding virtual bridge advertises for the same
   protocol, so the client behaves identically against both.
4. Executes each wire unit at its spectrum position: relay frames for `INJECT`/`SNIFF`/`REPLAY`;
   run the stack for each semantic `OP`; raw-pump bytes after `STREAM_READY` for a stream medium.
5. Carries no flag, no device model, no course content - generalist only.
6. Keeps third-party deps optional and lazy so the client core stays stdlib-only; each dep is a
   written justification scoped to that medium.
7. Passes `03`'s conformance tape set against the matching virtual bridge (where a software medium
   exists) or a documented spot-check against real silicon (where it does not).

Meet the checklist and the client never changes: `probe can send`, `probe gatt read`,
`probe uart read` route to the new bridge unaltered.
