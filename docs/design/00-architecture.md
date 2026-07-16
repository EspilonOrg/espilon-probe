# 00 - Fidelity architecture: everything over TCP, a backend is a bridge

Status: **SOURCE OF TRUTH.** This document governs the rest of the corpus. Where any other
doc disagrees, this one wins. The architecture is decided; this formalizes it and makes it
precise.

The goal is unchanged: **a skill learned against a virtual target transfers 1:1 to real hardware,
because the same `probe` command sequence produces the same client-observable result against
the real device.** What changed is *where fidelity is enforced*: not by author diligence, but
structurally, by construction of the transport.

Read alongside:
- `01-transport.md` - the wire tunnel (handshake, the two payload shapes, the raw-stream seam).
- `02-bridge-contract.md` - what a bridge is, the relay/stack executor spectrum, loopback spawn.
- `03-conformance.md` - the harness that proves the two terminations agree.
- `protocols/*.md` - one per protocol; UART and CAN are the detailed pilots.
- `protocol-conventions.md` and `protocol-{jtag,spi,subghz}.md` - the byte-level codec specs
  this corpus points at and does not restate.

---

## 1. The nine load-bearing decisions

These are locked. The rest of the corpus makes them precise. Do not re-litigate; expand.

1. **Everything over TCP.** The `probe` client is ALWAYS a TCP client speaking the wire tunnel
   (`core/wire.py`). There is NO per-medium I/O in the client. The client's only per-protocol
   work is the **frame codecs** (build a real PDU from verb args; parse a real PDU to output -
   `protocols/*.py`) plus talking TCP. No challenge, no flag, no device, no course knowledge
   lives in the client.

2. **A backend IS a bridge = a TCP endpoint.** The client connects to a bridge URL and cannot
   tell what is on the far side:
   - **virtual bridge** = a simulator (a training target), serving a device model;
   - **real bridge** = a daemon that terminates the tunnel into a real medium (CAN, serial,
     SPI/JTAG, radio).

   The client connects to a bridge in both cases and **cannot distinguish them**, so fidelity
   is **STRUCTURAL, not asserted**. "More faithful to real hardware" is not a property the
   client can have or lack; the client is a pipe.

3. **The bridge is a PROTOCOL-AWARE EXECUTOR on a spectrum, not a dumb byte relay.** The framed
   tunnel carries **semantic ops**. Where a protocol is a stateless bus (CAN), one op coincides
   with one real wire frame, so the bridge is a **thin relay** (op == "put this frame on the
   wire"). Where a protocol is a stateful stack (BLE GATT, Zigbee NWK/APS), the op is
   **semantic** (e.g. `gatt.read handle`) and the bridge **RUNS THE STACK**: the real bridge
   drives the OS protocol stack (BlueZ for BLE, an 802.15.4 stack for Zigbee), the virtual
   bridge simulates it. `virtual == real` still holds because the client only ever sees
   `op -> result`. Be honest: **writing a real BLE or Zigbee bridge means implementing a
   protocol-aware bridge over the OS stack, not relaying bytes.** `02` specifies this spectrum.

4. **Two payload shapes over the one TCP tunnel.**
   - **FRAMED** (CAN, BLE, JTAG, SPI, Zigbee, sub-GHz): one wire unit = one real PDU or one
     bounded transaction/op. Carried by the existing length-prefixed-JSON messages.
   - **RAW-STREAM** (UART, consoles): the socket is a bidirectional byte pipe; `read`/`write`
     are `recv`/`send`. No framing on the data path.

   The handshake negotiates **protocol + shape + capabilities + baud/params**. Boundary
   criterion (`protocol-conventions.md` rule 3, restated as a decision test): **does the
   physical layer define message boundaries?** Yes -> FRAMED; no -> RAW-STREAM. `01` specifies
   the negotiation and the raw-stream upgrade seam.

5. **Local hardware = a LOOPBACK AUTO-SPAWNED bridge.** Everything goes over TCP, including
   local hardware. `probe --backend serial --target /dev/ttyUSB0` stays simple for the user,
   but internally probe **auto-spawns a local loopback bridge** that opens the port/medium and
   exposes it over a localhost TCP port, then connects to that. Same bridge contract as a remote
   bridge; one extra loopback hop, accepted for uniformity. The in-client `socketcan` and
   `serial` **direct-syscall backends migrate into these bridges**. This is the core rework and
   is exactly what makes *"add a real medium = write a bridge, never touch the client."* `02`
   specifies the spawn model.

6. **Fidelity contract = "same tunnel, two terminations."** The same command tape run against
   the virtual bridge and the real bridge must be **observationally equal**: op/PDU/byte
   payloads, their order, and exit codes match. Wall-clock timing, MAC/BD_ADDR randomness,
   RSSI, and inter-frame spacing are allowed to differ. Proven by the conformance harness (`03`).

7. **The generalist/content boundary holds identically on RAW-STREAM and FRAMED.** Any device
   model, and any state a virtual target must hold to answer faithfully, lives **behind the
   virtual bridge**, entirely on the content side. The client and the wire carry no device,
   target, or content knowledge either way. Going raw changes *how bytes leave* (written to a
   socket vs returned from an op), not *where the model lives*: the content side stays the same
   generalist/content split the client keeps, one layer down (`02`).

8. **Honest caveats, stated plainly.** TCP adds latency and jitter, so **microsecond-precise
   timing** (fault-injection / glitching, some precise RF work) is **OUT of fidelity scope** and
   documented as such. A real or loopback bridge is **an extra process** running near the
   hardware (a Pi, an ESP, a laptop, or localhost for loopback). The **client core stays
   stdlib-only**; third-party dependencies live in bridges, never in the client core.

9. **Build sequence.** UART (RAW-STREAM pilot) + CAN (FRAMED pilot, real bridge via
   socketcan/vcan) first; then SPI/JTAG; then BLE; then sub-GHz/Zigbee. A real bridge without a
   hardened reference model validates nothing useful; a reference model without a real bridge
   reaches only the weaker *virtual-self-consistent* bar. They advance together.

---

## 2. The picture

```
                       ONE client, ONE wire, TWO terminations

  operator
     |  verbs: scan / sniff / inject / replay  (+ gatt, can, uart, jtag, spi, subghz)
     v
  +------------------------------------------+
  |  probe   (TCP tunnel client)             |  stdlib-only. NO medium I/O, NO device, NO flag.
  |  core/wire.py + protocols/*.py           |  per-protocol work = real PDU codec + talk TCP.
  +--------------------+---------------------+
                       |
        FRAMED (length-prefixed JSON: semantic OPs + hex PDUs)   OR   RAW-STREAM (raw bytes)
                       |
                       v
              +------------------+
              |    a BRIDGE      |  a TCP endpoint. The client cannot tell which kind it is.
              +--------+---------+
                       |
       +---------------+--------------------------------------------------+
       v                                                                  v
  VIRTUAL bridge                                                     REAL bridge
  (a simulator; a training target)                                 (generalist; near the medium)
  BridgeServer + a device model                                    terminates the tunnel

  and, WITHIN a bridge, the executor sits on a SPECTRUM:

  ---- RELAY end (stateless bus) --------------------      ---- STACK end (stateful stack) ------
  wire unit == one real frame                              wire unit == one semantic op
  INJECT/SNIFF/REPLAY/FRAME  <-> put/take a frame          OP {verb,args} -> OP_RESULT {result}

  virtual: simulate the bus                                virtual: simulate the stack
     e.g. CAN frame in/out of the model                      e.g. the model answers gatt.read
  real:    write/read the medium verbatim                  real:    DRIVE the OS stack
     e.g. socketcan send/recv on vcan0                        e.g. BlueZ GATT read for gatt.read
                                                                    openocd mdw for jtag.read
                                                                    ftdi MPSSE 0x03 for spi.read
```

Because both terminations are reached over the identical wire, fidelity lives entirely on the
two far terminations: the content side owns the model (what a device answers), `02` owns the
medium side (how a real op reaches the wire), and the harness (`03`) proves the two terminations
of the *same* model agree.

---

## 3. Where fidelity actually lives

Fidelity is two problems on the far side of the tunnel, never a client problem:

1. **Transport / codec / executor fidelity** - the bytes probe emits and parses must be the
   bytes a real bus carries, and a semantic op must produce, on the real medium, the PDUs a real
   stack would. Owned by the **real bridges** (`02`) and the **shared codecs** (`protocols/*.py`).
   Where a real bridge exists (CAN via vcan, UART via pty), this is *directly testable* with no
   hardware.
2. **Model fidelity** - the virtual target's responses must match what a real device answers
   (state machine, NRC/ATT error codes, register semantics, crypto). Owned by the **device
   models** behind the virtual bridge, on the content side.

Honest split of the total effort: roughly 10% client (the transport rework in section 5),
about 40% the virtual-side device models, about 50% building and validating the real bridges.
The gain is **structural** (targets faithful by construction, not by author diligence), not a
line-count win.

One honesty point carried forward: for CAN and UART a real *medium* exists in software (vcan,
pty), so virtual-vs-real equality is provable today. For BLE/Zigbee/sub-GHz/SPI/JTAG there is
neither a real bridge nor real silicon in CI yet. Even once those bridges exist, the achievable
contract is *"the same model served over the virtual tunnel and over the real medium is
observationally identical, and the model is spec-conformant"* - **not** fidelity to an arbitrary
commercial device. We bound it to "spec-conformant + spot-checked against silicon you own."

---

## 4. The fidelity contract (testable definition of "no difference")

Given a **tape** `T` = an ordered sequence of `probe` invocations (argv only, no backend
knowledge), and two runs:

- `virtual(T)` - `probe` against the virtual bridge over TCP.
- `real(T)` - `probe` against the real bridge (which terminates into the real medium) driving
  the *same* device model.

The contract: **`virtual(T)` and `real(T)` are observationally equal.**

| Surface | Must match | May differ |
|---|---|---|
| **stdout** | byte-for-byte after normalization | - |
| **exit code** | exactly | - |
| **pcap frames** | the ordered list of frame `raw` payloads, byte-for-byte | per-frame `ts` (wall clock); frame order *within the same instant* only if the protocol is genuinely unordered |

Normalized out before diff (the allowed-to-differ list, pinned once):

- pcap record timestamps (`ts_sec`/`ts_usec`);
- randomized link identifiers the protocol declares random (BLE random BD_ADDR, 802.15.4
  sequence numbers, an ephemeral SMP IRK);
- RSSI / signal-quality fields;
- CAN/radio inter-frame *wall-clock* spacing (the *order* is in scope, the microsecond gaps are
  not);
- a seed/nonce **only if** the scenario documents it as random. A seed the course teaches as
  fixed (e.g. UDS `SEED=0x1234`) is **in scope** and must match.

Always in scope: every PDU byte sent and parsed; every state transition and its error/negative
response (UDS NRC, ATT error code, WREN-gated refusal, DAP-lock refusal); the observable result
of a wrong action. `03` restates this as concrete per-protocol assertions.

---

## 5. Migration impact (client rework)

The rework is small in the client and localized. Concretely:

- **Delete** the direct-syscall bodies of `src/espilon_probe/backends/socketcan.py` and
  `backends/serial.py`. Their `PF_CAN` / raw-fd I/O moves into the generic bridge (`02`). Their
  shared *codec* logic already lives in `protocols/can.py` (`encode_frame`/`decode_frame`) and
  stays - that is the point of the codec being separate from the backend.
- **Collapse** `backends/` toward a single tunnel client. `backends/virtual.py` is no longer
  "virtual-specific" (it serves virtual and real bridges alike). Recommended: rename it to
  `backends/tunnel.py` (or keep the filename; naming is cosmetic). It gains the RAW-STREAM
  regime (`01`).
- **`--backend` keeps its user-facing meaning but changes internally.** Under decision 5:
  - `--backend virtual` (default): connect to the `--target` / `ESP_PROBE` TCP URL. No medium,
    no spawn. This reaches the lab or any already-running remote bridge.
  - `--backend socketcan|serial|ftdi|openocd|hci|sdr|killerbee`: **auto-spawn a local loopback
    bridge** for that medium at `--target` (device path / interface), then connect to it over
    loopback TCP. The client's job here is process orchestration (spawn `probe-bridge --medium
    <m> --endpoint <target> --listen 127.0.0.1:0`, read back the chosen port, connect) - a
    generic string passthrough, **not** medium I/O. So the CLI ergonomics are unchanged while
    the client contains zero medium logic.
- **`core/wire.py`** gains exactly two control messages (`STREAM_ATTACH` / `STREAM_READY`) and
  the documented raw-upgrade seam. The FRAMED codec is untouched. This is the only structural
  wire change (`01`).
- **`core/backend.py`** gains concrete `stream_read` / `stream_write` defaulting to a clean
  refusal, so FRAMED backends inherit a refusal for free and only the tunnel overrides them (`01`).
- Everything else in the client - the CLI verbs, the protocol codecs, the pcap writer, the
  capability gate - is unchanged. `probe can send 7DF 1003` still builds the same 16-byte
  SocketCAN frame; it now travels to a bridge instead of a direct `PF_CAN` socket.

The content and bridge side is where the weight is (`02`, `03`).

---

## 6. At-a-glance matrix

Current fidelity and gap severity are stated at the **contract surface** (what a `probe` user
observes), not at the RF/bit level probe never exposes. Severity: *cosmetic* (a label, invisible
to a solve), *meaningful* (a behavior a player hits that would break transfer to hardware),
*fundamental* (the model abstracts away the thing the skill is about).

| Protocol | Shape | Executor position | Current fidelity | Real bridge today | Gap severity | Effort (model / bridge) | Sequence |
|---|---|---|---|---|---|---|---|
| **UART** | RAW-STREAM | raw byte pump | High (baud garble faithful) | **Yes** (serial/pty, stdlib) | cosmetic-meaningful | S / S | **1 (mechanism)** |
| **CAN** | FRAMED (packet) | relay | High (codec shared; UDS hand-rolled) | **Yes** (socketcan/vcan, stdlib) | meaningful | M / S | **2 (depth)** |
| **SPI** | FRAMED (transaction) | stack (command sequences) | Med-high (FlashModel, sealed reads) | No (ftdi) | meaningful | M / L | 3 |
| **JTAG** | FRAMED (transaction) | stack (openocd) | Med-high (TapModel, sealed reads) | No (openocd) | meaningful | S-M / M-L | 3 |
| **BLE** | FRAMED (packet + op) | relay (adv/inject) + stack (GATT) | Med (adv+unlock faithful; GATT hand-rolled; no SMP) | No (hci) | meaningful (GATT) / fundamental (SMP) | M+L / L | 4 |
| **sub-GHz** | FRAMED (packet) | relay | Low-med (fixed-code OK; no encoding/rolling) | No (sdr) | cosmetic (fixed) / fundamental (rolling) | M / L | 5 |
| **Zigbee** | FRAMED (packet) | relay (capture/replay) + stack (join/NWK crypto) | Low (placeholder layering, no crypto) | No (killerbee) | fundamental | L / L | 5 |

"FRAMED (packet)" vs "FRAMED (transaction)" is the same transport (length-prefixed JSON); the
parenthetical is the semantic shape (`protocol-conventions.md` rule 3) that decides verb
applicability. "Executor position" places the protocol on the relay/stack spectrum of decision 3
(`02`); several protocols span it (BLE, Zigbee).

---

## 7. Build sequence

Prove the whole loop cheaply, then add depth, then build the hardware-bound bridges last.

1. **UART - mechanism pilot.** Cheapest closed loop: pty pair, no hardware, baud garble already
   faithful. Stand up the RAW-STREAM tunnel regime, the loopback serial bridge, the
   `conformance/` runner + normalizer, and get `diff-two-bridges` green. Shakes out the harness
   with the fewest moving parts. (`../protocols/uart.md`, `01`, `03`.)
2. **CAN - depth pilot.** The flagship dual-purpose proof, real medium (vcan) today. Build the
   generic loopback CAN bridge, add a `UdsEcu` reference model + ISO-TP flow control on the
   content side, and run `diff-two-bridges` over vcan0. Proves the reference-model pattern *and*
   the virtual-vs-real contract end to end with zero hardware. (`../protocols/can.md`.)
3. **SPI + JTAG** reference-model hardening in parallel with building the `ftdi` and `openocd`
   bridges. SPI validates against real NOR silicon (cheap); JTAG against a dev board or QEMU.
4. **BLE.** Land the `GattServer` model first (testable virtual-self-consistent immediately),
   then build the `hci` bridge (drives BlueZ - a protocol-aware bridge, not a relay) and validate
   against a BLE peripheral you own. Defer SMP unless an objective *is* pairing.
5. **sub-GHz and Zigbee** last - real RF, real crypto, hardware sniffers. Zigbee gates on getting
   AES-CCM* exactly right so `zbdsniff` decrypts; do it when a scenario genuinely needs
   decryptable captures.

---

## 8. What this corpus does NOT silently decide

The big forks are resolved (decisions 1-9). Two small implementation choices remain, flagged
here rather than decided in passing; both are non-blocking for the UART and CAN pilots:

1. **Exact tunnel-client filename.** Rename `backends/virtual.py` -> `backends/tunnel.py` vs keep
   the name. Cosmetic; recommendation is to rename for honesty (it is no longer virtual-only).
   Not load-bearing. (`01`, `00` section 5.)
2. **`transport_shape` explicit field vs derive from `shape`.** Recommendation: derive
   (`stream` -> RAW-STREAM; `packet`/`transaction` -> FRAMED) so there is nothing new to keep in
   sync. (`01`.)

The generic-bridge home is **decided by decision 5**: because the client must be able to
auto-spawn it locally, the generic real/loopback bridge ships **in the probe repo** as
`espilon_probe.bridges` with a `probe-bridge` console script, importing the same `core/wire.py`
so it can never drift. It is generalist infrastructure (no course content), so it belongs with
the client - but as a **separate import surface the client core never imports**, so the client
core stays stdlib-only and bridge dependencies are optional extras (`02` section 2).
