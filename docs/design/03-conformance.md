# 04 - Conformance: proving the two terminations agree

Status: spec, governed by `00-architecture.md`. Builds on `01` (transport), `02` (bridges), the
content-side device models, and the fidelity contract in `00` section 4.

The contract claim is: **the same command tape run against the virtual bridge and the real bridge
is observationally equal** (`00` section 4). This document specifies the harness that proves it -
the tape format, the runner, the normalizer, the "same tape, two bridges" diff - restates the
contract as testable per-protocol assertions, defines what "a protocol passes" means, places the
harness in CI, and states the honest per-protocol limits plainly.

---

## 1. Where the harness lives (the boundary)

Two pieces, on the correct side of the generalist/authoring boundary:

- **Client-side, in the probe repo: `conformance/`** - the tape format, the runner, and the
  normalizer. This is generalist: tapes name `probe` verbs (argv), never flags or device
  internals. It ships with probe and is what a reviewer runs. It reuses no course knowledge.
- **Content/medium-side: the model-to-medium adapters** - a tiny loop that binds the *same* device
  model onto a real medium so `probe --backend <medium>` can drive it (the `UdsEcu`-on-vcan
  adapter of `02` section 5; a `Console`-on-pty adapter for UART). Model-bearing adapters are
  content-side; the generic media themselves are `probe-bridge` media (`02` section 4).

The construction that makes "virtual vs real" real: **run the same model two ways** - once behind
the virtual bridge over TCP, once bound onto a real medium behind the real bridge - and diff the
normalized observables.

---

## 2. Tape format

A **tape** is an ordered list of `probe` invocations plus its expected observables. Keep it plain
data (JSON or a trivial line format), no DSL, no expression language - the simplest thing that
runs:

```
# each step: the argv (after `probe`), and the artifacts it produces
steps:
  - argv: ["--baud", "57600", "uart", "read", "-t", "2"]
  - argv: ["--baud", "57600", "uart", "write", "printenv\r\n"]
  - argv: ["--baud", "57600", "uart", "read", "-t", "2"]
# two run modes:
#   expected: pinned stdout/exit/pcap for a single-backend assertion, OR
#   diff:     no pinned expectation; run against TWO backends and compare (the primary mode)
```

Two modes:

- **`expected` mode** - the tape pins the normalized stdout, exit code, and (if any) pcap
  frame-payload list. Good for a fast single-backend regression and for the virtual-self-consistent
  bar (section 6) when no real bridge exists yet.
- **`diff` mode** (the primary mode) - no pinned expectation; the runner executes the tape against
  two backends (`--backend virtual` vs `--backend <real>`) and asserts the normalized observables
  match. This is the direct proof of the contract.

Tapes are argv-only. A tape must be writable by someone who knows only the `probe` CLI and the
course, never the device internals - that is what keeps the harness generalist.

---

## 3. Runner and normalizer

**Runner.** For each step, invoke `probe` with the step argv against the target backend, capturing
stdout, exit code, and any pcap it writes (`-w`). For a stream tape, the connection is per-verb
(`01`); the runner does not need to keep a session. It reuses the virtual bridge's spawn/teardown
machinery and the loopback-bridge spawn (`02`) for the real one.

**Normalizer.** Before comparing, strip exactly the allowed-to-differ list pinned in `00` section
4 (and no more - over-normalizing hides real drift):

- pcap record timestamps (`ts_sec`/`ts_usec`);
- declared-random link identifiers (BLE random BD_ADDR, 802.15.4 sequence numbers, an ephemeral
  SMP IRK);
- RSSI / signal-quality fields;
- inter-frame wall-clock spacing (order is kept; microsecond gaps are dropped);
- a seed/nonce **only if** the scenario documents it random (a course-fixed seed stays in scope).

Everything else is compared byte-exact. The normalizer is a fixed, small, pinned-once transform;
adding a field to it is a deliberate, reviewed change, not a convenience.

**Comparison per surface:**

- **stdout** - byte-for-byte after normalization.
- **exit code** - exact.
- **pcap** - the ordered list of frame `raw` payloads, byte-for-byte (timestamps normalized out;
  order within the same instant tolerated only for a genuinely unordered protocol).
- **RAW-STREAM stdout** - because a stream has no message boundaries, there is nothing to
  normalize about chunking: drain each backend's RX to EOF/idle, **concatenate**, compare the two
  byte strings. The OS coalesces; the comparison is `rx_virtual == rx_real`. This is *simpler* than
  the framed case, not harder.

---

## 4. "Same tape, two bridges" diff

The diff run for a protocol with a software medium (CAN, UART) needs no hardware:

- **UART:** virtual = `probe --backend virtual` -> BridgeServer -> `ConsoleDevice`. Real = a
  `Console`-on-pty adapter bound to the master side of a `pty` pair, driven by `probe --backend
  serial --target /dev/pts/N` (which auto-spawns the loopback serial bridge). Drive the same TX
  tape into both, drain RX with a `-t` larger than any device latency, concatenate, assert equal.
  Cheapest possible closed loop.
- **CAN:** virtual = `probe --backend virtual` -> BridgeServer -> `UdsEcu`-composing device. Real =
  the same `UdsEcu` model bound onto `vcan0` by a model-to-CAN adapter, driven by `probe --backend
  socketcan --target vcan0`. Run the UDS happy path + every documented failure branch through
  `diff-two-bridges` over vcan0.

For a protocol whose real medium is hardware-only (SPI/JTAG/BLE/sub-GHz/Zigbee), the diff run
requires the real bridge and, where you own silicon, a spot-check tape straight against the
chip. Until then those protocols reach only the weaker bar (section 6).

---

## 5. The contract as per-protocol assertions

`diff-two-bridges` proves observational equality; on top of it, each protocol adds spec assertions
that pin the behavior a wrong action must produce. A tape set covers the **happy path + every
documented failure branch**. Per protocol (detail in each `protocols/*.md`):

- **UART** - banner observable before the first command response on both backends; a command's
  response appears after the echo of that command; bytes of banner/echo/response match (ms need
  not). Wrong-baud: read is not readable and no flag byte survives - **asserted on virtual (model
  garble) or real hardware (physics), never a pty** (section 7).
- **CAN/UDS** - every documented NRC appears on its branch (`7F 27 35` invalidKey, `7F 27 33`
  securityAccessDenied, `7F xx 22` conditionsNotCorrect, `7F xx 78` responsePending); a wrong key
  never advances state; a fixed course seed reproduces; ISO-TP multi-frame reassembles identically.
- **SPI** - named-verb result == raw-`xfer`-command result through the same model (`spi.read` ==
  clocking `03 aa bb cc`); a write without WREN is refused; RDSR WIP asserts on write/erase; page
  program wraps at the page boundary.
- **JTAG** - scan-chain/IDCODE stable; a locked core refuses `halt` (or returns zeros / bus-fault
  per the declared fault mode); word read/write and fill match.
- **BLE** - GATT discovery handle layout + read/write + the ATT error-code table match the model; a
  write to a read-only characteristic returns `0x03` Write Not Permitted, not the branch's guess;
  the captured unlock frame dissects under DLT 256.
- **sub-GHz** - fixed-code: sniff -> replay unlocks on both; encoding: `demod` hint matches the
  staged encoding; rolling: a replayed old code is rejected.
- **Zigbee** - the staged capture decrypts under the declared keys with an **independent**
  reference AES-CCM* (not the builder), the recovered network key matches, MAC FCS validates.

---

## 6. What "a protocol passes" means

A protocol **passes fidelity** when its curated tape set (happy path + every documented failure
branch) runs `diff-two-bridges` and comes back observationally equal, **and** its spec assertions
(section 5) hold.

- **CAN and UART can reach *pass* now** - real software media (vcan, pty) exist, so
  `diff-two-bridges` runs in CI with no hardware.
- **The others reach *pass* only after their real bridge is built.** Before that they reach a
  weaker, still-useful bar: **virtual-self-consistent** = `expected`-mode tapes hold + the internal
  invariants hold (named-verb == raw-command through the same model; spec assertions on the virtual
  side). This bar catches model drift; it does not prove transport fidelity, and the docs must not
  claim it does.

A real bridge without a hardened reference model validates nothing useful; a reference model
without a real bridge reaches only the virtual-self-consistent bar. They advance together (`00`
section 7).

---

## 7. CI and the honest per-protocol limits

**CI.** The `conformance/` runner + normalizer + the two software-medium diff loops (UART on pty,
CAN on vcan) run in CI on every change, alongside the existing client unit tests. vcan needs the
`vcan` kernel module and a `vcan0` link; pty needs nothing.
Neither needs hardware. The CI runner target is the H2 roadmap item (memory: roadmap north-star).

**Honest limits - state them, do not paper over them:**

- **pty/TCP cannot exercise baud garble.** A pty and a TCP socket have no bit clock; they pass
  bytes through regardless of the requested rate. So the wrong-baud garble is proven on the
  **virtual** backend (model garble) or **real USB-UART** (physics), never a pty. A pty proves the
  stream plumbing (order, presence, echo, EOF, the read timeout) and nothing about baud (`01`,
  `../protocols/uart.md`).
- **Microsecond-precise timing is out of fidelity scope.** TCP (and the loopback hop) add
  latency/jitter, so fault-injection/glitching and some precise RF timing are not in scope and not
  asserted (`00` decision 8). Order and payload are; wall-clock is not.
- **vcan is not a transceiver.** vcan proves framing/relay fidelity and the UDS state machine over
  a real SocketCAN path, but not bus-error/arbitration/bit-timing physics; those need real CAN
  hardware and are a spot-check, not a CI gate.
- **No real silicon in CI for SPI/JTAG/BLE/sub-GHz/Zigbee.** Their real bridges validate against a
  board / adapter / sniffer you own, as a spot-check tape run out of band; CI holds them to
  the virtual-self-consistent bar until then.

Passing the harness is the release gate for a protocol's real bridge; the virtual-self-consistent
bar is the gate for a reference-model change before its bridge exists.
