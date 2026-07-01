# Devlog

Running log of changes while the repo is pre-git. Each entry is a pending "commit": a
conventional-commit title plus what changed and why. When we cut the real git history,
these become the commit messages.

---

## 021 - fix(cli): honest error messages across all 7 protocols (Audit-A polish)

Cosmetic follow-up to entry 020. The BLOCKER fix guarded jtag/spi at source, but three
at-source paths still leaked Python-internals text under the clean `probe:` prefix for the
remaining protocols (ble/zigbee/subghz + the read/inject hex paths). No safety/leak change:
the anti-leak BLOCKER is already closed. The verb gate, DLT logic, bounded sniff, and the
catch-all backstop are untouched. Only the wording is made honest/consistent.

- `cli.py`: new `_scan_rows()` normalizes the generic `scan` result before the display loop
  (skips non-dict rows, refuses a non-list `items` with `backend returned non-list scan
  items`), the same pattern jtag/spi `scan_rows` already use, so ble/zigbee/subghz `scan` stop
  rendering `'NoneType' object has no attribute 'get'`.
- `backends/virtual.py`: `scan()` refuses a non-list `items` loud at the backend boundary
  rather than passing a guessed shape to the display loop.
- `cli.py`: `_fmt_value` now routes through `_hex_field` (reuses spi's guarded `_hex_bytes`),
  so a bad backend hex value on `spi read` / `gatt read` gives `backend returned malformed hex
  for <field>` instead of `non-hexadecimal number found in fromhex()`. spi.dump already used
  the guarded path; interactive read is now consistent.
- `cli.py`: new `_parse_hex()` (sibling of `_parse_int`) validates operator `--hex` on
  `inject` and `spi write` at source, so `probe inject --hex zz` reads `invalid hex ...`
  matching the address-error wording instead of fromhex's text.
- `tests/test_error_honesty.py` (new): a malformed scan row on a packet protocol, a bad
  backend hex on gatt/spi read, and operator inject/spi-write `--hex` garbage, each asserting
  the clean protocol-level message and no Python-internals text.

Suite: 112 passed, 1 skipped.

---

## 020 - fix(protocols): crash-proof the transaction-scan + transaction-result paths

Sprint 2 audit BLOCKER: a malformed backend response could leak a raw Python traceback
(AttributeError/TypeError), violating the "no traceback on hostile input" contract this sprint
exists to honor. On a lab bridge the player partly controls these responses, so it was a real
parser-robustness hole. Fixed on the same branch.

BLOCKER - crash-proof the transaction paths:
- `core/fields.py` (new): `as_int`/`as_int_list` - the single sound place that coerces a
  backend numeric/list field or refuses with a field-named `ProbeError` (rejects bool/float/
  None/unparseable-string/non-list), instead of letting `int()`/`.get()` leak their own text.
- `protocols/jtag.py`: a `_result()` wrapper refuses a null or non-dict `op()` result (the wire
  carries JSON null, which `virtual.op`'s `.get("result", {})` passes through as None). New
  `taps()` normalizes a `taps` that is None/non-list (clean refusal) and skips null/non-dict
  rows, coercing idcode/index via `as_int`; `scan_rows`/`read_words`/`dump` go through it.
- `protocols/spi.py`, `protocols/subghz.py`: same `_result()` guard; `spi` adds `_hex_bytes`
  (a non-string / bad-hex `data` refuses clean); `subghz.band_list` refuses a non-list `bands`
  and drops non-dict rows.
- `cli.py`: the dispatch loops now use the coerced helpers (`jtag.taps`, `jtag.read_words`,
  `subghz.band_list`, `as_int` on idcode/pc/reg/jedec). `main()` catch list gains
  `AttributeError, TypeError, KeyError` as a backstop so no future malformed dict from any
  protocol can leak a stack trace.

MINOR 1 - numeric backend fields validate in the protocol layer: a string idcode/word/jedec
that is not a valid number raises a protocol-level `ProbeError` ("backend returned non-numeric
idcode ...") instead of a bare "invalid literal for int()".

MINOR 2 - sniff/replay DLT source agreement: `backends/virtual.py::sniff` no longer falls back
to a silent DLT 147 when the bridge omits `pcap_dlt`; it refuses loud (`ProbeError`), agreeing
with `replay` so a misconfigured bridge cannot produce a capture its own replay then rejects.

Tests: pinned the reviewer's repros - None/dict/null taps, an explicit null result, a string
idcode, a string word, a non-list bands, sniff-without-pcap_dlt - plus `test_fields.py` for
the coercion helpers and the cli.main backstop. Suite: 104 passed, 1 skipped (was 80/1).

Contract note (deferred per reviewer): `--band` stays a client-side filter for v1.

## 019 - feat(protocols): sprint 2 - JTAG, SPI, sub-GHz virtual protocols

Three new protocols implemented exactly to the architect's specs
(`docs/protocol-{jtag,spi,subghz}.md`) on top of the Sprint 1 conventions (C1 ProbeError +
verb gate, C2 `Capabilities.shape`, C4 replay-DLT). No Backend-contract or wire change: the
architect's conclusion held - `op()`/`OP`/`OP_RESULT` carry every transaction, radio params
ride in existing fields and the sub-GHz pseudo-header.

DLT registry: added `DLT_USER_PROBE_SUBGHZ=147`, `DLT_USER_PROBE_SPI=148`,
`DLT_USER_PROBE_JTAG=149` to `core/frame.py` (the libpcap LINKTYPE_USER range), mirroring the
conventions doc registry so both wire sides and the docs never drift.

- JTAG (`protocols/jtag.py`, shape=transaction): verbs `["scan", "jtag"]`. `scan` is the
  scan-chain enumerate; the `jtag` group adds scan-chain/idcode/halt/resume/read/write/reg/
  dump. `sniff`/`inject`/`replay` GATED OUT (advertised-verbs gate). Default artifact = raw
  binary memory image from `dump` (C3 sugar over `jtag.read`, 16 MiB client ceiling, whole-
  word lengths only); optional transaction pcap under DLT 149.
- SPI (`protocols/spi.py`, shape=transaction, master role): verbs `["scan", "spi"]`. `scan` is
  JEDEC-ID enumerate; the `spi` group adds id/read/write/reg/xfer/dump. `sniff`/`inject`/
  `replay` GATED OUT. Default artifact = raw binary flash image from `dump` (C3 sugar over
  `spi.read`, 32 MiB ceiling, 4 KiB chunks); optional transaction pcap under DLT 148.
- sub-GHz (`protocols/subghz.py`, shape=packet): all four core verbs apply, BOUNDED (reuses
  the Sprint-1 client-side sniff bound); the `subghz` group adds demod (HINT only, no solver)
  and bands. Radio params `--freq`/`--mod`/`--rate` extend the core verbs; `inject` builds the
  8-byte pseudo-header so a transmitted frame self-describes its params. DLT 147 with the
  documented pseudo-header; `replay` validates DLT==147 (C4). `scan --band` filters client-side
  on the advertised band ranges, refusing an unknown band.

CLI: `_VERB_REQUIRES` extended with jtag/spi/subghz group gating; `scan` is protocol-aware
(transaction protocols enumerate via the protocol module's `op()`-backed rows); int args
(addr/word/len) parse via a clean `_parse_int` helper (ProbeError, no traceback).

Tests: `test_jtag.py`, `test_spi.py`, `test_subghz.py` cover the verb set, capability gating
(sniff/inject/replay fail clean on JTAG/SPI), idcode/JEDEC enumerate, dump artifacts +
optional DLT pcaps + the dump ceiling, sub-GHz pseudo-header round-trip + bounded sniff +
replay DLT match/mismatch + band filter. Suite: 80 passed, 1 skipped (was 46/1).

## 018 - feat: sprint 1 hardening (bounded sniff, C1 clean errors + verb gate, C4 replay DLT, protocol honesty)

Retrofitted the four existing protocols and the core onto the cross-cutting conventions
(`docs/protocol-conventions.md`) after the adversarial review rated them fix-then-ship. The
three new protocols (JTAG/SPI/sub-GHz) and C3 (`dump` sugar) are out of scope for this sprint.

BLOCKERS:
- `backends/virtual.py::sniff` is now bounded entirely client-side (convention rule 4). The
  loop stops at `count`, at `seconds`, and at a hard wall-clock timeout, with a per-recv
  socket timeout derived from the remaining budget; when neither `count` nor `seconds` is
  given a default ceiling (`SNIFF_DEFAULT_SECONDS=30s`) applies instead of capturing forever.
  A never-ending or silent bridge can no longer hang the client. The client also sends a stop
  and clears the read timeout when it ends.
- C1 clean error handling + capability gate. New `core/errors.py::ProbeError(RuntimeError)`,
  operator-facing. `cli.main` now catches `NotImplementedError` (rendered "not supported by
  this backend") and `(ProbeError, wire.ProtocolError, RuntimeError, OSError, ValueError)`,
  printing `probe: <msg>` with a nonzero exit, never a traceback. `cli._require_verb(caps,
  verb)` gates every protocol verb against `capabilities().verbs` BEFORE routing; an
  unsupported verb is a clean `ProbeError`. The `socketcan.op` and `serial` sniff/inject/
  replay/op `NotImplementedError` sites became clean `ProbeError` refusals.

MAJORS:
- C4 replay DLT validation. New `core/frame.py::read_pcap_for_replay(path, expected_dlt)`
  refuses (ProbeError) a pcap whose link type differs from the active protocol's `PCAP_DLT`,
  and refuses loud when the protocol declares no DLT (conservative, never guesses). Wired into
  both `virtual.replay` and `socketcan.replay`.
- Protocol semantics honesty:
  - `can.decode_frame` now rejects an illegal DLC (>8) and a buffer that is not exactly one
    16-byte SocketCAN frame, instead of silently clamping/truncating.
  - `ble.unlock_write_frame` now emits the FULL LE_LL_WITH_PHDR layering its declared DLT 256
    requires (10-byte LE pseudo-header + LL data PDU with a connection access address + 3-byte
    CRC trailer + L2CAP on the ATT CID + ATT Write Request), so a capture actually dissects as
    `btatt.opcode == 0x12` in stock tools. Decision: keep DLT 256 and make the bytes match it
    (option A), because the conventions make DLT first-class and courses already reference
    LE_LL_WITH_PHDR / btatt. New `ble.att_write_pdu` validates the 16-bit handle / 8-bit value
    width (clean ProbeError on overflow, no silent wrap).
  - Reconciled the Zigbee DLT: `core/frame.py` docstring said 215, `zigbee.py` uses 195. 195
    (LINKTYPE_IEEE802_15_4_WITHFCS) is correct; fixed the docstring.

C2 + minors:
- C2 `Capabilities.shape` ("packet" | "stream" | "transaction", default "packet", backward
  compatible). Set packet for CAN/virtual, stream for serial/UART; `probe info` prints it.
- `inject --channel` added and threaded through to `backend.inject(..., channel=)`.
- `gatt write` help now states it also accepts a uuid (it already resolved one).
- `wire.decode` now reports a declared zero-length body as a clear "malformed frame", not the
  misleading "unexpected EOF reading body".

TESTS (19 -> 46 passing, 1 pre-existing skip): `test_sniff_bound` (count/seconds/silent/
default-ceiling bounds on a never-ending mock bridge), `test_cli_errors` (verb gate + clean
ProbeError/wire-error/NotImplementedError exits), `test_replay_inject` (inject + channel,
matching-DLT replay, cross-DLT refusal, no-DLT refusal), `test_cli_verbs` (UART read/write,
Zigbee sniff to a 195-DLT pcap), `test_ble_frame` (stdlib structural walk of the DLT-256
layering + width validation + optional scapy `btatt.opcode` dissection, skips without scapy),
`test_capabilities_shape` (shape default/values/info), plus CAN illegal-DLC + wrong-size and
the wire zero-length-body cases.

Public happy-path commands (scan/sniff/can send/uart read/gatt enum/...) unchanged; only
error handling, bounds, and wrong semantics changed.

Renamed the link-layer / frame-semantics abstraction from `medium` to `protocol` throughout
the client. The word `medium` was overloaded against the existing wire concept; `protocol`
now unambiguously means the link layer (ble/zigbee/can/uart), and the client<->bridge wire
is referred to as "the wire" in prose.

- `src/espilon_probe/mediums/` -> `protocols/` (git mv); module constants `MEDIUM` ->
  `PROTOCOL` in ble/can/uart/zigbee.
- `Capabilities.medium` -> `Capabilities.protocol`; `Frame.medium` -> `Frame.protocol`.
- Wire JSON key `"medium"` -> `"protocol"` in `Frame.to_msg`/`from_msg` and the WELCOME
  capabilities; the bridge side flips to match in the same vendored unit. Wire-shape change,
  noted in CHANGELOG. `PROTO_VERSION` not bumped (client/bridge re-vendored in lockstep).
- Backends: `virtual.py` reads `"protocol"` from caps; `socketcan.py`/`serial.py` advertise
  `protocol=`; imports moved to `espilon_probe.protocols`.
- CLI: `probe info` now prints `protocol: <x>`; help text and dispatch imports updated.
- Per Section A of the rename plan, `PROTO_VERSION` and `class ProtocolError` in
  `core/wire.py` are LEFT UNCHANGED (they name the wire, not the link layer); no new bare
  `protocol` identifier was introduced in `wire.py`.
- Tests and docs (ARCHITECTURE, wire-protocol, cli, README, CHANGELOG, CONTRIBUTING,
  ROADMAP) updated. Suite green.

## 001 - chore: scaffold espilon-probe project structure

Laid down the project skeleton and the design, no implementation.

- README (vision: one CLI for the physical layer, same commands lab + real hardware),
  ARCHITECTURE (3 layers CLI / mediums / Backend, the backend matrix, the wire protocol),
  ROADMAP (virtual -> BLE -> first real backend as the proof), docs/ (cli, wire-protocol,
  lab-authoring).
- Contracts as stubs: `core/backend.py` (the Backend interface), `core/frame.py` (pcap),
  `cli.py` (verb surface), `backends/virtual.py`, `mediums/ble.py`.
- Lab side: `bridge/` with the `Device` author SDK and an illustrative `ble_lock` example.
- `pyproject.toml` (`probe` entry point), `.gitignore`. All modules parse.

## 002 - feat(core): functional probe wire-protocol codec + round-trip tests

The keystone everything depends on. Concrete, framed, boring on purpose.

- `core/wire.py`: length-prefixed JSON messages (4-byte big-endian length + UTF-8 JSON).
  Raw medium PDUs travel hex-encoded in the JSON for debuggability; we can swap to a
  binary side-channel later without touching callers. Message types for the full session:
  HELLO/WELCOME, SCAN/SCAN_RESULT, OP/OP_RESULT, INJECT/ACK, REPLAY/REPLAYED,
  SNIFF/FRAME/SNIFF_END, ERROR. Helpers: `send(stream, msg)`, `recv(stream)`,
  frame encode/decode.
- `tests/test_wire.py`: round-trips every message type and a frame over a BytesIO stream;
  checks framing across partial reads and a clean EOF.
- Shared by both sides: the bridge imports `espilon_probe.core.wire` so client and server
  cannot drift.

## 003 - feat: end-to-end BLE vertical slice (probe -> bridge -> device -> flag)

The whole stack proven with no real radio, the first vertical.

- `bridge/server.py`: functional threading TCP server, serves a `Device` over the wire
  protocol (hello/welcome handshake from capabilities, then scan/op/inject/replay/sniff).
  One thread per session; a device error becomes an ERROR message, never kills the session.
  `start_background()`/`stop()` helpers for tests and embedding.
- `backends/virtual.py`: functional client. Parses `ESP_PROBE` (tcp://host:port, dynamic
  per spawn), handshakes, implements scan/op/inject/sniff over the wire. replay-from-pcap
  is deferred to todo 2 (needs the pcap writer).
- `mediums/ble.py`: gatt verbs (enum/read/write via Backend.op) + `unlock_write_frame()`
  (a real ATT Write Request PDU, opcode 0x12, what tshark dissects and a replay re-sends).
- `bridge/examples/ble_lock/device.py`: functional BLE smart-lock. fff1 (0x0011) state /
  fff2 (0x0014) control. Flag staged on fff1 OVER THE PROTOCOL with per-path provenance
  (direct write -> flag1, replayed frame -> flag2). Flags from env, safe under Model B (no
  player shell). Spoof/MITM flag3 path: still to design.
- `tests/test_e2e_ble.py`: spins the bridge in-thread, drives it through VirtualBackend,
  earns flag1 (gatt write) and flag2 (replay) over the protocol. Full suite 6/6 green.
- Run: `PYTHONPATH=src:bridge python -m pytest tests/ -q`.

## 004 - feat: sniff + replay over a standard pcap

The real capture workflow, mechanism-complete.

- `core/frame.py`: `PcapWriter` / `read_pcap` for classic pcap (24-byte global header +
  records), linktype per medium. The capture container is medium-agnostic; frames layered
  for the DLT dissect in stock tools.
- `backends/virtual.py`: `sniff` now writes the streamed frames to a real pcap (DLT from
  the bridge capabilities, USER0 fallback); `replay` reads a pcap and re-sends its frames.
  Filtering stays the operator's job in tshark before replay.
- Bridge capabilities advertise `pcap_dlt`. The ble_lock device `feed()` emits adverts +
  a legit unlock write, so the player can `sniff -w unlock.pcap` then `replay -r` it.
  Placeholder PDUs for now; the real ble lab will emit fully-layered BLE LL frames
  (pcap_dlt 256) so `tshark -Y btatt` dissects - that lands at lab-port time.
- `tests/test_e2e_ble.py`: added the sniff->pcap->replay path. Suite 7/7 green.

## 005 - feat(cli): functional probe CLI + editable packaging

`probe` works in a real shell end to end - this closes probe Phase 1.

- `cli.py`: real dispatch over the virtual backend - info / scan / sniff / inject / replay
  and the `gatt` group (enum / read / write). Real backends error cleanly ("Phase 3+").
  Values printed as text when printable, else hex.
- `pip install -e .` installs the `probe` entry point; verified `probe --help` and a live
  `probe info|scan|gatt enum|gatt write|gatt read` against an in-thread bridge: the unlock
  flag comes back over the protocol via `probe gatt read 0x0011`, exactly the documented
  player session.
- `tests/test_cli.py`: drives the CLI verbs against a bridge, asserts stdout. Suite 8/8.
- probe Phase 1 done: bridge + virtual backend + BLE medium + sniff/replay/pcap + CLI +
  packaging. Next: port the real ble-exploitation lab onto this (device.py + Model B compose).

## 006 - fix: harden probe after an adversarial code review (Pony Tail on the code)

Reviewed the Phase 1 code adversarially, broke it with repros, fixed everything. 16/16.

MAJOR:
- Connect timeout (10s) leaked into every read, so any sniff/op waiting >10s died with
  socket.timeout. `virtual.open()` now clears the timeout after connect.
- A malformed/oversized frame killed the server handler thread with a stderr traceback.
  `server.handle` now decodes inside try, answers a clean ERROR, and the session/server
  survive (verified: server still serves new connections afterwards).
- No anti-leak tests. Added `tests/test_adversarial.py`: the flag is unreachable before the
  action (scan/enum/read/wrong-inject never yield `ESPILON{`), and each provenance path
  yields only its own flag. (The test also caught that the brand name ESPILON-LOCK is not a
  leak; the invariant checks for `ESPILON{`.)

MINOR:
- `open()` leaked the socket on a failed handshake; now closes and leaves `_sock` None.
- `replay --filter` was silently ignored; dropped from the CLI (pre-filter with tshark -w).
- `sniff --seconds` was ignored; the bridge now honors a wall-clock deadline.
- `gatt read/write` by uuid crashed (int('fff1')); `_resolve_handle` resolves uuid->handle
  via enum.
- Concurrent connections shared the Device with no lock; the bridge now guards device ops
  with a per-server lock (feed streaming stays lock-free, must be side-effect free).
- The server no longer echoes internal exception text to the client (generic "internal lab
  error"); a handshake read timeout (30s) bounds idle connections.
- Example device flag default is now a loud `ESPILON{UNSET_FLAG_*}` marker, not a guessable
  real-looking flag.
- Added `bridge/pyproject.toml` so the bridge is an installable package depending on
  espilon-probe (closes the lab-image packaging gap).

NIT:
- `read_pcap` validates the pcap magic (us/ns, LE/BE) and rejects non-pcap input.
- `inject --read` closes the file; CLI dispatch errors print `probe: <msg>` not tracebacks.

- `tests/test_robustness.py`: timeout-not-leaked, malformed->ERROR, unknown-verb->ERROR,
  open-cleanup-on-failure, gatt-by-uuid, pcap-magic-rejection. Suite 16/16 green.

## 007 - feat(can): CAN medium + virtual device + real socketcan backend (dual-purpose)

The first second medium and the first real backend - the dual-purpose proof, on CAN.

- `mediums/can.py`: the classic 16-byte SocketCAN frame codec (encode/decode, std + 29-bit
  extended, auto-extended over 0x7FF), `ids_seen`, and `can send`/`can dump` sugar over the
  core inject/sniff verbs. DLT_CAN_SOCKETCAN (227) so tshark dissects captures as CAN. This
  codec is THE shared piece between virtual and real.
- `backends/socketcan.py`: real CAN over a Linux SocketCAN interface via raw PF_CAN (no
  third-party dep). scan/sniff/inject/replay against vcan0/can0/slcan0.
- `bridge/examples/can_bus/device.py`: a virtual CAN bus (two ECUs broadcast; the diagnostic
  unlock frame 0x7DF/0201 stages the flag as a multi-frame 0x7E8 response over the bus).
- CLI: `can send <id> <hex>` / `can dump -w pcap`, and `--backend socketcan --target vcan0`.
- Tests: `test_can_codec.py` (frame roundtrips), `test_e2e_can.py` (virtual: inject diag,
  sniff, reassemble flag off the bus), `test_socketcan_live.py` (real vcan0 loopback,
  auto-skips without the interface). Suite 21 passed, 1 skipped.
- Dual-purpose proven virtual-side and code-complete real-side; the live loopback turns
  green the moment a vcan0 exists: `sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0`.

## 008 - feat: all virtual mediums (zigbee + uart), 4 mediums total

- `mediums/zigbee.py` (DLT_IEEE802_15_4_WITHFCS 195) + `examples/zigbee_net`: beacon /
  transport-key / On/Off command; replaying the command actuates and the flag streams as
  data frames. Uses the core sniff/inject/replay verbs unchanged.
- `mediums/uart.py` (a byte-STREAM shape, not packets) + `examples/uart_console`: a U-Boot
  console; `uart read` / `uart write`; a privileged command (printenv/unlock/dump) leaks the
  flag over the line. Proves the non-packet medium shape via Backend.op.
- CLI: `uart read|write`. `test_e2e_zigbee.py` + `test_e2e_uart.py`. Suite 23 passed, 1 skip.
- Four mediums now: ble, can, zigbee, uart. Real backends so far: socketcan (CAN). Serial
  (UART, via pty) and the hardware ones remain.

## 009 - fix: code-review nits on the new surface (CAN/socketcan)

Adversarial pass over the new code (anti-leak held on all 4 mediums, server survived
hostile input, 200k-frame replay bounded). Two micro-fixes:
- `can.decode_frame` validates length and raises ValueError on a short frame; a hostile
  inject now returns a clean "bad request: CAN frame too short" instead of "internal lab
  error".
- `SocketCanBackend.inject/scan/sniff` raise RuntimeError if used before open() (was an
  AttributeError on None).
- `tests/test_socketcan_unit.py`: the open-guard and the short-frame validation. Suite 25
  passed, 1 skipped.

## 010 - chore: repo hygiene (GPL-3.0, packaging, CI)

- LICENSE: canonical GPL-3.0 text. pyproject: version 0.1.0, `license = {file}`, GPLv3+
  classifier, keywords, readme.
- `.gitlab-ci.yml`: pytest on python:3.11-slim. Install is two-step (`pip install -e .[dev]`
  then `-e ./bridge`) because the bridge depends on espilon-probe; verified green in a clean
  venv with no PYTHONPATH (25 passed, 1 skipped).
- README: Status + quickstart + License sections.
- Still pre-git by request; this entry plus 001-009 become the commit history on the go.

## 011 - feat(labs): 6 probe-backed labs catalogue (built + validated via workflows)

Built and validated a `labs/` catalogue with two orchestrated workflows.

- 6 varied labs, each `labs/<slug>/` with device.py + course.md + smoke.py + adversarial.py:
  ble-smart-lock (gatt write / replay / spoof-MITM, 3 flags), ble-beacon-clone (advert clone),
  zigbee-onoff (key recovery + On/Off replay), can-uds-unlock (UDS 0x27 security access,
  seed^0xA5A5), can-instrument-tamper (over-range speed spoof + ISO-TP flag), uart-bootloader
  (console printenv/unlock, ships clean first pass).
- Each: flags from env with loud UNSET markers, staged OVER THE PROTOCOL with distinct
  provenance (no path earns another's flag), Model B (no score.txt, no shell).
- Workflow 1 (build+review): all 6 built green (smoke+adversarial exit 0); Pony Tail caught
  a systemic non-iso-course defect (invented CLI flags --handle/--out/--frame/--id/--iface).
- Workflow 2 (course-iso-fix): rewrote every probe command in the 5 affected courses to the
  real CLI syntax, each verified live against a spawned bridge; all_iso=true.
- Verified after: 6/6 smoke+adversarial green, main suite 25 passed / 1 skipped, src/bridge
  core untouched by agents, no em-dash in any course.
- Known minors (non-blocking): ble-smart-lock replay step not strictly load-bearing; zigbee
  on_frame ignores channel on the key proof; uart scan output prints the raw advertiser dict.

## 012 - feat(serial): real UART backend over a pty (dual-purpose proven, no hardware)

- `backends/serial.py`: real serial backend via raw fd I/O (os.open/read/write + select), no
  third-party dep. Best-effort raw+baud via termios for a real tty, skipped on a pty.
  `uart read`/`uart write` over op(); the packet verbs raise (UART is a byte stream).
- CLI: `--backend serial --target /dev/ttyUSB0` (or a pty path).
- `tests/test_serial_pty.py`: a pty pair (a real serial line to the OS) with a tiny UART
  device on the master end; the SerialBackend drives the slave with the same verbs the
  virtual lab uses, ordinary command leaks nothing, printenv leaks the flag. LIVE, runs
  with no hardware. Suite 26 passed, 1 skipped.
- Real backends now: serial (UART) LIVE-proven on pty; socketcan (CAN) coded + codec-tested,
  live pending a vcan0. The dual-purpose claim is demonstrably real for UART today.

## 013 - test(socketcan): live loopback green on vcan0, dual-purpose proven for CAN

- With a `vcan0` up, `test_socketcan_live.py` passes (no longer skipped). Full suite 27
  passed, 0 skipped.
- Demonstrated at the real CLI: `probe --backend socketcan --target vcan0 can dump` +
  `... can send 0x123 deadbeef` on the live vcan0 bus captured the frame back
  (id=0x123 data=deadbeef), the same verbs as the virtual lab.
- Both real backends now LIVE-proven locally with no hardware: serial (UART/pty) and
  socketcan (CAN/vcan0). The lab-to-real continuity is real, not a claim.

## 014 - refactor!: M0 separation - probe is the generalist client only

The tool repo no longer bundles any challenge/content. probe = generalist client + the wire
protocol. The target side moved to a separate private repo.

- Moved OUT to `../espilon-probe-labs` (private): `bridge/` (server + Device SDK +
  examples), `labs/` (the 6 labs), and the device-dependent tests (test_e2e_*,
  test_adversarial). That repo got a conftest (adds bridge/ + the sibling probe/src to the
  path), a .gitignore, a README, and a test_bridge.py for server robustness. It depends on
  espilon-probe only for `core/wire.py`. Suite there: 10 passed.
- probe repo now: `tests/_mock_bridge.py` (a ~40-line scriptable wire server, NOT the bridge)
  lets the client/protocol/CLI tests run with no device in the repo. Rewrote test_cli and
  test_robustness against the mock; kept test_wire/can_codec/socketcan_unit+live/serial_pty.
  Removed `tests/__init__.py`, added `tests/conftest.py` for paths. Suite: 17 passed.
- CI install dropped the bridge step; README Layout/Status and ARCHITECTURE reworded to the
  client-only boundary; `docs/lab-authoring.md` moved to the content repo;
  `docs/wire-protocol.md` stays as the public contract.
- The only coupling between the two repos is the wire protocol. Clean public-tool /
  private-content split.

## 015 - fix(cli): generic gatt-write output (no lab-specific label)

`probe gatt write` printed `ok (unlocked=...)`, a label inherited from the smart-lock lab,
so a different device (e.g. one returning `{ok, opened}`) showed `unlocked=None`. Now prints
`ok` plus any extra result fields generically (`ok {'opened': True}`). The client stays
generalist: it does not assume any device's semantics. 17 tests green.

## 016 - feat(cli): --baud + config in the HELLO handshake

- `wire.hello(config=None)` carries a client config dict (backward compatible; defaults {}).
- CLI global `--baud` (default 115200); the virtual backend forwards it in HELLO config, the
  serial backend uses it for termios. This is what makes the content-side UART baud model
  work (a wrong baud reads garbage), and what sets a real line rate on hardware.
- `tests/_mock_bridge.py` can capture the HELLO; `test_baud_hello.py` asserts the baud lands
  in the config. 20 tests green.

## 017 - docs: client release-prep (honest README, CONTRIBUTING, CHANGELOG)

- README rewritten for GitHub and made HONEST: the quickstart shows only backends that
  actually work (socketcan on vcan0, serial, virtual), with a backend table marking
  hci/killerbee/sdr/openocd/ftdi as planned (the old intro implied they worked). Added the
  library-usage example and an install section (PyPI pending, source for now). Every README
  command verified live (socketcan scan/send on vcan0, the import snippet).
- CONTRIBUTING.md (setup, stdlib-only core, generalist-client rule, sound-not-heuristic for
  security code, adding a backend/medium, wire-protocol backward-compat, conventional commits).
- CHANGELOG.md (0.1.0 unreleased, user-facing feature list).
- Publishable-ready; the actual git history + GitHub/PyPI publish remain gated on an explicit go.
