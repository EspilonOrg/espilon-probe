# Rename `medium` -> `protocol` (execution plan)

Status: PLAN ONLY. No code, no rename, no git action taken by this document.
Decision on the name is FINAL: `medium` -> `protocol`. This plan does not re-litigate it.

`medium` currently names the link-layer / frame-semantics abstraction (ble, zigbee, can,
uart) living in `src/espilon_probe/mediums/`. We rename that concept to `protocol`. The hard
part is that espilon-probe already has a SECOND, unrelated "protocol": the client<->bridge
wire framing in `core/wire.py`. Section A pins down the disambiguation so the two never blur.

Repos in scope:
1. CLIENT  `~/git/espilon/espilon-probe`
2. KIT+LABS `~/git/espilon/espilon-probe-labs`
3. DEPLOYABLE LABS `~/git/espilon/Espilon-Challenges` (6 probe labs, each vendoring a
   stdlib-only copy of `espilon_probe` + `espilon_probe_bridge` under `target/`)
Plus the hosted client wheel at `~/git/espilon/Learn` (`assets/probe/...whl`,
served at `/learn/static/probe/`).

---

## A. COLLISION RESOLUTION (critical)

There are two distinct concepts that both want the word "protocol":

- CONCEPT 1 (being renamed): the link-layer / frame-semantics abstraction. Today `medium`.
  Values: `ble`, `zigbee`, `can`, `uart`. Lives in `mediums/`, carried on the wire as the
  `"medium"` JSON field, used to pick the pcap DLT and the verb group.
- CONCEPT 2 (already named "protocol" in code and prose): the client<->bridge wire framing
  in `core/wire.py` (length-prefixed JSON). It already owns these identifiers:
  - `PROTO_VERSION` (wire schema version, a serialized value in HELLO/WELCOME)
  - `class ProtocolError`
  - docstrings / `docs/wire-protocol.md` prose: "probe wire protocol", "the protocol"
  - bridge side (`espilon_probe_bridge`): `server.py`, `__init__.py`, `device.py`,
    `kit/harness.py` all say "the protocol" meaning the wire.

Identifier-vs-prose audit (did any real identifier clash, or only prose?):
- Grep of `\bproto(col)?\b|PROTO` in client `src/` returns ONLY: `PROTO_VERSION`,
  `ProtocolError`, and docstring/comment prose. No identifier named `protocol`/`proto`
  exists for the link-layer concept today (it is uniformly `medium`/`MEDIUM`). So there is
  NO identifier-level collision yet. The collision is purely conceptual/naming-space: if we
  blindly introduce `protocol`, future readers will conflate it with the wire protocol.

THE RULE (mandatory, applies to all 3 repos):

1. CONCEPT 1 becomes `protocol` (identifier and attribute) / `proto` (only where a short
   local is already idiomatic) / `PROTOCOL` (module constant, replacing `MEDIUM`). The wire
   JSON field `"medium"` becomes `"protocol"`. Directory `mediums/` becomes `protocols/`.

2. CONCEPT 2 (the wire) is NEVER called "protocol" bare again. It is always qualified as
   "wire", "wire frame", "wire format", or "wire framing" in prose, AND its existing
   identifiers are LEFT UNCHANGED to avoid serialized-value churn and needless diff:
   - KEEP `PROTO_VERSION` as-is. It is a serialized handshake value (HELLO/WELCOME
     `version`); renaming buys nothing and risks a wire break. Do not touch.
   - KEEP `class ProtocolError` as-is. It is the wire decoder error and is caught by name in
     callers; it predates this rename and is unambiguous in context (raised only by
     `wire.py`). Renaming is pure churn. Do not touch.
   - Prose only: where a docstring says "the protocol" meaning the wire, prefer "the wire
     protocol" / "the wire". This is editorial, not load-bearing; do it where you are
     already editing the file, do not chase every occurrence.

3. Net effect: after the rename, the token `protocol` as an identifier/attribute/JSON key
   ALWAYS means the link layer (ble/can/...). The wire keeps its two legacy `PROTO*`
   identifiers and is referred to in prose as "the wire". The two never share an identifier.

Concrete identifier mapping (CONCEPT 1):

| Old | New |
| --- | --- |
| dir `mediums/` (client + kit) | `protocols/` |
| module constant `MEDIUM = "<x>"` | `PROTOCOL = "<x>"` |
| `Capabilities.medium` (core/backend.py) | `Capabilities.protocol` |
| `Frame.medium` (core/wire.py + core/frame.py re-export) | `Frame.protocol` |
| wire JSON key `"medium"` (Frame.to_msg / from_msg / welcome caps) | `"protocol"` |
| `LabDevice.medium` (kit/labdevice.py) + `Device.medium` (bridge device.py) | `.protocol` |
| local vars / params named `medium` | `protocol` (or `proto` if already short-local) |
| kit CLI flag `--medium` and `MEDIUMS` tuple | `--protocol`, `PROTOCOLS` |
| `probe info` output `medium: <x>` | `protocol: <x>` |

DLT / pcap comments that say "per medium" / "medium-agnostic": editorial, reword to
"per protocol" / "protocol-agnostic" when touching the file.

---

## B. CALL-SITE INVENTORY

Counts are from case-insensitive grep of `medium` over `*.py *.md *.toml *.yaml *.yml` and
are approximate line-hit counts (a line can hold >1 token). They size the blast radius; the
implementer greps fresh.

### CLIENT (`~/git/espilon/espilon-probe`)

| Category | Where | ~hits | Visibility |
| --- | --- | --- | --- |
| Dir rename | `src/espilon_probe/mediums/` -> `protocols/` (5 files) | dir | internal |
| Module const | `MEDIUM` in ble/can/uart/zigbee.py | 4 | internal |
| Python identifier | `Capabilities.medium` (core/backend.py, 11 prose+1 attr) | 11 | internal API |
| Python identifier + WIRE KEY | `Frame.medium`, `to_msg`/`from_msg` `"medium"` (core/wire.py 6) | 6 | WIRE (serialized) |
| Re-export prose | core/frame.py | 2 | internal |
| Backend attr use | virtual.py `c.get("medium","")`; socketcan.py `medium="can"`x; serial.py `medium="uart"` | 8 | WIRE (serialized) on virtual |
| CLI output string | cli.py `medium: {c.medium}`, help text `medium`, imports `.mediums` | 9 | USER-VISIBLE (info output) |
| Tests | test_wire.py (2), test_cli.py (`"medium: ble"`), _mock_bridge.py caps, test_socketcan_*/can_codec/serial_pty import `mediums` | ~9 | internal |
| Docs | ARCHITECTURE.md 15, DEVLOG 16, docs/wire-protocol.md 9, docs/cli.md 5, README 4, CHANGELOG 3, CONTRIBUTING 4, ROADMAP 1 | ~57 | human text |

USER-VISIBLE / behavior-changing in client:
- `probe info` output line `medium: ...` -> `protocol: ...` (cli.py:100). Tests assert it.
- WIRE JSON key `"medium"` -> `"protocol"` in FRAME and WELCOME capabilities. Behavior change
  on the wire; both sides must flip together (see E + D).
- NO `--medium` flag exists in the client CLI; only the info output and import paths.

### KIT + LABS (`~/git/espilon/espilon-probe-labs`)

| Category | Where | ~hits | Visibility |
| --- | --- | --- | --- |
| Dir rename | `bridge/espilon_probe_bridge/kit/mediums/` -> `protocols/` (5 files) | dir | internal |
| Kit module const | `MEDIUM` in kit/mediums/{ble,can,uart,zigbee}.py | ~4 | internal |
| Bridge core attr + WIRE | `Device.medium` default + `{"medium": self.medium}` (device.py 11); `server.py` `medium=device.medium` (2) | 13 | WIRE (serialized) |
| LabDevice routing | kit/labdevice.py `_*_medium`, `getattr(f,"medium")`, dispatch (13) | 13 | internal |
| Kit CLI flag | kit/cli.py `--medium`, `MEDIUMS`, all templates emit `medium = "x"` and prose (33) | 33 | USER-VISIBLE (`probe-lab new --medium`) + generated code |
| Kit harness/init | harness.py 2, kit/__init__.py 2 | 4 | internal |
| Lab device.py | each of 6 labs sets `medium = "<x>"` (3-7 hits each) | ~29 | internal (but feeds wire) |
| Lab spec.py | 6 labs (1-3 each) | ~10 | internal |
| Lab smoke.py | 6 labs (2-3 each) | ~15 | internal |
| Lab adversarial.py | 6 labs (1-2 each) | ~8 | internal |
| Lab course.md | 6 labs (1-4 each) | ~15 | human text (player-facing) |
| Bridge examples | 4 example device.py | ~16 | internal samples |
| Tests | test_kit_labdevice 15, test_kit_mediums 3, test_kit_harness 5, e2e_* 7, others | ~35 | internal |
| Docs | docs/authoring-kit.md 21, docs/lab-authoring.md 2, bridge/README 2, DEVLOG 3 | ~28 | human text |

USER-VISIBLE / behavior-changing in kit/labs:
- `probe-lab new --medium {ble,can,zigbee,uart}` -> `--protocol {...}` (kit/cli.py:604).
  This is the lab AUTHOR-facing flag. Author-facing, not player-facing, but it is a real CLI
  break for the authoring side.
- Generated templates emit `medium = "x"` in scaffolded device.py; must emit `protocol = "x"`.
- course.md prose telling players `probe info should report medium: uart` -> `protocol: uart`.

### DEPLOYABLE LABS (`~/git/espilon/Espilon-Challenges`, 6 branches)

Each branch carries a FULL vendored stdlib copy of BOTH packages under
`lab/<cat>/<slug>/target/espilon_probe/` and `.../target/espilon_probe_bridge/`. So every
client-side and kit-side hit above is DUPLICATED once per lab inside `target/`, PLUS the lab's
own non-vendored files.

Per lab (counts from `can-instrument-tamper`, representative):
- vendored `target/espilon_probe/` : mirrors the CLIENT counts above (~40 hits incl. wire.py,
  cli.py, backends, mediums/).
- vendored `target/espilon_probe_bridge/` : mirrors the KIT counts above (~60 hits incl.
  kit/mediums/, device.py, server.py, cli.py).
- non-vendored lab files: `target/device.py` (3-7), `adversarial.py` (1-3), `README.md` (3-4),
  `lab.yaml` (CHECKED: 0 hits, see below), smoke if present.

Across 6 labs the vendored duplication dominates: roughly 6 x ~100 = ~600 vendored hits, but
they are NOT hand-edited. They are REGENERATED by re-vendoring after the client+kit rename
(Section D). Only the ~10-15 non-vendored hits per lab (device.py, README, adversarial) are
hand-touched, plus any course/README prose.

`lab.yaml` / `challenge.yml`: grep for `medium` over all challenge YAML returned ZERO hits.
The protocol is NOT a persisted field in lab config. This removes one compatibility hazard.

### LEARN (`~/git/espilon/Learn`)

- Hosted wheel asset `assets/probe/espilon_probe-0.1.0-py3-none-any.whl` (binary; rebuilt, not
  edited). Served at `/learn/static/probe/`.
- `wiki/software/probe.md`: grep `medium` returned ZERO hits. The canonical probe wiki page
  does NOT use the word; no edit needed there (confirm again before release in case it grows).

---

## C. BACK-COMPAT DECISION

Recommendation: HARD RENAME. No `medium` alias, no deprecation shim, no dual-read of the wire
key.

Why:
- probe is pre-release (`pyproject` 0.1.0, `__version__` still 0.0.0) and private. There is no
  external consumer pinned to the `"medium"` wire key or the `--medium` flag.
- The single coupling is `core/wire.py`, shared by both sides via vendoring. Because client and
  bridge are re-vendored together (Section D), there is never a moment where an old client meets
  a new bridge IN A LAB. A shim would exist only to protect against a drift we control by
  sequencing.
- A `medium`/`protocol` dual-read is exactly the kind of permanent ambiguity this rename is
  meant to kill, and it would muddy Section A's clean rule.
- One narrow exception is NOT a shim: keep `PROTO_VERSION` and `ProtocolError` unchanged (they
  belong to the wire concept, not the renamed one) per Section A. Bump `PROTO_VERSION` ONLY if
  you want a hard handshake-level reject of stale peers; not required since re-vendoring keeps
  both sides in lockstep. Recommendation: do NOT bump it (no mixed-version deployment exists),
  but note it in CHANGELOG as a wire-shape change.

Risk accepted: any not-yet-rebuilt vendored copy that talks to a rebuilt one breaks instantly
(KeyError / empty protocol). That is desired: it surfaces a missed re-vendor loudly instead of
silently degrading. Sequencing (D) makes the window zero.

---

## D. SEQUENCING ACROSS REPOS (the crux)

Hard ordering constraint: the `"medium"`->`"protocol"` wire key flips in BOTH the client wire
and the bridge that reads/writes it. They MUST flip in the same vendored unit. Therefore: do
the client and the kit/bridge rename, THEN re-vendor as one atomic copy into each lab, THEN
validate. Never partially re-vendor a lab.

Stage 1 - CLIENT rename (repo 1)
- Rename `mediums/` -> `protocols/`; `MEDIUM`->`PROTOCOL`; `Capabilities.protocol`;
  `Frame.protocol` + wire key `"protocol"`; backends; cli.py output `protocol:`; update
  imports and tests. Leave `PROTO_VERSION`/`ProtocolError` alone (A).
- Validate: client unit tests green (`tests/test_wire.py`, `test_cli.py` asserting
  `protocol: ble`, codec + serial/socketcan tests). This is the gate; nothing downstream runs
  until client tests pass.
- What breaks if skipped/out of order: every later stage vendors a half-renamed client.

Stage 2 - KIT + BRIDGE + LABS rename (repo 2)
- Rename `kit/mediums/`->`protocols/`; `Device.medium`/`LabDevice.medium`->`.protocol` and the
  `{"protocol": self.protocol}` cap; `server.py`; kit/cli.py `--protocol`/`PROTOCOLS` and all
  scaffolding templates; the 6 labs' device.py/spec.py/smoke.py/adversarial.py; example devices;
  course.md prose; kit tests.
- The kit imports the client's `protocols` modules (e.g. labdevice.py imports
  `espilon_probe.protocols.can`). It must see the Stage-1 client. Install/point the kit at the
  renamed client (editable or rebuilt wheel) before running kit tests.
- Validate: labs-repo test suite green (`tests/test_kit_*`, `test_e2e_*`, adversarial). e2e
  tests exercise the wire key end to end, so they prove client+bridge agree on `"protocol"`.
- What breaks if skipped/out of order: if the bridge still writes `"medium"` while the client
  reads `"protocol"`, FRAME/WELCOME parsing yields empty protocol -> `probe info` shows
  `protocol:` blank, pcap DLT selection and protocol-routing in labdevice.py misfire.

Stage 3 - REBUILD client wheel (repo 1)
- Build the new `espilon_probe-*.whl` from the Stage-1 tree (`python -m build`). This is the
  artifact both the labs and Learn consume. Consider a version bump (0.1.1 or note the wire
  change) so a stale-vs-new wheel is visible by filename.
- Validate: `pip install` the fresh wheel in a clean venv, run `probe info` against a
  Stage-2 bridge spawn, confirm `protocol: <x>`.

Stage 4 - RE-VENDOR the stdlib copies into the 6 deployable labs (repo 3)
- For EACH of the 6 branches, regenerate `target/espilon_probe/` and
  `target/espilon_probe_bridge/` from the Stage-1/Stage-2 trees using the SAME vendoring
  mechanism that produced them (the kit copy step / whatever script created `target/`). Do not
  hand-edit vendored files. Re-vendor BOTH packages together per lab (atomicity from D's
  constraint).
- Then hand-edit the lab's NON-vendored files on each branch: `target/device.py`
  (`protocol = "<x>"`), `adversarial.py`, `README.md` course prose (`protocol: uart` etc).
  `lab.yaml` needs no change (0 hits).
- Validate per lab: `labctl.py test <lab-dir>` (intended smoke path must pass) AND
  `labctl.py blind <lab-dir>` (adversarial, no reference answer). Run blind on a FRESH spawn
  (reveal-state labs false-positive if smoke ran first in the same container).
- What breaks if skipped/out of order: a lab whose `target/device.py` says `protocol = "ble"`
  but whose vendored bridge still reads `medium` (or vice versa) fails at spawn; that is the
  loud failure C accepts. Re-vendoring both packages together closes the window.

Stage 5 - REBUILD the hosted Learn wheel (Learn repo)
- Replace `assets/probe/espilon_probe-*.whl` with the Stage-3 wheel. Players pip-install this to
  drive the labs; it MUST match the `"protocol"` wire key the deployed bridges speak.
- Re-check `wiki/software/probe.md` for any newly-added `medium` prose (today: none).
- Validate: from the install URL, `pip install` then `probe info` against a deployed Stage-4
  lab, confirm `protocol:`.
- What breaks if skipped/out of order: a stale hosted wheel (old `"medium"` reader) against
  new bridges -> players get blank `protocol` and broken pcap/routing even though the lab is
  correct. The hosted wheel is the last domino precisely because it is what real players run.

Ordering invariant in one line: client tests green -> kit/labs tests green -> client wheel
rebuilt -> labs re-vendored+revalidated (test+blind) -> hosted wheel replaced. Each arrow is a
gate; do not advance on a red stage.

Re-prove matrix:
- Stage 1: client unit tests (`test_wire`, `test_cli`).
- Stage 2: kit unit + e2e (`test_kit_*`, `test_e2e_*`, adversarial).
- Stage 3: fresh-venv `pip install` + `probe info` smoke.
- Stage 4: `labctl test` + `labctl blind` per lab, blind on fresh spawn.
- Stage 5: install-from-URL + `probe info` against a deployed lab.

---

## E. RISK / EFFORT

Blast radius (rough): client ~115 hits (incl. docs), kit+labs ~250 hits (incl. docs/tests),
deployable labs ~600+ hits but ~90% are VENDORED and regenerated, not hand-edited. Realistic
hand-edited surface: ~150-200 lines across client+kit+labs source/tests, plus ~120 lines of
prose, plus ~10-15 hand-edited non-vendored lines per deployable lab (6 labs). This is a wide
but shallow mechanical rename; the effort is in the cross-repo SEQUENCING and re-validation,
not in any single edit. Do not expect a net line reduction; this is a rename, the payoff is
naming precision, not fewer lines.

Riskiest spots, in order:

1. WIRE KEY `"medium"` -> `"protocol"` (serialized). This is the only behavior-changing,
   cross-process edit. It lives in `core/wire.py` (Frame.to_msg/from_msg, welcome caps) on the
   client and is read/written by `device.py`/`server.py` on the bridge. Both must flip in the
   same vendored unit. A miss = blank protocol, wrong pcap DLT, broken protocol routing. This
   is what Stage 4's atomic per-lab re-vendor + `labctl test`/`blind` exists to catch.

2. VENDORED DUPLICATION DRIFT. Six independent `target/` copies of two packages across six
   branches. The failure mode is re-vendoring 5 of 6, or re-vendoring only `espilon_probe` and
   not `espilon_probe_bridge` in a lab. Mitigation: re-vendor via the original mechanism (never
   by hand), both packages together, and gate each lab on `labctl test` + `blind` before
   considering it done. Treat each branch as a separate unit of work.

3. THE WIRE COLLISION (Section A). The real risk is human: someone "tidies up" and renames
   `PROTO_VERSION`/`ProtocolError`, or introduces a bare `protocol` variable in `wire.py`
   meaning the wire. Guard: A's rule is explicit, leave the two `PROTO*` identifiers untouched,
   and in `wire.py` the token `protocol` should NOT appear as a new identifier (it is the link
   layer's word now; `wire.py` is about the wire). Reviewer checks: no new `protocol` identifier
   in `core/wire.py`; `PROTO_VERSION`/`ProtocolError` unchanged.

4. PERSISTED/SERIALIZED FIELDS OTHER THAN THE WIRE: checked. `lab.yaml`/`challenge.yml` have
   ZERO `medium` hits, and `PROTO_VERSION` is a separate value we are not renaming. No DB column,
   no on-disk lab config carries `medium`. The only serialized carrier is the wire JSON, handled
   in (1). The pcap files themselves carry no `medium` token (DLT is numeric); existing capture
   files are unaffected.

5. HOSTED WHEEL LAG (Learn). The hosted wheel is what players run; it is the LAST thing rebuilt
   (Stage 5). Risk is shipping deployed bridges before replacing the wheel. Mitigation: Stage 5
   is gated on a real install-from-URL `probe info` against a deployed Stage-4 lab.

Watch list for the implementer/reviewer:
- `grep -rn '"medium"'` must return ZERO across all three repos when done (wire key fully flipped).
- `grep -rni '\bMEDIUM\b'` ZERO (module constants renamed).
- `grep -rn -- '--medium'` ZERO (kit flag renamed).
- `probe info` prints `protocol:` not `medium:` (cli + every course.md/README that quotes it).
- `PROTO_VERSION` and `class ProtocolError` STILL PRESENT and unchanged.
- Each of the 6 lab branches: both `target/espilon_probe/` and `target/espilon_probe_bridge/`
  re-vendored, `labctl test` + `labctl blind` (fresh spawn) green.
- No outward action (no push, no deploy, no wheel publish) without an explicit per-item go.
