# DEVLOG

## fix(test): stop the console-fidelity harness leaking a stray ESCAPE across sessions

The `test (3.10)` CI job went red on the console-fidelity test while `3.11`/`3.12` stayed green.
It is not a 3.10 language issue: the test is timing-flaky and 3.10 simply lost the race that run.

### What

`tests/test_console_fidelity.py::_console_against` spawned two daemon threads (`driver`,
`watchdog`) that write to the session's pty `master` fd, and the `finally` closed `master`
(and `slave`) with only a `t.join(timeout=1.0)` on the driver and NO join on the watchdog. Under
load a pending thread could still write `console.ESCAPE` (`0x1d`) to `master` AFTER the finally
closed it, so the write landed on a REUSED fd - the next session's pty master or the bridge's
client socket - and injected a stray escape into an unrelated device-visible stream. That is
exactly the CI signature: both streams carried the full tape plus one extra `\x1d`, at opposite
ends (an injection that fired early lands at the start, late lands at the end).

The fix gates both threads on a `threading.Event` (`finished`): every sleep is `finished.wait(...)`,
so setting the Event wakes both at once, the watchdog fires its failsafe escape only on a genuine
hang, and the `finally` sets `finished` and JOINS both threads before closing any fd. No writer
thread can outlive the close, so no write can ever reach a reused fd.

### Why

The harness' own thread lifecycle was unsound: a fd closed while a writer thread might still use it.
This is the root cause of the red CI, and it can corrupt any co-running session, so the fix makes
the teardown deterministic rather than widening the sleeps. `requires-python` stays `>=3.10`:
3.10 is a correct, supported target and now passes.

### Tests

No assertion change (still asserts the two device-visible streams are byte-identical and the tape
reached the device). Full suite green on 3.10 and 3.11 (366 passed, 4 skipped); a 30x in-process
stress loop of the two-phase scenario under CPU load goes from ~10/40 corrupted streams on the old
harness to 0/30 on the fixed one.

## fix(release): clean the build dir and bound single-shot spi/jtag reads

Two small pre-public-release fixes surfaced by the adversarial review.

### What

1. **`make build` cleans first.** The `build` target now runs `rm -rf dist build` before
   `python -m build`, so a stale wheel left in `dist/` from a previous build can never be
   picked up and `twine upload`ed by accident. (The stale `dist/`, `build/`, `.demo-venv/`,
   `.demo-work/` trees were also removed from disk; they are gitignored, never tracked.)
2. **Non-positive single-shot reads are refused.** `spi read --len` and `jtag read --words`
   passed the operator's count straight to the backend op with no lower bound, so
   `spi read --len -5` / `jtag read --words -1` exited 0 silently. `spi.read` and `jtag.read`
   now raise a clean `ProbeError` on a non-positive count (`must be positive`), the same bound
   the `dump` sugar already enforces. The `dump` loops always pass a positive chunk, so they
   are unaffected.

### Why

Both are release footguns: the first can push a stale artifact to an index, the second lets a
malformed invocation look like a successful no-op instead of failing loud. Conservative,
fail-loud behavior for both.

### Tests

Added `test_spi_read_non_positive_length_refused` and `test_jtag_read_non_positive_words_refused`
(mirror the existing dump-ceiling tests: assert the backend `op` is never called and the error
carries `must be positive`). Full suite stays green.

## docs(demo): clean per-protocol demo GIF set for public release + README gallery

Brings the `demo/` per-protocol GIFs onto main for the public release, guaranteed free of any
real platform flag, and wires them into the README as a growable gallery.

### What

1. **`demo/` (new on main).** Five terminal-recording GIFs (`demo-info`, `demo-scan-sniff`,
   `demo-gatt`, `demo-bus`, `demo-solve`) with their `*.tape` VHS sources, the `render_agg.py`
   agg fallback renderer, `shell_setup.sh`, the stdlib-only `demo_bridge.py` target simulator,
   and `demo/README.md`. All five GIFs were re-rendered against the CURRENT main CLI, so the
   output is accurate (the previously-recorded `demo-info` was stale: it predated the
   `use`/`wizard`/`demo`/`esp` subcommands).
2. **Synthetic demo flag.** The `solve` scenario in `demo_bridge.py` returns a synthetic
   placeholder flag token, never a real platform flag, so the demo asset is safe to publish.
   Re-rendered and re-scanned: the final GIFs carry only the placeholder token (verified against
   the authoritative asciicast text each GIF renders from).
3. **README.** New `## Demos` section (in the Contents TOC) with a per-protocol table that is
   structured to grow one clip per protocol. The hero `assets/demo.gif` (the flag-free
   `probe demo` built-in) is unchanged.
4. **De-personalised** the tape scripts (dropped a hardcoded local home path; they now assume
   the repo root cwd documented in `demo/README.md`).

### Why

The public base had no per-protocol demos, and the pre-existing recordings on the demo branch
showed a real flag (a leak) and stale help text. This ships a clean, reproducible set.

### Scrutinise

The flag-leak guarantee is load-bearing: it rests on the asciicast being the sole text source
agg can render, and on `grep -n ESPILON` over every `.cast` returning empty after the sanitised
re-render. If a demo scenario is ever changed to surface secret bytes, re-run the cast scan
before publishing. `demo/demo_bridge.py` is a demo target simulator under `demo/`, not client
core, and imports nothing from `src/espilon_probe/`.

## feat(esp): ESP32 eFuse / secure-boot / flash-encryption protocol module + CLI

Adds the client half of the `esp` medium (per the locked `design-esp-medium` contract). The
client stays generalist and does NO crypto: real espsecure.py key-gen / sign / encrypt runs
off-device on the player's host (Model B); the client only shapes the burn/flash/verify
transactions and renders the results.

### What

1. **`protocols/esp.py` (new).** Named transactions over `Backend.op` as `OP{verb:"esp.<sub>"}`:
   `summary / burn_key / burn_efuse / read_protect / write_flash / read_flash / reboot`, mirroring
   the jtag/spi module shape. Client-side input validation fails loud BEFORE the wire: operator hex
   is normalised/checked, key-block names are gated to `key0..key5` (a hardware fact), eFuse values
   are int-coerced. No device/flag/verdict knowledge. The boot banner needs no code here - it rides
   the existing `uart` verbs (`probe uart read`) on the composite `op_console` medium.
2. **`cli.py`.** An `esp` subcommand group (summary / burn-key / burn-efuse / read-protect /
   write-flash / read-flash / reboot), `_PROTOCOL_VERB["esp"]="esp"`, `_VERB_REQUIRES["esp"]="esp"`,
   and dispatch. `summary` redacts a read-protected key block as `[read-protected]` (raw digest
   bytes never printed) and flags a write-protected field `(wp)`; `read-flash` renders opaque
   ciphertext as opaque bytes; `reboot` prints the returned banner + verdict.
3. **`core/frame.py`.** Allocated `DLT_USER_PROBE_ESP = 150` (USER3) for the optional esp
   transaction pcap.
4. **Docs.** `docs/protocols/esp.md` (player verb reference + the espefuse/esptool<->probe mapping
   table) and `docs/design/op-console.md` (the composite transaction+read-only-console shape; the
   client is shape-agnostic on the data path).

### Why

`esp` lets a player drive a simulated ESP32 secure-boot hardening campaign with the same generalist
`probe` CLI, and the same commands later drive a real serial (esptool ROM) backend - only the
backend swaps. The download-mode transactions and the read-only boot banner faithfully mirror the
two channels of a real ESP32 over one UART.

### Scrutinise

The client/device boundary: `esp read-flash` must never interpret opaque ciphertext, and `esp
summary` must never render a read-protected block's raw bytes (both enforced in `_dispatch_esp` /
`_print_esp_summary`). Key-block name validation is a deliberate generalist check (hardware fact),
not challenge knowledge.

## fix(client): bound uart reads, validate capture windows, coerce caps lists

Hardening pass closing three findings from an adversarial review of the probe client.

### What

1. **Byte ceiling on stream reads (MAJOR).** `StreamChannel.drain` had only a wall-clock cap,
   so a flooding or merely chatty line could grow one `uart read` to hundreds of MB / GB
   (repro: `stream_ready()` then `b"A"*4096` in a loop yielded ~2.6 GB, and `uart read -t 1`
   never returned). The drain is now bounded in SIZE as well as time via `UART_READ_MAX_BYTES`
   (8 MB default, `ESP_PROBE_MAX_READ_BYTES` override; a malformed/non-positive override falls
   back to the default, never disables the bound). The drain was refactored into one streaming
   core (`drain_into(timeout, sink, max_bytes)`); `drain` is now a thin buffering front over it.
   `uart read` writes to stdout INCREMENTALLY through an incremental UTF-8 decoder
   (`stream_read_into` / `uart.read_into`) instead of materializing-then-decoding the whole
   buffer, so a big read is never held in memory twice, and a multi-byte char split across recv
   chunks is not corrupted.

2. **Validate `-t`/`-c` on `sniff` and `can dump` (MINOR).** Both passed the raw flag straight
   to the backend; a non-positive / nan / inf value silently captured nothing and exited 0, and
   nan/inf leaked stdlib `settimeout` text. `_capture_bounds` now rejects them with a clean
   `probe: ...` error, matching how `scan` validates its window. The shared
   `_require_positive_seconds` also hardens `_scan_seconds` against nan/inf (previously only
   `<= 0` was caught).

3. **Coerce `verbs`/`channels` to lists (NIT).** A lying target could send `verbs` as a bare
   string, passing the substring-based capability gate (`"uart" in "scan,uart"`) and driving
   `info` char-by-char. `VirtualBackend.capabilities()` now coerces a non-list to `[]`
   (conservative: unadvertised means refused), and `_require_verb` re-checks defensively so no
   backend can route a verb past a substring accident.

### Why

Security-load-bearing paths (the anti-DoS read bound and the capability gate) must be sound and
conservative: a memory bound one typo away from unbounded, or a gate that a bare string can slip
through, is worse than none. Failure is loud (clean `probe: ...`), never a silent empty capture
or a raw traceback.

### Tests

Added flood/byte-ceiling and incremental-read tests (`test_uart_stream.py`), capture-window
validation and verbs/channels coercion tests (`test_cli_errors.py`), and a nan/inf scan-window
check (`test_cli_errors.py`). Full suite: 357 passed, 3 skipped.
