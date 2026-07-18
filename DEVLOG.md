# DEVLOG

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
