# Contributing to probe

Thanks for considering a contribution. probe is a small, deliberately lean tool; the bar is
clarity and correctness over breadth.

## Setup

```
pip install -e ".[dev]"
python -m pytest tests/ -q
```

Tests run against an in-repo mock server (`tests/_mock_bridge.py`), so you do not need any
target or hardware for the client/protocol/CLI tests. The `socketcan` live test needs a CAN
interface (`sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0`); it skips if
absent. The `serial` test uses a pty pair and needs no hardware.

## Ground rules

- Stdlib only in the client core (`src/espilon_probe/`). A new third-party dependency needs a
  clear justification and, ideally, lives behind an optional extra, not the core.
- The client stays generalist: no challenge, flag, device, or course knowledge in the client.
  It speaks the wire protocol and drives backends, nothing more.
- Keep the suite green. If you change behavior, add or update tests. Do not weaken a test to
  make it pass.
- Security-sensitive code (parsers facing untrusted input, anything that handles a target's
  output) must be sound and conservative, never a best-effort heuristic.
- Match the surrounding style: naming, idiom, comment density.
- No emoji, no em dashes in code, commits, or docs.

## Adding a backend

Implement `core.Backend` (open/close/capabilities/scan/sniff/inject/replay/op). A real
backend is a thin adapter over the native library or interface; reuse the protocol codecs in
`protocols/` so the same bytes work on the virtual and the real path. Add a live test that
skips cleanly when the hardware/interface is absent.

## Adding a protocol

A protocol module turns operator intent into frames/ops for any backend and declares the pcap
DLT. Keep it backend-agnostic.

## The wire protocol

`core/wire.py` is the contract between the client and any target server. Changes must stay
backward compatible (new fields optional, defaulted) or be versioned. See
`docs/wire-protocol.md`.

## Commits

Conventional Commits (`feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`). One logical
change per commit.
