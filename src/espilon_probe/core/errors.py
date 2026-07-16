"""Shared operator-facing error type.

`ProbeError` is the one clean failure the CLI catches and renders as `probe: {msg}` with a
nonzero exit, never a traceback. It is raised for expected, operator-visible faults:
an unsupported verb on this protocol, a malformed argument only the protocol layer can
judge, a target/transaction-level refusal, a replay onto the wrong link type.

It is deliberately a `RuntimeError` subclass so existing `except RuntimeError` sites keep
catching it, while new code can catch `ProbeError` specifically. It is distinct from
`wire.ProtocolError` (a wire-framing fault one layer down); a wire fault may be wrapped into
a `ProbeError` for presentation, but the two types are not the same.
"""

from __future__ import annotations


class ProbeError(RuntimeError):
    """Operator-facing, expected failure. The CLI prints `probe: {msg}` and exits non-zero."""
