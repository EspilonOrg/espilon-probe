"""espilon-probe conformance harness (docs/design/04-conformance.md).

Proves the fidelity contract: the SAME command tape run against a VIRTUAL bridge and a REAL bridge
is observationally equal. This package is generalist and client-side - tapes name `probe` verbs
(argv), never flags or device internals - and it ships with the tool so a reviewer can run it.

The UART pilot (docs/protocols/uart.md, sequence position 1) proves the RAW-STREAM plumbing with
zero hardware: a pty is the "real" side. It stands up
  - a minimal UART `Console` model (this package, `console.py`);
  - a VIRTUAL bridge that serves the Console over the TCP stream tunnel (`virtual_bridge.py`);
  - a REAL bridge = the SAME Console bound to a pty master (`pty_adapter.py`), reached through the
    generic serial bridge (`espilon_probe.bridges`) over the pty;
and diffs the two. Both bridges are reached by an IDENTICAL `probe --backend virtual --target
tcp://...` client, which literally cannot tell them apart - the purest demonstration of "the client
is a pipe; fidelity is structural" (docs/design/00 decision 2).

Honest scope (docs/design/04 section 7): a pty has no bit clock, so the wrong-baud garble is NOT
exercised here; that assertion needs the model garble (virtual) or real USB-UART (physics). The pty
pilot proves byte content + order + echo + EOF + the read timeout, and virtual==real over them.
"""
