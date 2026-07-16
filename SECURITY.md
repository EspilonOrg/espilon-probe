# Security policy

## Supported versions

`probe` is pre-1.0; security fixes land on the latest released version and `main`.

## Reporting a vulnerability

Please report suspected vulnerabilities privately. Do not open a public issue for a security
problem.

- Use GitHub's private vulnerability reporting on this repository
  (**Security -> Report a vulnerability**), or
- Open a minimal private channel with the maintainers as described on the repository's
  Security tab.

Please include:

- a description of the issue and its impact,
- the exact steps or a minimal proof of concept to reproduce it,
- the affected version(s) and environment.

We aim to acknowledge a report within a few business days and to coordinate a fix and
disclosure timeline with you. Please give us reasonable time to release a fix before any
public disclosure.

## Scope

`probe` is a client that parses backend and capture input, some of which may be
attacker-influenced (a remote target server, a crafted pcap). Parsing or capability-gating
issues that let malformed input crash with a traceback, bypass a verb gate, or otherwise
cause unsafe behavior are in scope. Use of the tool against systems you do not own or are not
authorized to test is out of scope and not condoned.
