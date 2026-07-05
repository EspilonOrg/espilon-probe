# Development log

Short, chronological engineering notes for `probe`. User-facing changes are summarized in
`CHANGELOG.md`; this log captures the reasoning behind non-obvious changes. Newest first.

## chore(release): public-prep

What: prepared the repository for its first public, pip-installable release. Rewrote the
README as the project's front door (hero line, badges, install, quickstart, protocol table,
backend model, architecture pointer). Added `[project.urls]` and classifiers to
`pyproject.toml`, a CI matrix across Python 3.10/3.11/3.12, issue/PR templates, a
`SECURITY.md`, and a public `CHANGELOG` entry. Documentation was reworded to describe the
generic wire-protocol contract and the virtual/real backend model only.

Why: the tool is a standalone, generalist physical-layer client. Its public surface must be
accurate against the real CLI and carry no target-specific content. The core stays stdlib
only; real-hardware dependencies remain optional extras.
