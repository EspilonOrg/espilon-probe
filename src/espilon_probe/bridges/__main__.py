"""`python -m espilon_probe.bridges` == the probe-bridge console script.

The loopback launcher (`espilon_probe.backends.serial`) spawns the bridge this way so it works
straight from a source checkout without an installed console script.
"""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
