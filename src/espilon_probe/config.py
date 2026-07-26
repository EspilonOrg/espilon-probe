"""Persistent client defaults for `probe use` and the guided wizard - stdlib only.

A single flat JSON object at `$XDG_CONFIG_HOME/probe/config.json` (falling back to
`~/.config/probe/config.json` when `XDG_CONFIG_HOME` is unset/empty). It holds only client
line/endpoint defaults - `backend` / `target` / `baud` / `scan_secs` - never a secret: there is
no key here that could carry a credential or a flag. The directory is created `0o700` and the
file written `0o600`.

This module is PURE client config: it imports no backend, medium, or wire module, and adds no
third-party dependency (`json` / `os` / `sys` / `tempfile` only). It sits BELOW env and CLI
flags in the precedence chain (see cli._resolve_config_defaults):

    CLI flag  >  environment  >  config file  >  built-in default

Robustness rule (D4): a missing/corrupt/non-object config never crashes the tool - `load()`
returns `{}` after one stderr warning. A stored key of the wrong type is dropped per-key with a
warning, not treated as fatal. Writes are atomic (temp file + `os.replace`) so a crash mid-write
never leaves a half-written config the next run would warn on.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile

# The stored keys and the python type each must have. Unknown keys are IGNORED (never rejected),
# so the format stays forward/backward tolerant; a known key with the wrong type is dropped.
# NOTE: `bool` is a subclass of `int`, so a JSON `true`/`false` is explicitly excluded below - it
# is never a valid baud or scan window.
_SCHEMA: dict[str, tuple] = {
    "backend": (str,),
    "target": (str,),
    "baud": (int,),
    "scan_secs": (int, float),
}


def config_path() -> str:
    """The resolved config file path (XDG, falling back to ~/.config)."""
    base = os.environ.get("XDG_CONFIG_HOME") or ""
    if not base:
        base = os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "probe", "config.json")


def _warn(msg: str) -> None:
    print(f"probe: {msg}", file=sys.stderr)


def _typename(types: tuple) -> str:
    return "/".join(t.__name__ for t in types)


def load() -> dict:
    """Return the validated stored config, or `{}` - NEVER raises.

    A missing file is the silent common case (`{}`). An unreadable/corrupt/non-object file
    degrades to `{}` with ONE stderr line. A stored key whose value is the wrong type is dropped
    per-key with its own warning; the rest of the file is still honoured.
    """
    path = config_path()
    try:
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        _warn(f"ignoring unreadable config at {path} ({e}); using env/defaults")
        return {}
    if not isinstance(raw, dict):
        _warn(f"ignoring unreadable config at {path} (not a JSON object); using env/defaults")
        return {}
    out: dict = {}
    for key, types in _SCHEMA.items():
        if key not in raw:
            continue
        val = raw[key]
        if isinstance(val, bool) or not isinstance(val, types):
            _warn(f"ignoring config key {key!r} in {path} "
                  f"(expected {_typename(types)}, got {val!r})")
            continue
        out[key] = val
    return out


def save(updates: dict) -> None:
    """Merge `updates` into the stored config and write atomically (0600).

    Only the keys passed are changed; every other stored key is preserved (a newbie edits one
    thing at a time, and a write must not silently wipe the other defaults). A `None` value in
    `updates` is skipped (it means "the caller did not set this key"). If the existing file is
    corrupt, `load()` has already degraded it to `{}` with a warning, so the write starts clean.
    """
    cfg = load()
    for key, val in updates.items():
        if val is None:
            continue
        cfg[key] = val
    _atomic_write(config_path(), cfg)


def clear() -> bool:
    """Remove the config file. Returns True if a file was removed, False if there was none."""
    try:
        os.unlink(config_path())
        return True
    except FileNotFoundError:
        return False


def _atomic_write(path: str, cfg: dict) -> None:
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    # Tighten the leaf dir to 0700 even if it pre-existed with a looser mode.
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".config-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)   # atomic on POSIX; never a half-written target
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def effective(args, cfg: dict) -> list[tuple[str, object, str]]:
    """`(key, value, source)` rows for `probe use --show`, one per resolvable default.

    Mirrors the precedence chain per key (flag > env > config > default). `source` is one of
    `flag` / `env` / `config` / `default`. `scan_secs` has no baked default value (its "default"
    is the medium's own window), so it reports `(None, "default")` and the caller renders it as
    "(medium default)". `baud` has no env var by design.
    """
    return [
        _resolve_row("backend", getattr(args, "backend", None),
                     os.environ.get("ESP_PROBE_BACKEND"), cfg.get("backend"), "virtual"),
        _resolve_row("target", getattr(args, "target", None),
                     os.environ.get("ESP_PROBE_TARGET"), cfg.get("target"), None),
        _resolve_row("baud", getattr(args, "baud", None),
                     None, cfg.get("baud"), 115200),
        _resolve_row("scan_secs", getattr(args, "seconds", None),
                     os.environ.get("ESP_PROBE_SCAN_SECS"), cfg.get("scan_secs"), None),
    ]


def _resolve_row(key, flag, env, conf, default) -> tuple[str, object, str]:
    if flag is not None and flag != "":
        return (key, flag, "flag")
    if env is not None and env != "":
        return (key, env, "env")
    if conf is not None and conf != "":
        return (key, conf, "config")
    return (key, default, "default")
