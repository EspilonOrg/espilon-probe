"""Conservative coercion of backend-supplied response fields.

A backend response is partly attacker-influenced on a lab bridge (the player drives some of
what the target returns). The protocol layer must never let a malformed field surface a raw
Python error (a `ValueError` from `int(...)`, an `AttributeError` from `.get()` on a non-dict):
it interprets the field authoritatively or refuses loud with a `ProbeError`. These helpers are
the single, sound place that judgement lives, so every protocol module coerces the same way.
"""

from __future__ import annotations

from .errors import ProbeError


def as_int(value, field: str) -> int:
    """Coerce a backend numeric field to int, or raise a clean `ProbeError`.

    Accepts a Python int, or a string in any base Python understands (`int(s, 0)`: 0x.., 0b..,
    decimal). Rejects bools (a bool is not a numeric the protocol intends), floats, None, and
    unparseable strings with a field-named message rather than letting `int()` leak its own
    "invalid literal" text. Conservative by design: when the value cannot be interpreted as the
    integer the field is supposed to be, we fail rather than guess.
    """
    if isinstance(value, bool):
        raise ProbeError(f"backend returned non-numeric {field} {value!r}")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            raise ProbeError(f"backend returned non-numeric {field} {value!r}")
    raise ProbeError(f"backend returned non-numeric {field} {value!r}")


def as_int_list(value, field: str) -> list[int]:
    """Coerce a backend list-of-ints field, or raise a clean `ProbeError`.

    The container must be a list/tuple (not a dict, not None, not a bare scalar) and every
    element must coerce via `as_int`. This is what `jtag.read` words / scan-chain idcodes go
    through before any formatting touches them."""
    if not isinstance(value, (list, tuple)):
        raise ProbeError(f"backend returned non-list {field} {value!r}")
    return [as_int(v, field) for v in value]
