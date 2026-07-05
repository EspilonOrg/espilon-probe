"""Backend-field coercion (core/fields.py) + the cli.main traceback backstop.

A target server's responses are partly attacker-influenced, so a malformed numeric/list field
must become a clean ProbeError in the protocol layer, and any malformed dict that still slips
through must be rendered as a clean `probe: ...` line by the CLI backstop, never a traceback.
"""

import os

import pytest

from espilon_probe import cli
from espilon_probe.core import wire
from espilon_probe.core.errors import ProbeError
from espilon_probe.core.fields import as_int, as_int_list

from _mock_bridge import GATT_CAPS, serve_mock


def test_as_int_accepts_int_and_based_string():
    assert as_int(5, "x") == 5
    assert as_int("0x1234", "x") == 0x1234
    assert as_int("0b101", "x") == 5
    assert as_int("42", "x") == 42


@pytest.mark.parametrize("bad", ["GARBAGE", "0xZZ", None, 1.5, True, [1], {"a": 1}])
def test_as_int_refuses_clean(bad):
    with pytest.raises(ProbeError) as ei:
        as_int(bad, "idcode")
    assert "non-numeric idcode" in str(ei.value)


def test_as_int_list_refuses_non_list_and_bad_elements():
    assert as_int_list([1, "0x2", 3], "word") == [1, 2, 3]
    with pytest.raises(ProbeError):
        as_int_list({"a": 1}, "word")          # dict is not a list
    with pytest.raises(ProbeError):
        as_int_list([1, "nope"], "word")       # a bad element


def test_cli_backstop_renders_attributeerror_clean(monkeypatch, capsys):
    # Force a path that raises a raw AttributeError after open(): the backstop in cli.main must
    # turn it into a clean `probe: ...` SystemExit instead of letting the traceback escape.
    srv, port = serve_mock(GATT_CAPS, lambda m: wire.error("x"))
    try:
        def boom(args, b):
            raise AttributeError("'NoneType' object has no attribute 'get'")

        monkeypatch.setattr(cli, "_dispatch", boom)
        os.environ["ESP_PROBE"] = f"tcp://127.0.0.1:{port}"
        with pytest.raises(SystemExit) as ei:
            cli.main(["info"])
        assert str(ei.value).startswith("probe:")
    finally:
        srv.shutdown()
        srv.server_close()
