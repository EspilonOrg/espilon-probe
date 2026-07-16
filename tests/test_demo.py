"""`probe demo` - the zero-setup onboarding tour.

Locks the promise that `pip install espilon-probe && probe demo` produces output with no
ESP_PROBE, no target, and no hardware: it must spin the bundled toy target, drive it through the
shipped client, exit 0, and print the story (info -> scan -> the locked/open door) plus the
equivalent real-hardware commands. Stdlib only; no network fixture, no env.
"""

from espilon_probe import cli, demo


def test_demo_run_exits_zero_and_tells_the_story(capsys):
    rc = demo.run()
    out = capsys.readouterr().out
    assert rc == 0
    # The header names it a demo against a bundled toy target.
    assert "demo-door-lock" in out
    # It exercises the real verb surface.
    assert "$ probe info" in out
    assert "protocol: ble" in out
    assert "$ probe scan" in out
    assert "$ probe gatt enum" in out
    # The one-sentence story: read locked -> turn key -> read open.
    assert "locked" in out
    assert "open" in out
    assert out.index("locked") < out.index("open")
    # It ends by pointing the same commands at real hardware.
    assert "--backend hci" in out
    # Flag-free: no flag marker or brace-wrapped secret leaks into the demo output.
    assert "flag" not in out.lower()
    assert "{" not in out and "}" not in out


def test_demo_verb_dispatches_through_main(capsys):
    rc = cli.main(["demo"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "demo-door-lock" in out
