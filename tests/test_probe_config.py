"""`probe use` + the config precedence layer (config.py and cli._resolve_config_defaults).

The load-bearing contracts pinned here:
  - the file is `$XDG_CONFIG_HOME/probe/config.json` (fallback ~/.config), 0600/0700, atomic;
  - load() NEVER crashes: a corrupt/non-object file degrades to {} + one warning, a wrong-typed
    key is dropped per-key with a warning;
  - the precedence chain flag > env > config > built-in default, per key, INCLUDING the regression
    contract "no config file present => today's behaviour byte-for-byte";
  - a bad `scan_secs` in the CONFIG file degrades to the medium default + warning, while a bad
    --seconds/env still hard-errors;
  - `probe use` --show/--clear/write-merge and the mutual-exclusion guard.

The autouse `_isolate_probe_config` fixture (conftest) points XDG at an isolated empty dir, so
every test starts with no config unless it writes one.
"""

import argparse
import json
import os

import pytest

from espilon_probe import cli, config
from espilon_probe.core import wire


# --- config.py: path resolution ----------------------------------------------------------------
def test_config_path_uses_xdg(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "x"))
    assert config.config_path() == str(tmp_path / "x" / "probe" / "config.json")


def test_config_path_falls_back_to_dot_config(monkeypatch):
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setenv("HOME", "/home/somebody")
    assert config.config_path() == "/home/somebody/.config/probe/config.json"


def test_empty_xdg_falls_back_to_dot_config(monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", "")
    monkeypatch.setenv("HOME", "/home/somebody")
    assert config.config_path() == "/home/somebody/.config/probe/config.json"


# --- config.py: round-trip, merge, perms, atomicity --------------------------------------------
def test_save_then_load_round_trips():
    config.save({"backend": "hci", "target": "PROTO-7", "baud": 9600, "scan_secs": 2.5})
    assert config.load() == {"backend": "hci", "target": "PROTO-7", "baud": 9600, "scan_secs": 2.5}


def test_save_merges_and_preserves_other_keys():
    config.save({"backend": "hci", "target": "PROTO-7"})
    config.save({"target": "PROTO-FOB"})              # only target changes
    assert config.load() == {"backend": "hci", "target": "PROTO-FOB"}


def test_file_and_dir_permissions_are_locked_down():
    config.save({"backend": "hci"})
    path = config.config_path()
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"
    assert oct(os.stat(os.path.dirname(path)).st_mode & 0o777) == "0o700"


def test_atomic_write_leaves_no_temp_file():
    config.save({"backend": "hci"})
    leftovers = [n for n in os.listdir(os.path.dirname(config.config_path()))
                 if n != "config.json"]
    assert leftovers == []


def test_clear_is_idempotent():
    config.save({"backend": "hci"})
    assert config.clear() is True
    assert config.clear() is False
    assert config.load() == {}


def test_missing_file_loads_as_empty_without_warning(capsys):
    assert config.load() == {}
    assert capsys.readouterr().err == ""


# --- config.py: degrade-not-crash (D4) ---------------------------------------------------------
def _write_raw(text):
    path = config.config_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def test_corrupt_json_degrades_to_empty_with_one_warning(capsys):
    _write_raw("{ this is not json")
    assert config.load() == {}
    err = capsys.readouterr().err
    assert "ignoring unreadable config" in err
    assert err.count("\n") == 1                       # exactly one warning line


def test_non_object_json_degrades_to_empty(capsys):
    _write_raw("[1, 2, 3]")
    assert config.load() == {}
    assert "not a JSON object" in capsys.readouterr().err


def test_wrong_typed_key_is_dropped_per_key(capsys):
    _write_raw(json.dumps({"backend": "hci", "baud": "fast"}))
    assert config.load() == {"backend": "hci"}        # the good key survives
    assert "ignoring config key 'baud'" in capsys.readouterr().err


def test_bool_is_not_accepted_as_baud(capsys):
    _write_raw(json.dumps({"baud": True}))
    assert config.load() == {}                         # bool is not a valid int here
    assert "ignoring config key 'baud'" in capsys.readouterr().err


# --- precedence: cli._resolve_config_defaults (D3) ---------------------------------------------
def _resolved(backend=None, target=None, baud=None, cfg=None):
    args = argparse.Namespace(backend=backend, target=target, baud=baud)
    cli._resolve_config_defaults(args, cfg or {})
    return args


def test_flag_beats_env_and_config(monkeypatch):
    monkeypatch.setenv("ESP_PROBE_BACKEND", "serial")
    a = _resolved(backend="hci", cfg={"backend": "socketcan"})
    assert a.backend == "hci"


def test_env_beats_config(monkeypatch):
    monkeypatch.setenv("ESP_PROBE_BACKEND", "serial")
    a = _resolved(cfg={"backend": "socketcan"})
    assert a.backend == "serial"


def test_config_beats_default(monkeypatch):
    monkeypatch.delenv("ESP_PROBE_BACKEND", raising=False)
    monkeypatch.delenv("ESP_PROBE_TARGET", raising=False)
    a = _resolved(cfg={"backend": "hci", "target": "PROTO-7", "baud": 9600})
    assert (a.backend, a.target, a.baud) == ("hci", "PROTO-7", 9600)


def test_regression_no_config_reproduces_today(monkeypatch):
    # With NO config file, resolution must equal the historical env-or-default behaviour.
    monkeypatch.delenv("ESP_PROBE_BACKEND", raising=False)
    monkeypatch.delenv("ESP_PROBE_TARGET", raising=False)
    a = _resolved()                                    # nothing anywhere
    assert (a.backend, a.target, a.baud) == ("virtual", None, 115200)

    monkeypatch.setenv("ESP_PROBE_BACKEND", "hci")
    monkeypatch.setenv("ESP_PROBE_TARGET", "PROTO-7")
    a = _resolved()
    assert (a.backend, a.target, a.baud) == ("hci", "PROTO-7", 115200)   # env still honoured


def test_baud_has_no_env(monkeypatch):
    monkeypatch.setenv("ESP_PROBE_BAUD", "42")          # a var that does NOT exist by design
    a = _resolved(cfg={"baud": 9600})
    assert a.baud == 9600                                # config, not the phantom env


def test_resolve_tracks_the_source_of_backend_and_target(monkeypatch):
    # The source label is what the opener notice keys off; it must not perturb the resolved value.
    monkeypatch.setenv("ESP_PROBE_BACKEND", "serial")
    monkeypatch.delenv("ESP_PROBE_TARGET", raising=False)
    a = _resolved(target="X", cfg={"target": "cfg-target"})
    assert (a.backend, a._backend_source) == ("serial", "env")
    assert (a.target, a._target_source) == ("X", "flag")
    monkeypatch.delenv("ESP_PROBE_BACKEND", raising=False)
    b = _resolved(cfg={"backend": "hci", "target": "PROTO-7"})
    assert (b._backend_source, b._target_source) == ("config", "config")
    c = _resolved()
    assert (c._backend_source, c._target_source) == ("default", "default")


# --- config-source notice / $ESP_PROBE shadow warning (BLOCKER: silent config redirect) --------
def _notice_err(capsys, backend=None, target=None, cfg=None):
    """Resolve then run the opener notice, returning ONLY what it wrote to stderr."""
    args = argparse.Namespace(backend=backend, target=target, baud=None)
    cli._resolve_config_defaults(args, cfg or {})
    capsys.readouterr()                                  # drop any resolution noise
    cli._config_source_notice(args)
    return capsys.readouterr().err


def test_config_sourced_backend_and_target_emit_the_notice(monkeypatch, capsys):
    monkeypatch.delenv("ESP_PROBE_BACKEND", raising=False)
    monkeypatch.delenv("ESP_PROBE_TARGET", raising=False)
    monkeypatch.delenv("ESP_PROBE", raising=False)
    err = _notice_err(capsys, cfg={"backend": "hci", "target": "PROTO-7"})
    assert "using backend 'hci' target 'PROTO-7'" in err
    assert config.config_path() in err                   # names the source path
    assert "probe use --clear" in err                    # tells the operator how to override


def test_config_sourced_backend_only_names_only_backend(monkeypatch, capsys):
    monkeypatch.delenv("ESP_PROBE_BACKEND", raising=False)
    monkeypatch.delenv("ESP_PROBE_TARGET", raising=False)
    monkeypatch.delenv("ESP_PROBE", raising=False)
    err = _notice_err(capsys, target="/dev/ttyUSB0", cfg={"backend": "serial"})
    assert "using backend 'serial' from" in err
    # the flag-sourced target is not NAMED as config-sourced (the override hint still says --target)
    assert "target '" not in err


def test_no_config_path_is_silent(monkeypatch, capsys):
    # THE regression contract: with no config file (and no shadowed $ESP_PROBE) the opener is mute.
    monkeypatch.delenv("ESP_PROBE_BACKEND", raising=False)
    monkeypatch.delenv("ESP_PROBE_TARGET", raising=False)
    monkeypatch.delenv("ESP_PROBE", raising=False)
    assert _notice_err(capsys, cfg={}) == ""
    # env-sourced values are explicit per-shell intent, still no config file -> still silent
    monkeypatch.setenv("ESP_PROBE_BACKEND", "hci")
    monkeypatch.setenv("ESP_PROBE_TARGET", "PROTO-7")
    assert _notice_err(capsys, cfg={}) == ""


def test_esp_probe_ignored_warning_when_config_backend_shadows(monkeypatch, capsys):
    monkeypatch.delenv("ESP_PROBE_BACKEND", raising=False)
    monkeypatch.delenv("ESP_PROBE_TARGET", raising=False)
    monkeypatch.setenv("ESP_PROBE", "tcp://127.0.0.1:9")
    err = _notice_err(capsys, cfg={"backend": "hci", "target": "PROTO-7"})
    assert "$ESP_PROBE is set" in err and "not being used" in err
    assert "config sets backend 'hci' (not virtual)" in err


def test_esp_probe_ignored_warning_when_config_target_shadows(monkeypatch, capsys):
    # backend stays virtual, but a config `target` displaces the $ESP_PROBE endpoint fallback
    monkeypatch.delenv("ESP_PROBE_BACKEND", raising=False)
    monkeypatch.delenv("ESP_PROBE_TARGET", raising=False)
    monkeypatch.setenv("ESP_PROBE", "tcp://127.0.0.1:9")
    err = _notice_err(capsys, cfg={"target": "tcp://10.0.0.1:5555"})
    assert "$ESP_PROBE is set" in err
    assert "config sets target 'tcp://10.0.0.1:5555'" in err


def test_esp_probe_in_use_is_not_warned(monkeypatch, capsys):
    # virtual backend + no resolved target => $ESP_PROBE IS what gets used; no warning.
    monkeypatch.delenv("ESP_PROBE_BACKEND", raising=False)
    monkeypatch.delenv("ESP_PROBE_TARGET", raising=False)
    monkeypatch.setenv("ESP_PROBE", "tcp://127.0.0.1:9")
    assert _notice_err(capsys, cfg={}) == ""


def test_esp_probe_shadowed_by_an_explicit_flag_is_not_warned(monkeypatch, capsys):
    # A --backend/--target the operator typed this run is explicit intent, not a silent redirect.
    monkeypatch.delenv("ESP_PROBE_BACKEND", raising=False)
    monkeypatch.delenv("ESP_PROBE_TARGET", raising=False)
    monkeypatch.setenv("ESP_PROBE", "tcp://127.0.0.1:9")
    assert _notice_err(capsys, backend="hci", target="PROTO-7", cfg={}) == ""


def test_main_emits_config_notice_on_an_opening_verb(monkeypatch, capsys):
    # End-to-end: a config-sourced target surfaces on stderr when a verb actually opens a backend.
    from _mock_bridge import serve_mock
    caps = {"protocol": "ble", "channels": [], "verbs": ["scan"],
            "shape": "transaction", "meta": {}}
    srv, port = serve_mock(caps, lambda m: wire.error("unhandled"))
    try:
        monkeypatch.delenv("ESP_PROBE_BACKEND", raising=False)
        monkeypatch.delenv("ESP_PROBE_TARGET", raising=False)
        monkeypatch.delenv("ESP_PROBE", raising=False)
        config.save({"backend": "virtual", "target": f"tcp://127.0.0.1:{port}"})
        assert cli.main(["info"]) == 0
    finally:
        srv.shutdown()
        srv.server_close()
    err = capsys.readouterr().err
    assert "using backend 'virtual' target" in err and str(port) in err


def test_use_and_wizard_paths_do_not_emit_the_opening_notice(monkeypatch, capsys):
    # `probe use` opens nothing, so even a fully-populated config must not trigger the notice.
    config.save({"backend": "hci", "target": "PROTO-7"})
    capsys.readouterr()
    _run(["use", "--show"])
    assert "using backend 'hci' target" not in capsys.readouterr().err


# --- scan_seconds config layer (D3) ------------------------------------------------------------
def _scan_args(seconds=None):
    return argparse.Namespace(seconds=seconds, count=None)


def test_scan_secs_config_below_env(monkeypatch):
    monkeypatch.setenv("ESP_PROBE_SCAN_SECS", "9")
    assert cli._scan_seconds(_scan_args(), {"scan_secs": 3.0}) == 9.0     # env wins


def test_scan_secs_config_used_when_no_flag_or_env(monkeypatch):
    monkeypatch.delenv("ESP_PROBE_SCAN_SECS", raising=False)
    assert cli._scan_seconds(_scan_args(), {"scan_secs": 3.0}) == 3.0


def test_scan_secs_flag_beats_config(monkeypatch):
    monkeypatch.delenv("ESP_PROBE_SCAN_SECS", raising=False)
    assert cli._scan_seconds(_scan_args(seconds=2.0), {"scan_secs": 3.0}) == 2.0


def test_bad_config_scan_secs_degrades_with_warning(monkeypatch, capsys):
    monkeypatch.delenv("ESP_PROBE_SCAN_SECS", raising=False)
    assert cli._scan_seconds(_scan_args(), {"scan_secs": -1.0}) is None
    assert "ignoring invalid config scan_secs" in capsys.readouterr().err


def test_bad_env_scan_secs_still_hard_errors(monkeypatch):
    monkeypatch.setenv("ESP_PROBE_SCAN_SECS", "soon")
    with pytest.raises(cli.ProbeError):
        cli._scan_seconds(_scan_args(), {"scan_secs": 3.0})


# --- probe use command surface (D2) ------------------------------------------------------------
def _run(argv):
    return cli.main(argv)


def test_use_writes_and_show_reports(capsys):
    assert _run(["use", "hci", "--target", "PROTO-7"]) == 0
    capsys.readouterr()
    assert _run(["use", "--show"]) == 0
    out = capsys.readouterr().out
    assert config.config_path() in out
    assert '"backend": "hci"' in out
    assert "backend   = hci" in out and "(config)" in out
    assert "target    = PROTO-7" in out


def test_use_show_lists_the_esp_probe_endpoint_in_the_note(capsys):
    # $ESP_PROBE must be a discoverable peer in the precedence note, not just the *_BACKEND/*_TARGET
    # vars - it is the documented virtual endpoint a config target can silently shadow.
    _run(["use", "hci"])
    capsys.readouterr()
    _run(["use", "--show"])
    out = capsys.readouterr().out
    assert "$ESP_PROBE" in out
    assert "$ESP_PROBE_BACKEND" in out and "$ESP_PROBE_TARGET" in out


def test_use_show_marks_env_source(monkeypatch, capsys):
    monkeypatch.setenv("ESP_PROBE_TARGET", "PROTO-FOB")
    _run(["use", "hci"])
    capsys.readouterr()
    _run(["use", "--show"])
    out = capsys.readouterr().out
    assert "target    = PROTO-FOB" in out and "(env)" in out


def test_use_clear_removes_file(capsys):
    _run(["use", "hci"])
    capsys.readouterr()
    assert _run(["use", "--clear"]) == 0
    assert "cleared" in capsys.readouterr().out
    assert config.load() == {}


def test_use_clear_when_absent_is_clean(capsys):
    assert _run(["use", "--clear"]) == 0
    assert "nothing to clear" in capsys.readouterr().out


def test_use_show_conflicts_with_write_key():
    with pytest.raises(SystemExit) as ei:
        _run(["use", "hci", "--show"])
    assert "cannot be combined" in str(ei.value)


def test_use_show_and_clear_are_mutually_exclusive(capsys):
    with pytest.raises(SystemExit):
        _run(["use", "--show", "--clear"])             # argparse mutex group rejects it


def test_use_rejects_non_positive_scan_secs():
    with pytest.raises(SystemExit) as ei:
        _run(["use", "--scan-secs", "0"])
    assert "must be > 0" in str(ei.value)


def test_use_opens_no_backend(monkeypatch):
    # `use` must never build/connect a backend: sabotage _make_backend and assert it is untouched.
    def boom(*a, **k):
        raise AssertionError("use must not open a backend")
    monkeypatch.setattr(cli, "_make_backend", boom)
    assert _run(["use", "hci", "--target", "PROTO-7"]) == 0
