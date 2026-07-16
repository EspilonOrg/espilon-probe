import glob
import json
import os
import pathlib
import signal
import sys

import pytest

_here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(_here))                     # for _mock_bridge
sys.path.insert(0, str(_here.parent / "src"))      # for espilon_probe (editable install also works)
sys.path.insert(0, str(_here.parent))              # for the conformance harness package


@pytest.fixture(autouse=True)
def _isolate_probe_config(tmp_path, monkeypatch):
    """Point `probe`'s persistent config at an isolated, empty XDG dir for EVERY test.

    The `probe use` / wizard config lives at `$XDG_CONFIG_HOME/probe/config.json`. Without this,
    a developer's real `~/.config/probe/config.json` would leak into the suite and quietly break
    the "no config file present => historical behaviour" regression contract. A test that wants a
    config writes into this tmp XDG dir (via `config.save` or a direct file write)."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))


@pytest.fixture
def probe_runtime(tmp_path, monkeypatch):
    """Isolate the persistent serial-bridge daemon rendezvous to a tmp dir and retire any daemon a
    test spawned on teardown.

    The `--backend serial` client spawns a DETACHED persistent daemon (it deliberately outlives the
    client). For test hygiene we point its rendezvous at an isolated dir, give it a short idle
    lifetime, and on teardown SIGTERM + reap any daemon still registered so nothing leaks between
    tests."""
    rt = tmp_path / "runtime"
    monkeypatch.setenv("ESPILON_PROBE_RUNTIME", str(rt))
    monkeypatch.setenv("ESPILON_PROBE_BRIDGE_IDLE", "10")
    yield rt
    for info in glob.glob(str(rt / "espilon-probe" / "*.json")):
        try:
            with open(info, encoding="utf-8") as fh:
                pid = int(json.load(fh)["pid"])
        except Exception:
            continue
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
        try:
            os.waitpid(pid, 0)          # reap our child so it does not linger as a zombie
        except OSError:
            pass
