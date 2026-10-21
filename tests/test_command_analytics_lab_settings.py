"""The approval lab initializes fresh settings and preserves a resumed home."""

import importlib.util
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import config


@pytest.mark.parametrize("existing_mode", [None, "ask", "safe-alternative"])
def test_lab_settings_are_initialized_only_for_a_fresh_home(tmp_path, monkeypatch, existing_mode):
    path = Path(__file__).parent / "dockerlabs/command-extension-analytics/installed_server.py"
    spec = importlib.util.spec_from_file_location("guard_analytics_settings_fixture", path)
    assert spec is not None and spec.loader is not None
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    home = tmp_path / "guard"
    home.mkdir()
    before = None
    if existing_mode is not None:
        config.update_guard_settings(home, {"blocked_request_mode": existing_mode})
        before = (home / "config.toml").read_bytes()

        def unexpected_write(*args, **kwargs):
            pytest.fail("a resumed approval lab must not request a gated settings write")

        monkeypatch.setattr(config, "update_guard_settings", unexpected_write)
    monkeypatch.setattr(fixture, "GUARD_HOME", home)
    monkeypatch.setattr(fixture, "_prepare_workspace", lambda: None)
    monkeypatch.setattr(fixture, "GuardStore", lambda *args, **kwargs: object())
    monkeypatch.setenv("HOL_GUARD_LAB_EXPECTED_VERSION", fixture.__version__)

    def daemon_boundary(*args, **kwargs):
        raise RuntimeError("fixture_daemon_boundary")

    monkeypatch.setattr(fixture, "GuardDaemonServer", daemon_boundary)
    with pytest.raises(RuntimeError, match="fixture_daemon_boundary"):
        fixture.main()
    assert config.load_guard_config(home).blocked_request_mode == (existing_mode or "ask")
    if before is not None:
        assert (home / "config.toml").read_bytes() == before
