"""Regression tests for Guard branding on local state paths."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard import bridge as bridge_module
from codex_plugin_scanner.guard.config import load_guard_config, resolve_guard_home
from codex_plugin_scanner.guard.store import GuardStore


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_resolve_guard_home_defaults_to_hol_guard_directory(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    monkeypatch.setattr(Path, "home", lambda: home_dir)

    assert resolve_guard_home() == home_dir / ".hol-guard"


def test_resolve_guard_home_falls_back_to_legacy_directory(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    legacy_home = home_dir / ".config" / ".ai-plugin-scanner-guard"
    legacy_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(Path, "home", lambda: home_dir)

    assert resolve_guard_home() == legacy_home


def test_resolve_guard_home_prefers_legacy_state_over_empty_canonical_directory(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    canonical_home = home_dir / ".hol-guard"
    legacy_home = home_dir / ".config" / ".ai-plugin-scanner-guard"
    canonical_home.mkdir(parents=True, exist_ok=True)
    _write_text(legacy_home / "guard.db", "sqlite placeholder")
    monkeypatch.setattr(Path, "home", lambda: home_dir)

    assert resolve_guard_home() == legacy_home


def test_resolve_guard_home_prefers_legacy_credentials_over_empty_canonical_database(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    canonical_home = home_dir / ".hol-guard"
    legacy_home = home_dir / ".ai-plugin-scanner-guard"
    GuardStore(canonical_home)
    legacy_store = GuardStore(legacy_home)
    legacy_store.set_sync_credentials("https://hol.org/api/guard/receipts/sync", "legacy-token", "2026-04-15T00:00:00Z")
    monkeypatch.setattr(Path, "home", lambda: home_dir)

    assert resolve_guard_home() == legacy_home


def test_resolve_guard_home_keeps_canonical_state_when_legacy_only_has_credentials(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    canonical_home = home_dir / ".hol-guard"
    legacy_home = home_dir / ".ai-plugin-scanner-guard"
    _write_text(canonical_home / "guard.db", "sqlite placeholder")
    legacy_store = GuardStore(legacy_home)
    legacy_store.set_sync_credentials("https://hol.org/api/guard/receipts/sync", "legacy-token", "2026-04-15T00:00:00Z")
    monkeypatch.setattr(Path, "home", lambda: home_dir)

    assert resolve_guard_home() == canonical_home


def test_load_guard_config_prefers_hol_guard_workspace_override(tmp_path):
    guard_home = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    guard_home.mkdir(parents=True, exist_ok=True)
    _write_text(guard_home / "config.toml", 'default_action = "warn"\n')
    _write_text(workspace_dir / ".ai-plugin-scanner-guard.toml", 'default_action = "allow"\n')
    _write_text(workspace_dir / ".hol-guard.toml", 'default_action = "block"\n')

    config = load_guard_config(guard_home, workspace_dir)

    assert config.default_action == "block"


def test_load_guard_config_merges_nested_workspace_tables_across_legacy_and_hol_guard_files(tmp_path):
    guard_home = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    guard_home.mkdir(parents=True, exist_ok=True)
    _write_text(
        workspace_dir / ".ai-plugin-scanner-guard.toml",
        "\n".join(
            [
                "[harnesses.codex]",
                'default_action = "allow"',
            ]
        )
        + "\n",
    )
    _write_text(
        workspace_dir / ".hol-guard.toml",
        "\n".join(
            [
                "[harnesses.claude-code]",
                'default_action = "block"',
            ]
        )
        + "\n",
    )

    config = load_guard_config(guard_home, workspace_dir)

    assert config.harness_actions == {
        "codex": "allow",
        "claude-code": "block",
    }


def test_load_guard_config_new_action_alias_overrides_legacy_alias(tmp_path):
    guard_home = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    guard_home.mkdir(parents=True, exist_ok=True)
    _write_text(
        workspace_dir / ".ai-plugin-scanner-guard.toml",
        "\n".join(
            [
                "[harnesses.codex]",
                'action = "block"',
            ]
        )
        + "\n",
    )
    _write_text(
        workspace_dir / ".hol-guard.toml",
        "\n".join(
            [
                "[harnesses.codex]",
                'default_action = "allow"',
            ]
        )
        + "\n",
    )

    config = load_guard_config(guard_home, workspace_dir)

    assert config.harness_actions == {"codex": "allow"}


def test_run_bridge_uses_resolved_guard_home_by_default(tmp_path, monkeypatch):
    expected_guard_home = tmp_path / ".hol-guard"
    captured: dict[str, Path] = {}

    class _FakeGuardBridge:
        def __init__(self, *, config, store, backend):
            captured["guard_home"] = store.guard_home

        def run(self) -> None:
            return

    monkeypatch.setattr(bridge_module, "resolve_guard_home", lambda: expected_guard_home)
    monkeypatch.setattr(bridge_module, "GuardBridge", _FakeGuardBridge)

    bridge_module.run_bridge(dry_run=True)

    assert captured["guard_home"] == expected_guard_home
