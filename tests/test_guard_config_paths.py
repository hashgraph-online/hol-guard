"""Regression tests for Guard branding on local state paths."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import bridge as bridge_module
from codex_plugin_scanner.guard import config as guard_config_module
from codex_plugin_scanner.guard.config import (
    GuardHomeMigrationError,
    _copy_guard_database,
    _migrate_guard_home_state,
    load_guard_config,
    resolve_guard_home,
    update_guard_settings,
)
from codex_plugin_scanner.guard.store import GuardStore


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _create_sqlite_guard_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        connection.execute("create table migration_probe (value text)")
        connection.execute("insert into migration_probe(value) values ('legacy')")


def test_resolve_guard_home_defaults_to_hol_guard_directory(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    monkeypatch.setattr(Path, "home", lambda: home_dir)

    assert resolve_guard_home() == home_dir / ".hol-guard"


def test_dashboard_settings_update_persists_to_cli_config_loader(tmp_path):
    guard_home = tmp_path / ".hol-guard"
    _write_text(
        guard_home / "config.toml",
        'mode = "prompt"\ndefault_action = "warn"\n\n[harnesses]\ncodex = "review"\n',
    )

    updated = update_guard_settings(
        guard_home,
        {
            "mode": "enforce",
            "default_action": "review",
            "changed_hash_action": "block",
            "approval_wait_timeout_seconds": 45,
            "approval_surface_policy": "approval-center",
            "telemetry": True,
            "ignored_key": "ignored",
        },
    )
    loaded = load_guard_config(guard_home)
    config_text = (guard_home / "config.toml").read_text(encoding="utf-8")

    assert updated.mode == "enforce"
    assert loaded.mode == "enforce"
    assert loaded.default_action == "review"
    assert loaded.changed_hash_action == "block"
    assert loaded.approval_wait_timeout_seconds == 45
    assert loaded.approval_surface_policy == "approval-center"
    assert loaded.telemetry is True
    assert loaded.harness_actions == {"codex": "review"}
    assert "ignored_key" not in config_text


def test_dashboard_settings_update_preserves_nested_cli_policy_tables(tmp_path):
    guard_home = tmp_path / ".hol-guard"
    _write_text(
        guard_home / "config.toml",
        "\n".join(
            [
                'mode = "prompt"',
                "",
                "[harnesses.codex]",
                'default_action = "review"',
                "",
                '[publishers."@scope/pkg"]',
                'action = "block"',
                "",
                '[artifacts."codex:project:workspace-tools"]',
                'action = "allow"',
            ]
        )
        + "\n",
    )

    updated = update_guard_settings(
        guard_home,
        {
            "mode": "enforce",
            "approval_wait_timeout_seconds": 30,
        },
    )
    loaded = load_guard_config(guard_home)
    config_text = (guard_home / "config.toml").read_text(encoding="utf-8")

    assert updated.mode == "enforce"
    assert loaded.mode == "enforce"
    assert loaded.approval_wait_timeout_seconds == 30
    assert loaded.harness_actions == {"codex": "review"}
    assert loaded.publisher_actions == {"@scope/pkg": "block"}
    assert loaded.artifact_actions == {"codex:project:workspace-tools": "allow"}
    assert "[harnesses.codex]" in config_text
    assert '[publishers."@scope/pkg"]' in config_text
    assert '[artifacts."codex:project:workspace-tools"]' in config_text


def test_dashboard_settings_update_rejects_boolean_approval_timeout(tmp_path):
    guard_home = tmp_path / ".hol-guard"
    _write_text(
        guard_home / "config.toml",
        'mode = "prompt"\napproval_wait_timeout_seconds = 45\n',
    )

    with pytest.raises(ValueError, match="Approval wait timeout"):
        update_guard_settings(
            guard_home,
            {
                "approval_wait_timeout_seconds": True,
            },
        )

    loaded = load_guard_config(guard_home)
    assert loaded.approval_wait_timeout_seconds == 45


def test_dashboard_settings_update_preserves_existing_float_config_values(tmp_path):
    guard_home = tmp_path / ".hol-guard"
    _write_text(
        guard_home / "config.toml",
        'mode = "prompt"\nscore_threshold = 0.75\n',
    )

    updated = update_guard_settings(
        guard_home,
        {
            "mode": "enforce",
        },
    )
    config_payload = guard_config_module._read_toml(guard_home / "config.toml")

    assert updated.mode == "enforce"
    assert config_payload["score_threshold"] == 0.75
    assert isinstance(config_payload["score_threshold"], float)


def test_dashboard_settings_update_preserves_existing_array_config_values(tmp_path):
    guard_home = tmp_path / ".hol-guard"
    _write_text(
        guard_home / "config.toml",
        'mode = "prompt"\ntrusted_harnesses = ["codex", "claude-code"]\n',
    )

    updated = update_guard_settings(
        guard_home,
        {
            "mode": "enforce",
        },
    )
    config_payload = guard_config_module._read_toml(guard_home / "config.toml")

    assert updated.mode == "enforce"
    assert config_payload["trusted_harnesses"] == ["codex", "claude-code"]


def test_dashboard_settings_update_preserves_existing_inline_table_array_config_values(tmp_path):
    guard_home = tmp_path / ".hol-guard"
    _write_text(
        guard_home / "config.toml",
        'mode = "prompt"\nrules = [{ name = "canary", action = "review", weight = 0.5 }]\n',
    )

    updated = update_guard_settings(
        guard_home,
        {
            "mode": "enforce",
        },
    )
    config_payload = guard_config_module._read_toml(guard_home / "config.toml")

    assert updated.mode == "enforce"
    assert config_payload["rules"] == [{"name": "canary", "action": "review", "weight": 0.5}]


def test_resolve_guard_home_migrates_legacy_directory_into_canonical_home(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    legacy_home = home_dir / ".config" / ".ai-plugin-scanner-guard"
    legacy_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(Path, "home", lambda: home_dir)

    assert resolve_guard_home() == home_dir / ".hol-guard"


def test_migrate_guard_home_state_copies_guard_db_with_sqlite_backup(tmp_path):
    canonical_home = tmp_path / ".hol-guard"
    legacy_home = tmp_path / ".config" / ".ai-plugin-scanner-guard"
    _create_sqlite_guard_db(legacy_home / "guard.db")

    _migrate_guard_home_state(source=legacy_home, destination=canonical_home)

    with sqlite3.connect(canonical_home / "guard.db") as connection:
        row = connection.execute("select value from migration_probe").fetchone()
    assert row == ("legacy",)


def test_resolve_guard_home_migrates_legacy_credentials_into_canonical_database(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    canonical_home = home_dir / ".hol-guard"
    legacy_home = home_dir / ".ai-plugin-scanner-guard"
    GuardStore(canonical_home)
    legacy_store = GuardStore(legacy_home)
    legacy_store.set_sync_credentials("https://hol.org/api/guard/receipts/sync", "legacy-token", "2026-04-15T00:00:00Z")
    monkeypatch.setattr(Path, "home", lambda: home_dir)

    resolved_home = resolve_guard_home()

    assert resolved_home == canonical_home
    canonical_store = GuardStore(canonical_home)
    assert canonical_store.get_sync_credentials() == {
        "token": "legacy-token",
        "sync_url": "https://hol.org/api/guard/receipts/sync",
    }


def test_migrate_guard_home_state_merges_nested_legacy_directories(tmp_path):
    canonical_home = tmp_path / ".hol-guard"
    legacy_home = tmp_path / ".ai-plugin-scanner-guard"
    _write_text(canonical_home / "bin" / "keep.txt", "canonical")
    _write_text(legacy_home / "bin" / "legacy.txt", "legacy")

    _migrate_guard_home_state(source=legacy_home, destination=canonical_home)

    assert (canonical_home / "bin" / "keep.txt").read_text(encoding="utf-8") == "canonical"
    assert (canonical_home / "bin" / "legacy.txt").read_text(encoding="utf-8") == "legacy"


def test_migrate_guard_home_state_skips_legacy_daemon_runtime_state(tmp_path):
    canonical_home = tmp_path / ".hol-guard"
    legacy_home = tmp_path / ".ai-plugin-scanner-guard"
    _write_text(legacy_home / "daemon-state.json", '{"port": 1, "auth_token": "legacy"}')
    _write_text(legacy_home / "config.toml", 'default_action = "warn"\n')

    _migrate_guard_home_state(source=legacy_home, destination=canonical_home)

    assert not (canonical_home / "daemon-state.json").exists()
    assert (canonical_home / "config.toml").read_text(encoding="utf-8") == 'default_action = "warn"\n'


def test_migrate_guard_home_state_skips_legacy_sqlite_sidecars(tmp_path, monkeypatch):
    canonical_home = tmp_path / ".hol-guard"
    legacy_home = tmp_path / ".ai-plugin-scanner-guard"
    _write_text(legacy_home / "guard.db", "legacy-db")
    _write_text(legacy_home / "guard.db-wal", "wal")
    _write_text(legacy_home / "guard.db-shm", "shm")
    _write_text(legacy_home / "guard.db-journal", "journal")
    copied: list[tuple[Path, Path]] = []

    def _record_copy(*, source: Path, destination: Path) -> None:
        copied.append((source, destination))
        _write_text(destination, "copied-db")

    monkeypatch.setattr(guard_config_module, "_copy_guard_database", _record_copy)

    _migrate_guard_home_state(source=legacy_home, destination=canonical_home)

    assert copied == [(legacy_home / "guard.db", canonical_home / "guard.db")]
    assert (canonical_home / "guard.db").is_file()
    assert not (canonical_home / "guard.db-wal").exists()
    assert not (canonical_home / "guard.db-shm").exists()
    assert not (canonical_home / "guard.db-journal").exists()


def test_copy_guard_database_does_not_fallback_to_raw_copy_on_sqlite_error(tmp_path, monkeypatch):
    source = tmp_path / "legacy" / "guard.db"
    destination = tmp_path / "canonical" / "guard.db"
    _write_text(source, "legacy")

    class _FailingConnection:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def backup(self, *_args, **_kwargs):
            raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(guard_config_module.sqlite3, "connect", lambda *_args, **_kwargs: _FailingConnection())
    monkeypatch.setattr(
        guard_config_module.shutil,
        "copy2",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("raw copy fallback should not run")),
    )

    try:
        _copy_guard_database(source=source, destination=destination)
        raise AssertionError("expected GuardHomeMigrationError")
    except GuardHomeMigrationError:
        pass

    assert not destination.exists()


def test_copy_guard_database_aborts_when_backup_deadline_elapses(tmp_path, monkeypatch):
    source = tmp_path / "legacy" / "guard.db"
    destination = tmp_path / "canonical" / "guard.db"
    _write_text(source, "legacy")

    class _ProgressConnection:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def backup(self, _target, *, progress=None, **_kwargs):
            if progress is not None:
                progress(0, 1, 1)

    monkeypatch.setattr(guard_config_module, "GUARD_DB_BACKUP_TIMEOUT_SECONDS", 0.0)
    monkeypatch.setattr(guard_config_module.time, "monotonic", lambda: 0.0)
    monkeypatch.setattr(guard_config_module.sqlite3, "connect", lambda *_args, **_kwargs: _ProgressConnection())
    monkeypatch.setattr(
        guard_config_module.shutil,
        "copy2",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("raw copy fallback should not run")),
    )

    try:
        _copy_guard_database(source=source, destination=destination)
        raise AssertionError("expected GuardHomeMigrationError")
    except GuardHomeMigrationError:
        pass

    assert not destination.exists()


def test_resolve_guard_home_falls_back_to_legacy_home_when_database_migration_fails(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    canonical_home = home_dir / ".hol-guard"
    legacy_home = home_dir / ".ai-plugin-scanner-guard"
    _write_text(legacy_home / "guard.db", "legacy-db")
    _write_text(legacy_home / "config.toml", 'default_action = "warn"\n')
    monkeypatch.setattr(Path, "home", lambda: home_dir)

    def _fail_copy(*, source: Path, destination: Path) -> None:
        raise GuardHomeMigrationError("guard.db migration failed")

    monkeypatch.setattr(guard_config_module, "_copy_guard_database", _fail_copy)

    assert resolve_guard_home() == legacy_home
    assert not canonical_home.exists()


def test_resolve_guard_home_falls_back_to_legacy_home_when_file_copy_fails(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    canonical_home = home_dir / ".hol-guard"
    legacy_home = home_dir / ".ai-plugin-scanner-guard"
    _write_text(legacy_home / "config.toml", 'default_action = "warn"\n')
    monkeypatch.setattr(Path, "home", lambda: home_dir)
    monkeypatch.setattr(
        guard_config_module,
        "_migrate_guard_home_state",
        lambda **_kwargs: (_ for _ in ()).throw(PermissionError("unreadable legacy file")),
    )

    assert resolve_guard_home() == legacy_home
    assert not canonical_home.exists()


def test_resolve_guard_home_keeps_canonical_state_when_legacy_only_has_credentials(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    canonical_home = home_dir / ".hol-guard"
    legacy_home = home_dir / ".ai-plugin-scanner-guard"
    _write_text(canonical_home / "guard.db", "sqlite placeholder")
    legacy_store = GuardStore(legacy_home)
    legacy_store.set_sync_credentials("https://hol.org/api/guard/receipts/sync", "legacy-token", "2026-04-15T00:00:00Z")
    monkeypatch.setattr(Path, "home", lambda: home_dir)

    assert resolve_guard_home() == canonical_home


def test_load_guard_config_ignores_workspace_default_action_overrides(tmp_path):
    guard_home = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    guard_home.mkdir(parents=True, exist_ok=True)
    _write_text(guard_home / "config.toml", 'default_action = "warn"\n')
    _write_text(workspace_dir / ".ai-plugin-scanner-guard.toml", 'default_action = "allow"\n')
    _write_text(workspace_dir / ".hol-guard.toml", 'default_action = "block"\n')

    config = load_guard_config(guard_home, workspace_dir)

    assert config.default_action == "warn"


def test_load_guard_config_ignores_workspace_action_tables_across_legacy_and_hol_guard_files(tmp_path):
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

    assert config.harness_actions == {}


def test_load_guard_config_preserves_home_action_aliases_when_workspace_tries_to_override(tmp_path):
    guard_home = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    guard_home.mkdir(parents=True, exist_ok=True)
    _write_text(
        guard_home / "config.toml",
        "\n".join(
            [
                "[harnesses.codex]",
                'action = "review"',
            ]
        )
        + "\n",
    )
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

    assert config.harness_actions == {"codex": "review"}


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
