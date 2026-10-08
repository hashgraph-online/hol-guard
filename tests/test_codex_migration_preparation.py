"""Captured Codex migration contracts preserve sources and rollback material."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from codex_plugin_scanner.guard.adapters import codex as adapter
from codex_plugin_scanner.guard.codex_hook_sources import parse_toml_object
from codex_plugin_scanner.guard.runtime_transition import TransitionError

from .test_codex_publication_preparation import _context, _tree
from .test_runtime_transition import begin, transition  # noqa: F401 -- imported pytest fixture


def _sources(tmp_path, monkeypatch):
    context = _context(tmp_path, monkeypatch)
    config = context.home_dir / ".codex/config.toml"
    hooks = config.with_name("hooks.json")
    config.parent.mkdir(parents=True)
    config.write_text('model = "fixture"\n')
    hooks.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {"matcher": "Bash", "hooks": [{"type": "command", "command": "python3 user_hook.py"}]},
                    ]
                }
            }
        )
    )
    config.chmod(0o644)
    hooks.chmod(0o600)
    return context, config, hooks


def test_migration_capture_never_publishes_or_creates_backup(tmp_path, monkeypatch):
    context, config, hooks = _sources(tmp_path, monkeypatch)
    before = _tree(tmp_path)
    prepared = adapter.prepare_codex_hook_migration(context, config_path=config, hooks_path=hooks)
    assert _tree(tmp_path) == before
    changes = {change.path: change for change in prepared.files}
    migrated = parse_toml_object(changes[config].after, path=config, label="fixture")
    assert migrated["model"] == "fixture"
    assert migrated["hooks"] == json.loads(hooks.read_text())["hooks"]
    assert changes[hooks].before == hooks.read_bytes()
    assert changes[hooks].after is None
    backup = next(change for change in prepared.files if change.path not in {config, hooks})
    payload = json.loads(backup.after)
    assert payload["content"] == config.read_text()
    assert payload["existed"] is True
    assert not backup.path.exists()


def test_existing_migration_backup_remains_unchanged(tmp_path, monkeypatch):
    context, config, hooks = _sources(tmp_path, monkeypatch)
    first = adapter.prepare_codex_hook_migration(context, config_path=config, hooks_path=hooks)
    backup = next(change for change in first.files if change.path not in {config, hooks})
    backup.path.parent.mkdir(parents=True)
    backup.path.write_bytes(b"existing backup generation")
    backup.path.chmod(0o600)
    before = _tree(tmp_path)
    second = adapter.prepare_codex_hook_migration(context, config_path=config, hooks_path=hooks)
    assert _tree(tmp_path) == before
    retained = next(change for change in second.files if change.path == backup.path)
    assert retained.before == retained.after == b"existing backup generation"


@pytest.mark.parametrize("invalid", [b'{"hooks":{},"hooks":{}}', b"[1,2]", b"\xff"])
def test_invalid_json_cannot_create_migration_files(tmp_path, monkeypatch, invalid):
    context, config, hooks = _sources(tmp_path, monkeypatch)
    hooks.write_bytes(invalid)
    before = _tree(tmp_path)
    with pytest.raises(RuntimeError, match="codex_hook_inventory_source_"):
        adapter.prepare_codex_hook_migration(context, config_path=config, hooks_path=hooks)
    assert _tree(tmp_path) == before


def test_invalid_toml_cannot_retire_json_source(tmp_path, monkeypatch):
    context, config, hooks = _sources(tmp_path, monkeypatch)
    config.write_bytes(b"\xff")
    before = _tree(tmp_path)
    with pytest.raises(RuntimeError, match="codex_hook_inventory_source_malformed"):
        adapter.prepare_codex_hook_migration(context, config_path=config, hooks_path=hooks)
    assert _tree(tmp_path) == before


def test_changed_source_after_inventory_never_publishes_migration(tmp_path, monkeypatch):
    context, config, hooks = _sources(tmp_path, monkeypatch)
    expected_hooks = json.loads(hooks.read_text())
    config.write_text('model = "user-modified"\n')
    before = _tree(tmp_path)
    with pytest.raises(RuntimeError, match="codex_hook_inventory_source_changed"):
        adapter.prepare_codex_hook_migration(
            context,
            config_path=config,
            hooks_path=hooks,
            expected_config_payload={"model": "fixture"},
            expected_hooks_payload=expected_hooks,
        )
    assert _tree(tmp_path) == before


def test_foreign_json_generation_during_render_is_preserved(tmp_path, monkeypatch):
    context, config, hooks = _sources(tmp_path, monkeypatch)
    original = adapter._migrate_hooks_json_into_config

    def foreign_write(*args, **kwargs):
        result = original(*args, **kwargs)
        hooks.write_text('{"foreign":"generation"}')
        return result

    monkeypatch.setattr(adapter, "_migrate_hooks_json_into_config", foreign_write)
    with pytest.raises(TransitionError, match="generation_changed"):
        adapter.prepare_codex_hook_migration(context, config_path=config, hooks_path=hooks)
    assert json.loads(hooks.read_text()) == {"foreign": "generation"}
    assert config.read_text() == 'model = "fixture"\n'
    assert not context.guard_home.exists()


@pytest.mark.parametrize("existing_backup", [False, True])
def test_signed_migration_inverse_restores_sources_and_backup(
    transition,  # noqa: F811 -- pytest injects the imported shared fixture
    tmp_path,
    monkeypatch,
    existing_backup,
):
    runtime, plan, _bindings, _pointer = transition
    context, config, hooks = _sources(tmp_path, monkeypatch)
    prepared = adapter.prepare_codex_hook_migration(context, config_path=config, hooks_path=hooks)
    if existing_backup:
        backup = next(change for change in prepared.files if change.path not in {config, hooks})
        backup.path.parent.mkdir(parents=True)
        backup.path.write_bytes(b"prior backup generation")
        backup.path.chmod(0o600)
        prepared = adapter.prepare_codex_hook_migration(context, config_path=config, hooks_path=hooks)
    plan = replace(plan, files=(*plan.files, *prepared.files))
    begin(runtime, plan)
    runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
    runtime.publish(plan.operation_id, "HooksPrepared")
    assert not hooks.exists()
    runtime.restore_files(plan.operation_id, first_cause="fixture candidate failed")
    for change in prepared.files:
        if change.before is None:
            assert not change.path.exists()
        else:
            assert change.path.read_bytes() == change.before
            assert change.path.stat().st_mode & 0o777 == change.before_mode
