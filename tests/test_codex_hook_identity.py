"""P23 regressions for format-independent Codex hook identity and migration."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import codex as codex_adapter
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.codex_config import dump_toml
from codex_plugin_scanner.guard.codex_hook_inventory import enumerate_codex_hooks
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.consumer.service import (
    _consumer_approval_context_token,
    artifact_hash,
    diff_artifact,
)
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.types import ProvenanceBundle


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _group(
    command: str = "python3 hook.py",
    *,
    matcher: str = "Bash",
    handler_type: str = "command",
    **handler_fields: object,
) -> dict[str, object]:
    return {
        "matcher": matcher,
        "hooks": [{"type": handler_type, "command": command, **handler_fields}],
    }


def _record_identity(
    group: Mapping[str, object],
    *,
    event: str = "PreToolUse",
    source_format: str = "json",
    tmp_path: Path,
) -> str:
    inventory = enumerate_codex_hooks(
        {"hooks": {event: [group]}},
        source_path=tmp_path / ("hooks.json" if source_format == "json" else "config.toml"),
        source_scope="global",
        source_format="json" if source_format == "json" else "toml",
        source_hooks_enabled=True,
    )
    assert len(inventory.records) == 1
    return inventory.records[0].canonical_identity


def _hook_artifact(detection: HarnessDetection, event: str) -> GuardArtifact:
    return next(
        artifact for artifact in detection.artifacts if artifact.artifact_type == "hook" and artifact.name == event
    )


def _approval_token(
    detection: HarnessDetection,
    artifact: GuardArtifact,
    *,
    tmp_path: Path,
) -> str:
    return _consumer_approval_context_token(
        detection=detection,
        artifact=artifact,
        content_hash=artifact_hash(artifact),
        capability_snapshot={},
        structured_signals=(),
        provenance=ProvenanceBundle(),
        config=GuardConfig(guard_home=tmp_path / "guard-home", workspace=None),
        configured_action=None,
        effective_default_action=None,
        current_action="review",
        runtime_detector_context=None,
    )


def test_json_and_toml_inventory_share_identity_for_plain_argv_and_mapping_order(tmp_path: Path) -> None:
    json_group = {
        "matcher": "Bash",
        "description": "fixture",
        "hooks": [
            {
                "type": "command",
                "command": "python3   hook.py --mode safe",
                "env": {"SECOND": "2", "FIRST": "1"},
                "timeout": 12,
            }
        ],
    }
    toml_group = {
        "hooks": [
            {
                "timeout": 12.0,
                "env": {"FIRST": "1", "SECOND": "2"},
                "command": "python3 hook.py --mode safe",
                "type": "command",
            }
        ],
        "description": "fixture",
        "matcher": "Bash",
    }

    assert _record_identity(json_group, tmp_path=tmp_path) == _record_identity(
        toml_group,
        source_format="toml",
        tmp_path=tmp_path,
    )


@pytest.mark.parametrize(
    "changed_group",
    (
        _group(env={"MODE": "changed"}),
        _group(timeout=13),
        _group(matcher="Read"),
        _group(command="python3 'hook.py'"),
        _group(handler_type="future-command"),
        _group(statusMessage="changed status"),
    ),
)
def test_execution_affecting_hook_fields_have_distinct_identities(
    tmp_path: Path,
    changed_group: dict[str, object],
) -> None:
    assert _record_identity(_group(), tmp_path=tmp_path) != _record_identity(changed_group, tmp_path=tmp_path)


def test_event_name_is_part_of_canonical_identity(tmp_path: Path) -> None:
    group = _group()

    assert _record_identity(group, event="PreToolUse", tmp_path=tmp_path) != _record_identity(
        group,
        event="FutureAgentEvent",
        tmp_path=tmp_path,
    )


def test_migration_identity_uses_the_written_hook_activation_state() -> None:
    payload: dict[str, object] = {"hooks": {"PreToolUse": [_group()]}}

    disabled = codex_adapter._migration_group_identities(
        payload,
        source_scope="global",
        source_hooks_enabled=False,
    )
    enabled = codex_adapter._migration_group_identities(
        payload,
        source_scope="global",
        source_hooks_enabled=True,
    )

    assert len(disabled) == 1
    assert len(enabled) == 1
    assert disabled != enabled


def test_detect_inventories_every_toml_event_and_deduplicates_mixed_sources(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    config_path = home_dir / ".codex" / "config.toml"
    hooks_path = home_dir / ".codex" / "hooks.json"
    shared_toml_group = _group("python3 hook.py")
    shared_json_group = _group("python3   hook.py")
    _write(
        config_path,
        dump_toml(
            {
                "features": {"hooks": True},
                "hooks": {
                    "FutureAgentEvent": [shared_toml_group],
                    "Stop": [_group("python3 stop.py", matcher="stop")],
                },
            }
        ),
    )
    _write(hooks_path, json.dumps({"hooks": {"FutureAgentEvent": [shared_json_group]}}) + "\n")

    detection = codex_adapter.CodexHarnessAdapter().detect(
        HarnessContext(home_dir=home_dir, workspace_dir=None, guard_home=tmp_path / "guard-home")
    )
    hook_artifacts = [artifact for artifact in detection.artifacts if artifact.artifact_type == "hook"]
    future = _hook_artifact(detection, "FutureAgentEvent")

    assert {artifact.name for artifact in hook_artifacts} == {"FutureAgentEvent", "Stop"}
    assert len(hook_artifacts) == 2
    assert future.metadata["source_formats"] == ["json", "toml"]
    assert future.metadata["source_paths"] == sorted([str(config_path), str(hooks_path)])


def test_authenticated_guard_hooks_do_not_become_consumer_artifacts(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    context = HarnessContext(home_dir=home_dir, workspace_dir=None, guard_home=tmp_path / "guard-home")
    adapter = codex_adapter.CodexHarnessAdapter()

    adapter.install(context)
    detection = adapter.detect(context)

    assert not [artifact for artifact in detection.artifacts if artifact.artifact_type == "hook"]


def test_hash_diff_and_approval_identity_survive_json_to_toml_format_change(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    config_path = home_dir / ".codex" / "config.toml"
    hooks_path = home_dir / ".codex" / "hooks.json"
    _write(config_path, dump_toml({"features": {"hooks": True}}))
    _write(hooks_path, json.dumps({"hooks": {"FutureAgentEvent": [_group()]}}) + "\n")
    adapter = codex_adapter.CodexHarnessAdapter()
    context = HarnessContext(home_dir=home_dir, workspace_dir=None, guard_home=tmp_path / "guard-home")
    json_detection = adapter.detect(context)
    json_artifact = _hook_artifact(json_detection, "FutureAgentEvent")

    hooks_path.unlink()
    _write(
        config_path,
        dump_toml({"features": {"hooks": True}, "hooks": {"FutureAgentEvent": [_group()]}}),
    )
    toml_detection = adapter.detect(context)
    toml_artifact = _hook_artifact(toml_detection, "FutureAgentEvent")
    previous = {**json_artifact.to_dict(), "artifact_hash": artifact_hash(json_artifact)}

    assert json_artifact.artifact_id == toml_artifact.artifact_id
    assert artifact_hash(json_artifact) == artifact_hash(toml_artifact)
    assert diff_artifact(previous, toml_artifact)["changed"] is False
    assert _approval_token(json_detection, json_artifact, tmp_path=tmp_path) == _approval_token(
        toml_detection,
        toml_artifact,
        tmp_path=tmp_path,
    )

    tampered_previous = {**previous, "artifact_hash": "0" * 64}
    tampered_diff = diff_artifact(tampered_previous, toml_artifact)
    assert tampered_diff["changed"] is True
    assert tampered_diff["changed_fields"] == ["metadata"]


def test_migration_deduplicates_only_canonical_equivalents_and_surfaces_conflicts(tmp_path: Path) -> None:
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard")
    config_payload: dict[str, object] = {
        "features": {"hooks": True},
        "hooks": {"PreToolUse": [_group("python3 hook.py", timeout=12)]},
    }
    equivalent: dict[str, object] = {"hooks": {"PreToolUse": [_group("python3   hook.py", timeout=12.0)]}}

    changed = codex_adapter._migrate_hooks_json_into_config(
        config_payload,
        equivalent,
        context=context,
        source_scope="global",
    )

    assert changed is False
    config_hooks = config_payload["hooks"]
    assert isinstance(config_hooks, dict)
    pre_tool_use = config_hooks["PreToolUse"]
    assert isinstance(pre_tool_use, list)
    assert len(pre_tool_use) == 1

    conflicting: dict[str, object] = {"hooks": {"PreToolUse": [_group("python3 hook.py", timeout=13)]}}
    with pytest.raises(RuntimeError, match="codex_hook_migration_conflict"):
        codex_adapter._migrate_hooks_json_into_config(
            config_payload,
            conflicting,
            context=context,
            source_scope="global",
        )


def test_readback_failure_preserves_original_toml_and_legacy_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    guard_home = tmp_path / "guard-home"
    config_path = home_dir / ".codex" / "config.toml"
    hooks_path = home_dir / ".codex" / "hooks.json"
    original_config = '[features]\nhooks = true\nmodel = "fixture"\n'
    original_hooks = json.dumps({"hooks": {"FutureAgentEvent": [_group()]}}) + "\n"
    _write(config_path, original_config)
    _write(hooks_path, original_hooks)

    def _fail_readback(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("injected canonical readback failure")

    monkeypatch.setattr(codex_adapter, "_require_hook_semantics_readback", _fail_readback)

    with pytest.raises(RuntimeError, match="injected canonical readback failure"):
        codex_adapter.CodexHarnessAdapter().install(
            HarnessContext(home_dir=home_dir, workspace_dir=None, guard_home=guard_home)
        )

    assert config_path.read_text(encoding="utf-8") == original_config
    assert hooks_path.read_text(encoding="utf-8") == original_hooks
    backups = list((guard_home / "managed" / "codex" / "migration-backups").glob("*.json"))
    assert len(backups) == 1
    assert json.loads(backups[0].read_text(encoding="utf-8"))["content"] == original_config


def test_partial_unlink_failure_restores_every_legacy_source_and_keeps_toml_backups(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    home_config = home_dir / ".codex" / "config.toml"
    workspace_config = workspace_dir / ".codex" / "config.toml"
    home_hooks = home_dir / ".codex" / "hooks.json"
    workspace_hooks = workspace_dir / ".codex" / "hooks.json"
    original_home_config = '[features]\nhooks = true\nmodel = "fixture"\n'
    original_workspace_config = '[features]\nhooks = true\napproval_policy = "never"\n'
    original_home_hooks = json.dumps({"hooks": {"FutureGlobalEvent": [_group("python3 global.py")]}}) + "\n"
    original_workspace_hooks = json.dumps({"hooks": {"FutureProjectEvent": [_group("python3 project.py")]}}) + "\n"
    _write(home_config, original_home_config)
    _write(workspace_config, original_workspace_config)
    _write(home_hooks, original_home_hooks)
    _write(workspace_hooks, original_workspace_hooks)
    original_unlink = Path.unlink
    failed = False

    def _unlink(path: Path, missing_ok: bool = False) -> None:
        nonlocal failed
        if path == workspace_hooks and not failed:
            failed = True
            raise OSError("injected legacy unlink failure")
        original_unlink(path, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", _unlink)

    with pytest.raises(OSError, match="injected legacy unlink failure"):
        codex_adapter.CodexHarnessAdapter().install(
            HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=guard_home)
        )

    assert home_hooks.read_text(encoding="utf-8") == original_home_hooks
    assert workspace_hooks.read_text(encoding="utf-8") == original_workspace_hooks
    assert home_config.read_text(encoding="utf-8") == original_home_config
    assert workspace_config.read_text(encoding="utf-8") == original_workspace_config
    assert not codex_adapter.hook_manifest_path(guard_home, home_config).exists()
    assert not codex_adapter.hook_secret_path(guard_home).exists()
    backup_payloads = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in (guard_home / "managed" / "codex" / "migration-backups").glob("*.json")
    ]
    assert {payload["content"] for payload in backup_payloads} == {
        original_home_config,
        original_workspace_config,
    }
