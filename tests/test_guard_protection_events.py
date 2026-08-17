"""Protection posture telemetry events."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.config import update_guard_settings
from codex_plugin_scanner.guard.store import GuardStore


def test_posture_change_records_timeline_event(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    update_guard_settings(guard_home, {"protection_posture": "watch"})
    events = GuardStore(guard_home).list_events()
    names = [str(item.get("event_name") or "") for item in events]
    assert "guard.protection.posture_selected" in names
    assert "guard.protection.watch_entered" in names


def test_watch_revert_records_timeline_event(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    update_guard_settings(guard_home, {"protection_posture": "watch"})
    update_guard_settings(guard_home, {"protection_posture": "protected"})
    events = GuardStore(guard_home).list_events()
    names = [str(item.get("event_name") or "") for item in events]
    assert "guard.protection.watch_reverted" in names


def test_explicit_watch_from_implicit_observe_records_watch_entered(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    guard_home.mkdir(parents=True)
    (guard_home / "config.toml").write_text('mode = "observe"\n', encoding="utf-8")
    update_guard_settings(
        guard_home,
        {"protection_posture": "watch", "protection_posture_explicit": True},
    )
    names = [str(item.get("event_name") or "") for item in GuardStore(guard_home).list_events()]
    assert "guard.protection.posture_selected" in names
    assert "guard.protection.watch_entered" in names


def test_explicit_protected_from_implicit_records_posture_selected(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    update_guard_settings(
        guard_home,
        {"protection_posture": "protected", "protection_posture_explicit": True},
    )
    names = [str(item.get("event_name") or "") for item in GuardStore(guard_home).list_events()]
    assert "guard.protection.posture_selected" in names


def test_ask_once_shown_records_on_enqueue(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.approvals import queue_blocked_approvals
    from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection

    guard_home = tmp_path / ".hol-guard"
    workspace = tmp_path / "workspace"
    store = GuardStore(guard_home)
    artifact = GuardArtifact(
        artifact_id="codex:runtime:project:danger_lab:ask_once",
        name="danger_lab:ask_once",
        harness="codex",
        artifact_type="tool_call",
        source_scope="project",
        config_path=str(workspace / ".codex" / "config.toml"),
        command="ask_once",
    )
    detection = HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(artifact.config_path,),
        artifacts=(artifact,),
    )
    queue_blocked_approvals(
        detection=detection,
        evaluation={
            "artifacts": [
                {
                    "artifact_id": artifact.artifact_id,
                    "artifact_name": artifact.name,
                    "artifact_hash": "hash-ask-once",
                    "artifact_type": artifact.artifact_type,
                    "source_scope": artifact.source_scope,
                    "config_path": artifact.config_path,
                    "changed_fields": ["runtime_tool_call"],
                    "policy_action": "require-reapproval",
                    "launch_target": "ask_once",
                }
            ]
        },
        store=store,
        approval_center_url="http://127.0.0.1:4455",
        now="2026-04-17T00:00:00+00:00",
    )
    names = [str(item.get("event_name") or "") for item in store.list_events()]
    assert "guard.protection.ask_once_shown" in names
    assert "guard.protection.ask_once_remembered" not in names


def test_known_bad_auto_stop_records_timeline_event(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.cli.commands_support_runtime_policy import (
        _apply_explicit_posture_action,
    )
    from codex_plugin_scanner.guard.models import GuardArtifact

    guard_home = tmp_path / ".hol-guard"
    config = update_guard_settings(guard_home, {"protection_posture": "protected"})
    artifact = GuardArtifact(
        artifact_id="codex:project:tool-action:exfil",
        name="exfil",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path="/workspace/repo/.guard/config.toml",
        metadata={"risk_confidence": "strong"},
    )
    action = _apply_explicit_posture_action(config, artifact, "credential_exfiltration", "require-reapproval")
    assert action == "block"
    names = [str(item.get("event_name") or "") for item in GuardStore(guard_home).list_events()]
    assert "guard.protection.auto_stop" in names
