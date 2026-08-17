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
