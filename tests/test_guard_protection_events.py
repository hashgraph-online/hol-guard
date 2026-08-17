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
