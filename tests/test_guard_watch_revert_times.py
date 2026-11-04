"""When Watch ends, and the repair that gives an unstamped explicit Watch an end."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.config import load_guard_config, update_guard_settings


def _strip_watch_stamp(guard_home: Path) -> None:
    config_path = guard_home / "config.toml"
    lines = config_path.read_text(encoding="utf-8").splitlines(keepends=True)
    config_path.write_text(
        "".join(line for line in lines if not line.startswith("watch_entered_at")),
        encoding="utf-8",
    )


def test_explicit_watch_without_start_time_is_stamped_then_reverts(tmp_path: Path) -> None:
    from datetime import datetime, timedelta, timezone

    from codex_plugin_scanner.guard.config import maybe_auto_revert_watch

    guard_home = tmp_path / ".hol-guard"
    update_guard_settings(guard_home, {"protection_posture": "watch", "watch_auto_revert_hours": 24})
    _strip_watch_stamp(guard_home)
    unstamped = load_guard_config(guard_home)
    assert unstamped.protection_posture == "watch"
    assert unstamped.protection_posture_explicit is True
    assert unstamped.watch_entered_at is None

    stamped = maybe_auto_revert_watch(guard_home)
    assert stamped.protection_posture == "watch"
    assert stamped.watch_entered_at is not None

    reverted = maybe_auto_revert_watch(guard_home, now=datetime.now(timezone.utc) + timedelta(hours=25))
    assert reverted.protection_posture == "protected"


def test_watch_revert_times_report_when_watch_ends(tmp_path: Path) -> None:
    from datetime import datetime, timedelta

    from codex_plugin_scanner.guard.harness_posture import watch_revert_times

    guard_home = tmp_path / ".hol-guard"
    protected = update_guard_settings(guard_home, {"protection_posture": "protected"})
    assert watch_revert_times(protected)["watch_reverts_at"] is None

    loaded = update_guard_settings(guard_home, {"protection_posture": "watch", "watch_auto_revert_hours": 24})
    times = watch_revert_times(loaded)
    assert loaded.watch_entered_at is not None
    assert times["watch_entered_at"] == loaded.watch_entered_at
    entered = datetime.fromisoformat(loaded.watch_entered_at)
    assert datetime.fromisoformat(str(times["watch_reverts_at"])) == entered + timedelta(hours=24)

    never = update_guard_settings(guard_home, {"watch_auto_revert_hours": 0})
    assert watch_revert_times(never)["watch_reverts_at"] is None


def test_status_says_when_watch_ends(tmp_path: Path, capsys: object) -> None:
    import json

    from codex_plugin_scanner.cli import main
    from codex_plugin_scanner.guard.cli.render import _watch_revert_line

    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    home_dir.mkdir()
    workspace_dir.mkdir()
    update_guard_settings(guard_home, {"protection_posture": "watch", "watch_auto_revert_hours": 24})
    rc = main(
        [
            "guard",
            "status",
            "--home",
            str(home_dir),
            "--guard-home",
            str(guard_home),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["protection"] == "watch"
    assert isinstance(payload["watch_reverts_at"], str)
    assert payload["watch_reverts_at"] in _watch_revert_line(payload)
    assert "never on its own" in _watch_revert_line({"protection": "watch", "watch_reverts_at": None})
    assert _watch_revert_line({"protection": "protected", "watch_reverts_at": None}) == ""


def test_watch_restore_command_names_a_non_default_guard_home() -> None:
    from codex_plugin_scanner.guard.cli.render import _watch_revert_line

    default = _watch_revert_line({"protection": "watch", "guard_home": "~/.hol-guard"})
    assert default.endswith("run `hol-guard settings set protection protected`")
    custom = _watch_revert_line({"protection": "watch", "guard_home": "~/guard homes/a'b"})
    assert "--guard-home ~/'guard homes/a'\"'\"'b'`" in custom
    absolute = _watch_revert_line({"protection": "watch", "guard_home": "/srv/guard home"})
    assert "--guard-home '/srv/guard home'`" in absolute


def test_watch_restore_command_prints_bracketed_home_literally() -> None:
    from rich.console import Console

    from codex_plugin_scanner.guard.cli.render import _watch_revert_line

    console = Console(record=True, width=200)
    console.print(_watch_revert_line({"protection": "watch", "guard_home": "/srv/[bold]team"}))
    assert "--guard-home '/srv/[bold]team'" in console.export_text()


def test_watch_stamp_repair_keeps_a_posture_saved_after_the_read(tmp_path: Path, monkeypatch: object) -> None:
    from datetime import datetime, timedelta, timezone

    from codex_plugin_scanner.guard import config as config_module

    guard_home = tmp_path / ".hol-guard"
    update_guard_settings(guard_home, {"protection_posture": "watch", "watch_auto_revert_hours": 24})
    _strip_watch_stamp(guard_home)
    stale = load_guard_config(guard_home)
    assert stale.watch_entered_at is None
    # The user saves Protected after the auto-revert pass read the unstamped Watch.
    update_guard_settings(guard_home, {"protection_posture": "protected"})

    real_load = config_module.load_guard_config
    reads = iter([stale])
    monkeypatch.setattr(  # type: ignore[attr-defined]
        config_module, "load_guard_config", lambda *args, **kwargs: next(reads, None) or real_load(*args, **kwargs)
    )
    result = config_module.maybe_auto_revert_watch(guard_home, now=datetime.now(timezone.utc) + timedelta(minutes=1))
    assert result.protection_posture == "protected"
    assert real_load(guard_home).protection_posture == "protected"
