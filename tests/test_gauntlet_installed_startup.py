"""The installed-acceptance lane records when the daemon came up, never who it was."""

from __future__ import annotations

import json
from pathlib import Path

from ci.gauntlet.installed_startup import LIFECYCLE_DIRECTORY, startup_timeline


def _event(directory: Path, name: str, payload: object) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text(json.dumps(payload), encoding="utf-8")


def test_the_timeline_is_offsets_from_install_and_names_when_the_daemon_was_ready(tmp_path: Path) -> None:
    journal = tmp_path / LIFECYCLE_DIRECTORY
    since = 1_000_000_000
    _event(journal, "b.json", {"event": "ready", "recorded_at_ns": since + 12_345_600_000, "pid": 41, "port": 9})
    _event(journal, "a.json", {"event": "spawn", "reason": "ensure", "recorded_at_ns": since + 200_000_000})
    _event(journal, "c.json", {"event": "ready", "recorded_at_ns": since + 20_000_000_000, "session_id": "s"})
    timeline = startup_timeline(tmp_path, since_ns=since)
    assert timeline["ready_ms"] == 12345.6
    assert timeline["events"] == [
        {"event": "spawn", "ms_after_install": 200.0, "reason": "ensure"},
        {"event": "ready", "ms_after_install": 12345.6},
        {"event": "ready", "ms_after_install": 20000.0},
    ]
    assert "41" not in json.dumps(timeline)


def test_a_daemon_that_never_came_up_has_no_ready_offset(tmp_path: Path) -> None:
    assert startup_timeline(tmp_path, since_ns=0) == {"events": [], "ready_ms": None}


def test_a_ready_left_by_an_earlier_run_in_a_reused_home_is_not_this_runs_ready(tmp_path: Path) -> None:
    journal = tmp_path / LIFECYCLE_DIRECTORY
    started = 100_000_000_000
    installed = started + 3_000_000_000
    _event(journal, "a.json", {"event": "ready", "recorded_at_ns": started - 60_000_000_000})
    _event(journal, "b.json", {"event": "ready", "recorded_at_ns": installed - 1_000_000_000})
    timeline = startup_timeline(tmp_path, since_ns=installed, not_before_ns=started)
    # The current daemon may be ready before install returns, so that offset stays negative.
    assert timeline["ready_ms"] == -1000.0
    assert timeline["events"] == [{"event": "ready", "ms_after_install": -1000.0}]


def test_unreadable_and_oversized_journal_files_are_skipped(tmp_path: Path) -> None:
    journal = tmp_path / LIFECYCLE_DIRECTORY
    _event(journal, "a.json", ["not", "an", "event"])
    _event(journal, "b.json", {"event": "ready", "recorded_at_ns": "late"})
    _event(journal, "c.json", {"event": "ready", "recorded_at_ns": 5, "pad": "x" * 4096})
    (journal / "d.json").write_text("{", encoding="utf-8")
    assert startup_timeline(tmp_path, since_ns=0) == {"events": [], "ready_ms": None}


def test_the_lane_records_the_prewarm_probe_before_any_harness_pass(tmp_path: Path, monkeypatch) -> None:
    from ci.gauntlet import installed_lane

    calls: list[str] = []

    def probe(runtime, harness, *, root):
        calls.append(f"probe:{harness}")
        return {"events": [], "ready_ms": None, "harness": harness}

    def harness_pass(runtime, harness, expectation, contract, *, root, repeat):
        calls.append(f"pass:{harness}")
        return {"failures": [], "passed": True}

    monkeypatch.setattr(installed_lane, "prewarm_probe", probe)
    monkeypatch.setattr(installed_lane, "harness_pass", harness_pass)
    monkeypatch.setattr(installed_lane, "resolve_runtime", lambda path, require_frozen: _Runtime())
    evidence = installed_lane.run_lane(
        runtime_path=tmp_path / "hol-guard",
        harnesses=["claude-code", "codex"],
        repeat=1,
        require_frozen=False,
        aged_store=False,
        output=tmp_path / "evidence",
        work_root=tmp_path / "work",
    )
    assert calls == ["probe:claude-code", "pass:claude-code", "pass:codex"]
    assert evidence["prewarm_probe"]["harness"] == "claude-code"


class _Runtime:
    def as_evidence(self) -> dict[str, str]:
        return {"kind": "stub"}


def test_each_harness_pass_stops_its_daemon_before_the_next_cold_start(tmp_path: Path, monkeypatch) -> None:
    from ci.gauntlet import installed_lane

    calls: list[str] = []

    def install(runtime, harness, *, home, guard_home, workspace):
        calls.append(f"install:{harness}")
        return {"harness": harness, "exit_code": 0, "payload": {}, "stderr_tail": ""}

    def stop(runtime, *, home, guard_home, timeout=60.0):
        calls.append(f"stop:{home.name}")
        return 0

    monkeypatch.setattr(installed_lane, "install_harness", install)
    monkeypatch.setattr(installed_lane, "stop_daemon", stop)
    monkeypatch.setattr(installed_lane, "assess_harness", lambda home, harness, expectation: {"failures": []})
    homes = []
    for harness in ("claude-code", "codex"):
        result = installed_lane.harness_pass(_Runtime(), harness, {"replay": False}, {}, root=tmp_path, repeat=1)
        assert result["startup"]["daemon_stop_exit_code"] == 0
        homes.append(installed_lane.build_home(tmp_path, f"home-{harness}").name)
    assert calls == [
        "install:claude-code",
        f"stop:{homes[0]}",
        "install:codex",
        f"stop:{homes[1]}",
    ]
