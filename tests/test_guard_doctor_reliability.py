"""`hol-guard doctor reliability` reports what the daemon's records say, and changes nothing.

The native runtime does the counting; its window, causes, failure codes,
crash-report classes and unsafe-path handling are unit tested in
`rust/crates/guard-runtime/src/daemon_manage_reliability_tests.rs`.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import commands_parser_policy, doctor_reliability
from codex_plugin_scanner.guard.cli.commands_router import run_guard_command
from codex_plugin_scanner.guard.native_daemon_manage import record_daemon_repair

DAY_NS = 86_400 * 1_000_000_000


def _args(tmp_path: Path, **overrides: object) -> argparse.Namespace:
    fields: dict[str, object] = {
        "guard_command": "doctor",
        "harness": "reliability",
        "incident": False,
        "json": True,
        "days": 30,
        "home": str(tmp_path / "home"),
        "guard_home": str(tmp_path / "guard-home"),
        "workspace": None,
        "repair": False,
    }
    fields.update(overrides)
    return argparse.Namespace(**fields)


def _private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)


def _event(guard_home: Path, at_ns: int, pid: int, event: str, reason: str | None = None) -> None:
    record: dict[str, object] = {"event": event, "pid": pid, "recorded_at_ns": at_ns, "version": 1}
    if reason is not None:
        record["reason"] = reason
    suffix = ".recovery.json" if event == "recovery_requested" else ".json"
    _private(guard_home / "daemon-lifecycle" / f"{at_ns:020}-{pid:010}-{pid:016x}{suffix}", json.dumps(record))


def test_the_report_runs_before_the_lifecycle_gate_and_names_its_inputs(tmp_path, monkeypatch) -> None:
    (tmp_path / "home").mkdir()
    asked: list[tuple[Path, dict[str, object]]] = []

    def fake_report(guard_home: Path, **kwargs: object) -> dict[str, object]:
        asked.append((guard_home, kwargs))
        return {"window": {"days": kwargs["days"]}}

    def no_gate(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("the read-only report must not run the lifecycle gate")

    monkeypatch.setattr(doctor_reliability, "daemon_reliability_report", fake_report)
    monkeypatch.setattr("codex_plugin_scanner.guard.cli.commands_router.enforce_lifecycle_gate", no_gate)
    output = io.StringIO()

    assert run_guard_command(_args(tmp_path, days=7), output_stream=output) == 0

    assert json.loads(output.getvalue()) == {"window": {"days": 7}}
    [(guard_home, kwargs)] = asked
    assert guard_home == (tmp_path / "guard-home").resolve()
    assert kwargs["days"] == 7
    assert kwargs["processes"] is True
    expected_crash_dir = (
        (tmp_path / "home").resolve() / "Library" / "Logs" / "DiagnosticReports" if sys.platform == "darwin" else None
    )
    assert kwargs["crash_reports_dir"] == expected_crash_dir


def test_the_text_report_lists_every_section() -> None:
    report = {
        "window": {"days": 30},
        "journal": {"status": "ok", "lifecycle_oldest_ns": 1_794_873_600 * 10**9, "recovery_oldest_ns": None},
        "daemon_exits": {"total": 3, "by_cause": {"exiting:signal_term": 2, "unclean_exit_detected": 1}},
        "ready_per_day": {"2026-11-15": 1, "2026-11-16": 2},
        "repairs": {"total": 1, "per_day": {"2026-11-16": 1}},
        "recovery_requests": {"total": 2, "by_reason": {"transport_failure": 2}},
        "failed_launches": {"status": "no_failures_recorded", "total": 0, "by_code": {}},
        "crash_reports": {"status": "ok", "total": 4, "by_origin": {"temporary": 4}, "by_stack": {"double_panic": 4}},
        "orphaned_daemons": {"status": "known", "published_pid": 9, "pids": [11]},
    }

    assert doctor_reliability.render_reliability_report(report).splitlines() == [
        "Guard daemon reliability, last 30 days",
        "",
        "Daemon exits: 3",
        "  exiting:signal_term  2",
        "  unclean_exit_detected  1",
        "Daemon starts: 3",
        "  2026-11-15  1",
        "  2026-11-16  2",
        "Failed launches: 0 (no failures recorded)",
        "Crash reports: 4",
        "  by origin: temporary 4",
        "  by stack: double_panic 4",
        "Repairs run: 1",
        "Recovery requests: 2",
        "  transport_failure  2",
        "Daemons besides the published one: 11",
        "",
        "Journal: ok; lifecycle records from 2026-11-17, recovery records from none",
    ]


@pytest.mark.parametrize("value", ["0", "-1", "91", "seven"])
def test_a_day_count_outside_one_to_ninety_is_refused(value: str) -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        _ = commands_parser_policy._reliability_days(value)  # pyright: ignore[reportPrivateUsage]


def test_the_day_count_bounds_are_accepted() -> None:
    assert commands_parser_policy._reliability_days("1") == 1  # pyright: ignore[reportPrivateUsage]
    assert commands_parser_policy._reliability_days("90") == 90  # pyright: ignore[reportPrivateUsage]


def test_partial_counts_are_marked_partial() -> None:
    report = {
        "failed_launches": {"status": "log_unreadable", "total": 1, "by_code": {"spawn_failed": 1}},
        "crash_reports": {"status": "scan_limit", "total": 0, "by_origin": {}, "by_stack": {}},
    }

    lines = doctor_reliability.render_reliability_report(report).splitlines()

    assert "Failed launches: 1 (a failure log could not be read safely; counts are partial)" in lines
    assert "Crash reports: 0 (scan_limit, partial)" in lines


def _runtime_binary() -> Path | None:
    configured = os.environ.get("HOL_GUARD_NATIVE_BINARY")
    return Path(configured) if configured and Path(configured).is_file() else None


@pytest.mark.skipif(_runtime_binary() is None, reason="needs the native runtime binary")
def test_the_native_report_counts_a_fixture_home(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
    (tmp_path / "home").mkdir()
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    now = time.time_ns()
    _event(guard_home, now - 40 * DAY_NS, 100, "exiting", "signal_term")
    _event(guard_home, now - 2 * DAY_NS, 101, "ready")
    _event(guard_home, now - 2 * DAY_NS + 1, 101, "exiting", "signal_term")
    _event(guard_home, now - DAY_NS, 102, "ready")
    _event(guard_home, now - DAY_NS + 1, 102, "unclean_exit_detected")
    _event(guard_home, now - 5, 103, "recovery_requested", "transport_failure")
    failure = {"code": "runtime_panic", "kind": "panic", "pid": 7, "recorded_at_ns": now - 10, "version": 1}
    _private(guard_home / "logs" / "runtime-failures.jsonl", json.dumps(failure) + "\n")
    record_daemon_repair(guard_home)

    output = io.StringIO()
    assert run_guard_command(_args(tmp_path), output_stream=output) == 0
    report = json.loads(output.getvalue())

    assert report["schema"] == "hol-guard-daemon-reliability.v1"
    assert report["daemon_exits"] == {
        "total": 2,
        "by_cause": {"exiting:signal_term": 1, "unclean_exit_detected": 1},
    }
    assert sum(report["ready_per_day"].values()) == 2
    assert report["repairs"]["total"] == 1
    assert report["recovery_requests"] == {"total": 1, "by_reason": {"transport_failure": 1}}
    assert report["failed_launches"]["by_code"] == {"runtime_panic": 1}
    assert report["orphaned_daemons"]["status"] in {"known", "unknown"}
    # The report itself writes nothing: the journal holds the fixture and the one repair.
    assert len(list((guard_home / "daemon-lifecycle").iterdir())) == 7
