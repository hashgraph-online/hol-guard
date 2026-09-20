"""Launcher boundaries preserve original workload results and failure evidence."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

from scripts import native_slo_rust_phase_run as launch
from tests.native_slo_rust_phase_test_support import sample_frame


class LauncherControl:
    def __init__(self, monkeypatch: pytest.MonkeyPatch, mode: str = "complete") -> None:
        self.events: list[object] = []
        self.mode = mode
        self.workload = {"original": ["retained", "semantic", "result"]}
        self.environment = {
            "HOL_GUARD_NATIVE_PHASE_SOCKET": "controlled owned endpoint",
            "HOL_GUARD_NATIVE_PHASE_DEVICE": "1",
            "HOL_GUARD_NATIVE_PHASE_INODE": "2",
        }
        owner = self

        class Receiver:
            def __init__(self, runtime: Path) -> None:
                owner.events.append(("receiver", runtime))
                if owner.mode == "receiver_start":
                    raise OSError("private diagnostic detail must not be exported")

            def environment(self) -> dict[str, str]:
                return owner.environment

            def attach(self, pid: int) -> None:
                owner.events.append(("attach", pid))
                if owner.mode == "attach":
                    raise OSError("private process detail must not be exported")

            def close(self) -> None:
                owner.events.append("receiver_close")
                if owner.mode == "receiver_close":
                    raise OSError("private close detail must not be exported")

            def report(self) -> dict[str, Any]:
                owner.events.append("receiver_report")
                snapshot = sample_frame()["snapshot"]
                if owner.mode == "complete":
                    for phase in snapshot["phases"]:
                        phase["statistics"] = copy.deepcopy(snapshot["phases"][0]["statistics"])
                return {"processes": [{"role": "persistent_client", "snapshot": snapshot}]}

        class Fixture:
            pid = 271

            def __init__(self, runtime: Path, *, setup: str, _native_phase_environment: dict[str, str]) -> None:
                owner.events.append(("fixture", runtime, setup))
                assert _native_phase_environment is owner.environment

            def __enter__(self) -> Fixture:
                owner.events.append("fixture_enter")
                if owner.mode == "fixture_start":
                    raise RuntimeError("private fixture detail must not be exported")
                return self

            def __exit__(self, *args: object) -> None:
                owner.events.append("fixture_exit")
                if owner.mode == "fixture_close":
                    raise RuntimeError("private shutdown detail must not be exported")

        def measure(session: Fixture, count: int, evidence_file: Path) -> dict[str, list[str]]:
            owner.events.append(("measure", session.pid, count, evidence_file))
            if owner.mode == "workload":
                evidence_file.write_text("original fixed failure record\n", encoding="utf-8")
                raise RuntimeError("private workload detail must not be exported")
            return owner.workload

        monkeypatch.setattr(launch, "supported", lambda: True)
        monkeypatch.setattr(launch, "NativePhaseReceiver", Receiver)
        monkeypatch.setattr(launch, "DaemonFixture", Fixture)
        monkeypatch.setattr(launch, "measure_installed_phases", measure)


def test_native_launcher_returns_the_original_workload_object_with_incomplete_scope(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    control = LauncherControl(monkeypatch)
    runtime, evidence = tmp_path / "runtime", tmp_path / "evidence.jsonl"
    report = launch.measure_native_phases(runtime, 3, evidence)
    assert report["original_semantic_workload"] is control.workload
    assert report["status"] == "diagnostic_phases_observed"
    assert report["workload_passed"] is True
    assert report["complete_run"] is report["qualification_complete"] is report["headline_timing_eligible"] is False
    assert control.events == [
        ("receiver", runtime),
        ("fixture", runtime, "normal"),
        "fixture_enter",
        ("attach", 271),
        ("measure", 271, 3, evidence),
        "fixture_exit",
        "receiver_close",
        "receiver_report",
    ]


def test_native_launcher_unsupported_platform_does_not_start_the_original_fixture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    control = LauncherControl(monkeypatch)
    monkeypatch.setattr(launch, "supported", lambda: False)
    report = launch.measure_native_phases(tmp_path / "runtime", 1, tmp_path / "journal")
    assert report["status"] == "platform_unsupported" and report["native"] is None
    assert report["workload_started"] is False and not control.events


@pytest.mark.parametrize("mode", ["receiver_start", "attach", "fixture_start"])
def test_native_launcher_setup_failure_does_not_run_or_claim_a_semantic_workload(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mode: str,
) -> None:
    control = LauncherControl(monkeypatch, mode)
    report = launch.measure_native_phases(tmp_path / "runtime", 1, tmp_path / "journal")
    assert report["workload_started"] is report["workload_passed"] is False
    assert report["original_semantic_workload"] is None
    assert not any(isinstance(event, tuple) and event[0] == "measure" for event in control.events)
    assert "private" not in repr(report)
    if mode != "receiver_start":
        assert control.events.count("receiver_close") == 1
    if mode == "attach":
        assert control.events.index("fixture_exit") < control.events.index("receiver_close")


def test_native_launcher_retains_original_failure_journal_and_closes_the_fixture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    control = LauncherControl(monkeypatch, "workload")
    evidence = tmp_path / "journal"
    report = launch.measure_native_phases(tmp_path / "runtime", 1, evidence)
    assert report["status"] == "workload_failed"
    assert report["workload_failure_observed"] is True and report["workload_passed"] is False
    assert evidence.read_text(encoding="utf-8") == "original fixed failure record\n"
    assert "fixture_exit" in control.events and "receiver_close" in control.events
    assert "private" not in repr(report)


@pytest.mark.parametrize("mode", ["receiver_close", "fixture_close", "missing_tail"])
def test_native_launcher_diagnostic_or_shutdown_failure_preserves_the_original_result(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mode: str,
) -> None:
    control = LauncherControl(monkeypatch, mode)
    report = launch.measure_native_phases(tmp_path / "runtime", 1, tmp_path / "journal")
    assert report["original_semantic_workload"] is control.workload and report["workload_passed"] is True
    assert report["status"] == ("existing_fixture_failed" if mode == "fixture_close" else "diagnostic_incomplete")
    assert report["complete_run"] is report["qualification_complete"] is False
    assert control.events.count("receiver_close") == 1
    assert "private" not in repr(report)


@pytest.mark.parametrize("count", [True, False, 0, 101, -1, 1.0])
def test_native_launcher_rejects_invalid_count_before_fixture_or_filesystem_work(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    count: object,
) -> None:
    control = LauncherControl(monkeypatch)
    with pytest.raises(ValueError, match="native_phase_count_outside_original_bound"):
        launch.measure_native_phases(tmp_path / "runtime", count, tmp_path / "journal")  # type: ignore[arg-type]
    assert not control.events and not (tmp_path / "journal").exists()
