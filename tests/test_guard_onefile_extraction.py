"""The onefile extraction reclaim shim over the native runtime."""

from __future__ import annotations

import threading
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import onefile_extraction
from codex_plugin_scanner.guard.mdm import runtime_request
from codex_plugin_scanner.guard.onefile_extraction import (
    ExtractionReclaimResult,
    ExtractionReclaimUnavailableError,
    reclaim_orphaned_extraction_dirs,
)

_NOW = datetime(2026, 2, 1, tzinfo=timezone.utc)

_Call = tuple[str, str, Mapping[str, object], dict[str, object]]

_ANSWER: dict[str, object] = {
    "reclaimed_count": 3,
    "reclaimed_bytes": 300,
    "killed_launches": 1,
    "unmarked_count": 4,
    "unmarked_bytes_estimate": 400,
    "unmarked_reclaimed_count": 2,
    "unmarked_reclaimed_bytes": 200,
    "partial_reclaimed_count": 1,
    "unmarked_scan": "ok",
    "unmarked_budget_exhausted": True,
    "errors": ["rmtree:PermissionError"],
}


def _answer(monkeypatch: pytest.MonkeyPatch, answer: dict[str, object] | None) -> list[_Call]:
    calls: list[_Call] = []

    def fake(feature: str, command: str, request: Mapping[str, object], **kwargs: object) -> dict[str, object] | None:
        calls.append((feature, command, request, kwargs))
        return answer

    monkeypatch.setattr(runtime_request, "runtime_answer", fake)
    return calls


def test_reclaim_asks_the_native_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _answer(monkeypatch, _ANSWER)

    result = reclaim_orphaned_extraction_dirs(
        temp_root=tmp_path,
        current_meipass="/tmp/_MEIcurrent",
        now=_NOW,
        scan_open_paths=True,
        unmarked_time_budget=timedelta(minutes=3),
        max_unmarked_reclaims=5000,
        dry_run=True,
    )

    assert result == ExtractionReclaimResult(
        reclaimed_count=3,
        reclaimed_bytes=300,
        killed_launches=1,
        unmarked_count=4,
        unmarked_bytes_estimate=400,
        unmarked_reclaimed_count=2,
        unmarked_reclaimed_bytes=200,
        partial_reclaimed_count=1,
        unmarked_scan="ok",
        unmarked_budget_exhausted=True,
        errors=["rmtree:PermissionError"],
    )
    [(feature, command, request, kwargs)] = calls
    assert (feature, command) == ("native-onefile-extraction-reclaim-v1", "onefile-extraction-reclaim")
    assert request == {
        "schema": "onefile-extraction-reclaim.v1",
        "temp_root": str(tmp_path),
        "current_meipass": "/tmp/_MEIcurrent",
        "now": _NOW.timestamp(),
        "min_age_seconds": 600.0,
        "unmarked_min_age_seconds": 7200.0,
        "max_unmarked_reclaims": 5000,
        "unmarked_time_budget_seconds": 180.0,
        "scan_open_paths": True,
        "dry_run": True,
    }
    # Long enough for the lsof scan plus the whole unmarked budget.
    timeout = kwargs["timeout_seconds"]
    assert isinstance(timeout, float) and timeout > 90.0 + 180.0


def test_an_unbounded_sweep_still_has_a_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _answer(monkeypatch, _ANSWER)

    _ = reclaim_orphaned_extraction_dirs(
        temp_root=tmp_path,
        current_meipass=None,
        now=_NOW,
        unmarked_time_budget=None,
    )

    [(_feature, _command, request, kwargs)] = calls
    assert request["unmarked_time_budget_seconds"] is None
    assert request["scan_open_paths"] is False
    assert isinstance(kwargs["timeout_seconds"], float)


@pytest.mark.parametrize(
    "answer",
    [
        None,
        {**_ANSWER, "reclaimed_count": -1},
        {**_ANSWER, "reclaimed_bytes": True},
        {**_ANSWER, "unmarked_scan": "maybe"},
        {**_ANSWER, "unmarked_budget_exhausted": 1},
        {**_ANSWER, "errors": [1]},
        {key: value for key, value in _ANSWER.items() if key != "killed_launches"},
    ],
)
def test_reclaim_fails_without_a_clean_answer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: dict[str, object] | None
) -> None:
    _ = _answer(monkeypatch, answer)

    with pytest.raises(ExtractionReclaimUnavailableError):
        _ = reclaim_orphaned_extraction_dirs(temp_root=tmp_path, current_meipass=None, now=_NOW)


def test_marker_constants_are_the_launch_contract() -> None:
    assert onefile_extraction.OWNER_MARKER_NAME == ".hol-guard-extraction-owner.json"
    assert onefile_extraction._OWNER_MARKER_SCHEMA == "guard.onefile-extraction-owner.v1"  # pyright: ignore[reportPrivateUsage]


def test_a_stop_event_reaches_the_runtime_request(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _answer(monkeypatch, _ANSWER)
    stop = threading.Event()

    reclaim_orphaned_extraction_dirs(temp_root=tmp_path, current_meipass=None, now=_NOW, stop_event=stop)

    assert calls[0][3]["stop_event"] is stop


def test_runtime_answer_hands_the_stop_event_to_the_native_process(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import native_runtime

    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=Path("/opt/guard/hol-guard-runtime")),
        capabilities=SimpleNamespace(features=("native-test-v1",)),
    )
    seen: list[object] = []

    def run(path: Path, args: tuple[str, ...], **kwargs: object) -> str | None:
        seen.append(kwargs.get("stop_event"))
        return None

    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda **_kwargs: status)
    monkeypatch.setattr(native_runtime, "_run_native_process", run)
    stop = threading.Event()

    assert runtime_request.runtime_answer("native-test-v1", "test", "{}", output_limit=64, timeout_seconds=1.0) is None
    assert (
        runtime_request.runtime_answer(
            "native-test-v1", "test", "{}", output_limit=64, timeout_seconds=1.0, stop_event=stop
        )
        is None
    )
    assert seen == [None, stop]
