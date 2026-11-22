"""The detector debug trace is written by the native runtime; Python only reports its answer."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

import pytest

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError
from codex_plugin_scanner.guard.runtime import guard_run_evaluation
from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope
from codex_plugin_scanner.guard.runtime.detectors import DetectorRunResult, DetectorTelemetry


class _Envelope:
    def to_dict(self) -> dict[str, object]:
        return {"tool_name": "Bash", "prompt_excerpt": "kept out"}


_RESULT = DetectorRunResult(
    signals=(),
    telemetry=(DetectorTelemetry("secret.local", ("secret",), "ok", 3),),
)


def _write(tmp_path: Path) -> dict[str, object] | None:
    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=tmp_path)
    return guard_run_evaluation._write_detector_debug_trace(
        config,
        cast(GuardActionEnvelope, cast(object, _Envelope())),
        _RESULT,
    )


def _answer(monkeypatch: pytest.MonkeyPatch, answer: object, seen: list[tuple[str, Mapping[str, Any]]]) -> None:
    def native(kind: str, args: Mapping[str, Any], **_kwargs: object) -> object:
        seen.append((kind, args))
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(guard_run_evaluation, "native_runner_authority", native)


def test_the_trace_inputs_go_to_the_native_writer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple[str, Mapping[str, Any]]] = []
    _answer(monkeypatch, {"trace_error": None}, seen)

    assert _write(tmp_path) is None
    kind, args = seen[0]
    assert kind == "detector_debug_trace"
    assert "guard_home" not in args
    assert args["action"] == {"tool_name": "Bash", "prompt_excerpt": "[redacted]"}
    assert args["signals"] == []
    assert args["telemetry"] == [_RESULT.telemetry[0].to_dict()]


def test_the_served_home_is_the_one_the_resident_checks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    homes: list[object] = []

    def native(_kind: str, _args: Mapping[str, Any], **kwargs: object) -> object:
        homes.append(kwargs.get("guard_home"))
        return {"trace_error": None}

    monkeypatch.setattr(guard_run_evaluation, "native_runner_authority", native)

    assert _write(tmp_path) is None
    assert [Path(str(home)).resolve() for home in homes] == [(tmp_path / "guard-home").resolve()]


def test_a_reported_write_failure_is_returned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    failure = {"error_type": "FileExistsError", "message": "exists"}
    _answer(monkeypatch, {"trace_error": failure}, [])

    assert _write(tmp_path) == failure


def test_an_unavailable_runtime_is_reported_not_raised(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _answer(monkeypatch, NativeRunnerAuthorityError("native_runner_authority_unavailable"), [])

    assert _write(tmp_path) == {
        "error_type": "NativeRunnerAuthorityError",
        "message": "native_runner_authority_unavailable",
    }


@pytest.mark.parametrize(
    "answer",
    [
        {},
        {"trace_error": None, "extra": 1},
        {"trace_error": "bad"},
        {"trace_error": {"error_type": "OSError"}},
        {"trace_error": {"error_type": "OSError", "message": 7}},
        {"trace_error": {"error_type": "OSError", "message": "m", "extra": "x"}},
    ],
)
def test_a_malformed_answer_is_reported_as_no_answer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: dict[str, object]
) -> None:
    _answer(monkeypatch, answer, [])

    assert _write(tmp_path) == {
        "error_type": "NativeRunnerAuthorityError",
        "message": "native detector_debug_trace returned no answer",
    }
