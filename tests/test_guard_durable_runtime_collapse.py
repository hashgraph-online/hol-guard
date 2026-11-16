from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import durable_runtime_collapse as collapse
from codex_plugin_scanner.guard import repair_engine
from codex_plugin_scanner.guard.repair_engine import repair_native_runtime

_DIGEST = "a" * 64


def _report(**overrides: object) -> dict[str, object]:
    report: dict[str, object] = {
        "outcome": "ok",
        "collapsed": 2,
        "reclaimed_bytes": 4096,
        "kept": {"too_recent": 1},
        "budget_exhausted": False,
        "errors": [],
    }
    report.update(overrides)
    return report


@pytest.fixture
def answers(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str, object]]:
    from codex_plugin_scanner.guard.mdm import runtime_request

    calls: list[tuple[str, str, object]] = []
    monkeypatch.setattr(collapse, "_current_digest", lambda: _DIGEST)
    monkeypatch.setattr(runtime_request, "runtime_offers", lambda _feature, **_options: False)
    monkeypatch.setattr(
        runtime_request,
        "runtime_answer",
        lambda feature, command, request, **_options: calls.append((feature, command, request)) or _report(),
    )
    return calls


def test_the_request_names_the_home_and_the_pinned_digest(
    tmp_path: Path, answers: list[tuple[str, str, object]]
) -> None:
    assert collapse.collapse_durable_runtimes(tmp_path) == _report()
    assert answers == [
        (
            "native-durable-runtime-collapse-v1",
            "durable-runtime-collapse",
            {"schema": "durable-runtime-collapse.v1", "guard_home": str(tmp_path), "current_digest": _DIGEST},
        )
    ]


def test_a_source_install_asks_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.mdm import runtime_request

    def unexpected(*_args: object, **_options: object) -> None:
        raise AssertionError("a source install pins no durable copy")

    monkeypatch.setattr(runtime_request, "runtime_answer", unexpected)
    assert collapse.collapse_durable_runtimes(tmp_path) is None


@pytest.mark.parametrize(
    "answer",
    [
        _report(outcome="done"),
        _report(collapsed=-1),
        _report(reclaimed_bytes=True),
        _report(errors=[1]),
        _report(kept={"too_recent": "1"}),
        _report(budget_exhausted=None),
    ],
)
def test_a_malformed_report_is_dropped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: object) -> None:
    from codex_plugin_scanner.guard.mdm import runtime_request

    monkeypatch.setattr(collapse, "_current_digest", lambda: _DIGEST)
    monkeypatch.setattr(runtime_request, "runtime_answer", lambda *_args, **_options: answer)
    assert collapse.collapse_durable_runtimes(tmp_path) is None


def test_a_collapse_rides_on_the_runtime_step(tmp_path: Path, answers: list[tuple[str, str, object]]) -> None:
    result = repair_engine._native_runtime_result(tmp_path, dry_run=False)

    assert result["durable_runtimes"] == _report()


def test_a_failed_collapse_leaves_the_step_alone(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(_guard_home: Path) -> None:
        raise OSError("runtime vanished")

    monkeypatch.setattr(collapse, "collapse_durable_runtimes", broken)

    assert "durable_runtimes" not in repair_engine._native_runtime_result(tmp_path, dry_run=False)


def test_a_dry_run_repair_never_relinks(tmp_path: Path, answers: list[tuple[str, str, object]]) -> None:
    _ = repair_native_runtime(tmp_path, dry_run=True)

    assert all(feature != "native-durable-runtime-collapse-v1" for feature, _command, _request in answers)
