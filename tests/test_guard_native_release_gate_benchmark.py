from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from typing import Any, ClassVar

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench_guard_native_release_gate.py"
SPEC = importlib.util.spec_from_file_location("bench_guard_native_release_gate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)


class _RecordingRunner:
    modes: ClassVar[list[str | None]] = []

    def __init__(self, **_kwargs: Any) -> None:
        self.modes.append(os.environ.get("HOL_GUARD_NATIVE"))

    def start(self) -> None:
        self.modes.append(os.environ.get("HOL_GUARD_NATIVE"))

    def close(self) -> None:
        pass


@pytest.fixture(autouse=True)
def _reset_recorded_modes() -> None:
    _RecordingRunner.modes.clear()


def test_python_warm_reference_spawns_and_reviews_with_native_disabled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    review_modes: list[str | None] = []
    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
    monkeypatch.setattr(benchmark, "HookProcessRunner", _RecordingRunner)
    monkeypatch.setattr(
        benchmark,
        "_python_review",
        lambda *_args, **_kwargs: review_modes.append(os.environ.get("HOL_GUARD_NATIVE")),
    )

    values = benchmark._bench_python_warm_reference(
        workspace=tmp_path,
        guard_home=tmp_path / "guard-home",
        iterations=2,
    )

    assert len(values) == 2
    assert _RecordingRunner.modes == ["off", "off"]
    assert review_modes == ["off", "off", "off"]
    assert os.environ["HOL_GUARD_NATIVE"] == "force"


def test_python_cold_spawns_and_reviews_with_native_disabled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    review_modes: list[str | None] = []
    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
    monkeypatch.setattr(benchmark, "HookProcessRunner", _RecordingRunner)
    monkeypatch.setattr(
        benchmark,
        "_python_review",
        lambda *_args, **_kwargs: review_modes.append(os.environ.get("HOL_GUARD_NATIVE")),
    )

    values = benchmark._bench_python_cold(
        workspace=tmp_path,
        guard_home=tmp_path / "guard-home",
        iterations=2,
    )

    assert len(values) == 2
    assert _RecordingRunner.modes == ["off", "off", "off", "off"]
    assert review_modes == ["off", "off"]
    assert os.environ["HOL_GUARD_NATIVE"] == "force"
