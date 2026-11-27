"""The uninstall glue that asks the native runtime to forget every provider integration."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import provider_integration_uninstall as purge

RUNTIME = Path("fixture-runtime")


@pytest.fixture(autouse=True)
def _fixture_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(purge, "resident_stop_executable", lambda: RUNTIME)


def _answer(monkeypatch: pytest.MonkeyPatch, calls: list[list[str]], code: int, stdout: str) -> None:
    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        assert kwargs.get("timeout"), "the purge never waits forever"
        return subprocess.CompletedProcess(command, code, stdout=stdout, stderr="")

    monkeypatch.setattr(purge.subprocess, "run", fake_run)


def test_the_runtime_forgets_every_provider_under_the_guard_home(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[list[str]] = []
    _answer(monkeypatch, calls, 0, '{"keys_deleted":2,"providers_forgotten":2}')

    assert purge.forget_provider_integrations(tmp_path) == {"keys_deleted": 2, "providers_forgotten": 2}
    assert calls == [[str(RUNTIME), "forget-provider-integrations", "--guard-home", str(tmp_path)]]


@pytest.mark.parametrize(("code", "stdout"), [(2, ""), (0, "not json"), (0, "[]")])
def test_a_purge_that_did_not_finish_is_reported(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, code: int, stdout: str
) -> None:
    _answer(monkeypatch, [], code, stdout)
    assert purge.forget_provider_integrations(tmp_path) is None


def test_a_missing_runtime_is_reported(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def missing(*_args: object, **_kwargs: object) -> None:
        raise FileNotFoundError("runtime")

    monkeypatch.setattr(purge.subprocess, "run", missing)
    assert purge.forget_provider_integrations(tmp_path) is None


def test_a_missing_guard_home_has_nothing_to_forget(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[list[str]] = []
    _answer(monkeypatch, calls, 0, "{}")
    assert purge.forget_provider_integrations(tmp_path / "absent") == {"keys_deleted": 0, "providers_forgotten": 0}
    assert calls == []
