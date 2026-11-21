from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_runner_authority as authority
from codex_plugin_scanner.guard.cli import context_usage_commands as usage


def _ready(text: str | None) -> dict[str, Any]:
    state = {"schema": usage.SCHEMA, "state": "ready", "window_days": 7, "today": [], "week": [], "unread": []}
    return {"usage": state, "savings": {"total": {"sessions": 0}}, "text": text}


def _run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, argv: list[str]) -> int:
    from codex_plugin_scanner import cli, install_integrity

    monkeypatch.setattr(sys, "argv", ["hol-guard"])
    monkeypatch.setattr(install_integrity, "warn_if_shadowed", lambda: None)
    return cli.main(["context", "usage", "--guard-home", str(tmp_path), *argv])


def test_the_cli_asks_the_service_again_while_it_counts_then_prints_its_text(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[tuple[str, dict[str, Any]]] = []
    answers = [{"usage": {"state": "counting"}, "savings": None, "text": None}, _ready("Codex: 1 session\n")]

    def fake(kind: str, args: dict[str, Any], guard_home: Path | None = None, **_: Any) -> dict[str, Any]:
        calls.append((kind, dict(args)))
        return answers.pop(0)

    monkeypatch.setattr(authority, "native_runner_authority", fake)
    monkeypatch.setattr(usage, "POLL_SECONDS", 0)
    monkeypatch.setenv("CODEX_HOME", "/elsewhere/codex")
    assert _run(monkeypatch, tmp_path, []) == 0
    captured = capsys.readouterr()
    assert captured.out == "Codex: 1 session\n"
    assert "Counting." in captured.err
    assert [kind for kind, _ in calls] == ["context_usage", "context_usage"]
    assert calls[0][1]["op"] == "read"
    assert calls[0][1]["text"] is True
    assert calls[0][1]["codex_home"] == "/elsewhere/codex"
    assert Path(calls[0][1]["home_dir"]).is_absolute()


def test_the_cli_json_carries_the_savings_and_a_failure_says_unavailable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(authority, "native_runner_authority", lambda *_a, **_k: _ready(None))
    assert _run(monkeypatch, tmp_path, ["--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["state"] == "ready"
    assert data["savings"] == {"total": {"sessions": 0}}

    def refuse(*_a: Any, **_k: Any) -> dict[str, Any]:
        raise authority.NativeRunnerAuthorityError("native_runner_authority_unavailable")

    monkeypatch.setattr(authority, "native_runner_authority", refuse)
    assert _run(monkeypatch, tmp_path, ["--json"]) == 1
    assert json.loads(capsys.readouterr().out) == {"schema": usage.SCHEMA, "state": "unavailable"}
    assert _run(monkeypatch, tmp_path, []) == 1
    assert capsys.readouterr().out == "Guard could not read the usage records on this computer.\n"
