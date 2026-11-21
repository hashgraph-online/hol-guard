from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_runner_authority as authority


def _run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, argv: list[str]) -> int:
    from codex_plugin_scanner import cli, install_integrity

    monkeypatch.setattr(sys, "argv", ["hol-guard"])
    monkeypatch.setattr(install_integrity, "warn_if_shadowed", lambda: None)
    return cli.main(["context", "lean", "--guard-home", str(tmp_path), *argv])


def test_lean_on_passes_the_size_and_an_absolute_codex_home_and_prints_the_text(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[tuple[str, dict[str, Any]]] = []

    def fake(kind: str, args: dict[str, Any], guard_home: Path | None = None, **_: Any) -> dict[str, Any]:
        calls.append((kind, dict(args)))
        return {"ok": True, "state": {"state": "on", "limit": 100000}, "text": "Guard set Codex.\n"}

    monkeypatch.setattr(authority, "native_runner_authority", fake)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CODEX_HOME", "codex")
    assert _run(monkeypatch, tmp_path, ["on", "--limit", "100000"]) == 0
    assert capsys.readouterr().out == "Guard set Codex.\n"
    kind, args = calls[0]
    assert kind == "codex_config"
    assert args["switch"] == "lean" and args["action"] == "enable" and args["limit"] == 100000
    assert args["codex_home"] == str(tmp_path / "codex") and args["text"] is True


def test_lean_failures_keep_the_json_error_shape(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    answer = {"ok": False, "code": "codex_lean_limit_required", "text": None}
    monkeypatch.setattr(authority, "native_runner_authority", lambda *_a, **_k: answer)
    monkeypatch.delenv("CODEX_HOME", raising=False)
    assert _run(monkeypatch, tmp_path, ["on", "--json"]) == 1
    assert json.loads(capsys.readouterr().out) == {
        "schema": "guard-codex-lean-sessions.v1",
        "status": "error",
        "code": "codex_lean_limit_required",
    }

    def broken(*_a: Any, **_k: Any) -> dict[str, Any]:
        raise authority.NativeRunnerAuthorityError("runtime_unavailable")

    monkeypatch.setattr(authority, "native_runner_authority", broken)
    assert _run(monkeypatch, tmp_path, ["off"]) == 1
    assert "codex_config_unavailable" in capsys.readouterr().out
