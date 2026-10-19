"""A resident refusal from `guard protect` is a structured denial, not a traceback."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.cli.commands_support as _commands_support
from codex_plugin_scanner.guard.cli.commands_dispatch_local import _run_guard_protect_command
from codex_plugin_scanner.guard.native_protect_request import NativeProtectRequestError

assert _commands_support._sync_namespace


class _Store:
    def __init__(self, home: Path) -> None:
        self.guard_home = home
        self.path = home / "guard.db"

    def get_cloud_sync_profile(self) -> None:
        return None


def test_protect_command_fails_closed_when_the_resident_refuses(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*_args: object, **_kwargs: object) -> None:
        raise NativeProtectRequestError("native_protect_request_unavailable")

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.protect.native_protect_request",
        refuse,
    )
    exit_code = _run_guard_protect_command(
        argparse.Namespace(protect_command=["npm", "install", "lodash"], json=True),
        guard_home=tmp_path,
        store=_Store(tmp_path),
        config=argparse.Namespace(mode="enforce"),
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    payload = json.loads(captured.out)
    assert payload["policy_action"] == "block"
    assert payload["verdict"]["action"] == "block"
    assert payload["verdict"]["blocking"] is True
    assert payload["error"]["code"]
    assert "Traceback" not in captured.err


def test_a_relative_workspace_reaches_the_resident_as_an_absolute_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import codex_plugin_scanner.guard.native_protect_request as module

    sent: list[dict[str, object]] = []

    def capture(**kwargs: object) -> None:
        sent.append(kwargs["request"])  # type: ignore[arg-type]
        return None

    monkeypatch.setattr(module, "_resolve_digest_home", lambda _home: tmp_path)
    monkeypatch.setattr(module, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(module.native_execution, "_resident_request", capture)
    monkeypatch.chdir(tmp_path)
    with pytest.raises(NativeProtectRequestError):
        module.native_protect_request(["bun", "tool.ts"], guard_home=None, store_path=None, cwd=Path("work"))
    # The resident reads a relative script only against an absolute directory.
    assert sent[0]["cwd"] == str(tmp_path / "work")
