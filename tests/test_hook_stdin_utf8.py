"""Hook stdin is UTF-8 even when the console code page is not (Windows cp1252)."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import claude_daemon_hook_bridge as bridge
from codex_plugin_scanner.guard.adapters.hook_input_reader import read_stdin_text
from codex_plugin_scanner.guard.cli.commands_support_hook_payload_loader import load_hook_payload
from codex_plugin_scanner.guard.codex_hook_bridge_runtime import bounded_hook_input

_PAYLOAD = {"hook_event_name": "PreToolUse", "tool_input": {"file_path": "C:/Users/zoë/café.txt"}}


def _cp1252_stdin(text: str) -> io.TextIOWrapper:
    return io.TextIOWrapper(io.BytesIO(text.encode("utf-8")), encoding="cp1252")


def test_read_stdin_text_decodes_utf8_under_cp1252_locale(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin", _cp1252_stdin("\ufeff" + json.dumps(_PAYLOAD, ensure_ascii=False)))

    text, oversized = read_stdin_text(4096)

    assert not oversized
    assert json.loads(text) == _PAYLOAD


def test_read_stdin_text_limits_bytes_not_characters(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin", _cp1252_stdin("é" * 3))

    assert read_stdin_text(5)[1]
    monkeypatch.setattr("sys.stdin", _cp1252_stdin("é" * 3))
    assert read_stdin_text(6) == ("ééé", False)


def test_read_stdin_text_accepts_text_only_streams(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("é" * 3))

    assert read_stdin_text(5) == ("ééé", True)


def test_codex_bounded_hook_input_decodes_utf8(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin", _cp1252_stdin(json.dumps(_PAYLOAD, ensure_ascii=False)))

    data = bounded_hook_input(4096)

    assert data is not None
    assert json.loads(data) == _PAYLOAD
    monkeypatch.setattr("sys.stdin", _cp1252_stdin("é" * 3))
    assert bounded_hook_input(5) is None


def test_fallback_hook_payload_loader_decodes_utf8(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin", _cp1252_stdin(json.dumps(_PAYLOAD, ensure_ascii=False)))

    payload = load_hook_payload(None, normalize=False)

    assert payload == _PAYLOAD


def test_claude_bridge_forwards_utf8_paths_unchanged(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    captured: list[str] = []

    def fake_post(endpoint: str, data: str, *, state_path: str | Path, deadline: float | None = None) -> str:
        del endpoint, state_path, deadline
        captured.append(data)
        return json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}})

    monkeypatch.setattr(bridge, "state_path_for_query", lambda state_path, query: state_path)
    monkeypatch.setattr(bridge, "_daemon_url", lambda state_path, fallback: "http://127.0.0.1:5474")
    monkeypatch.setattr(bridge, "_post_to_loopback_daemon", fake_post)
    monkeypatch.setattr("sys.stdin", _cp1252_stdin(json.dumps(_PAYLOAD, ensure_ascii=False)))

    assert (
        bridge.main(
            state_path=tmp_path / "daemon-state.json",
            fallback_daemon_url="http://127.0.0.1:5474",
            fallback_command=(sys.executable, "-c", "print('{}')"),
            query="guard-home=/tmp/guard-home",
        )
        == 0
    )

    assert json.loads(captured[0])["tool_input"]["file_path"] == "C:/Users/zoë/café.txt"
