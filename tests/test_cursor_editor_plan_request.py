"""The Cursor editor install's native plan request, how its answer is applied, and the answers it refuses."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from codex_plugin_scanner.guard import native_runner_authority as authority
from codex_plugin_scanner.guard.adapters import cursor
from codex_plugin_scanner.guard.adapters.base import HarnessContext

_NOTES = ["first note", "second note"]


def _fake(monkeypatch: pytest.MonkeyPatch, answer: dict[str, object]) -> list[tuple[str, dict[str, object]]]:
    sent: list[tuple[str, dict[str, object]]] = []

    def fake_native(kind: str, request: dict[str, object]) -> dict[str, object]:
        sent.append((kind, request))
        return answer

    monkeypatch.setattr(authority, "native_runner_authority", fake_native)
    return sent


def _server(name: str, scope: str, path: str) -> Any:
    return SimpleNamespace(name=name, source_scope=scope, config_path=path)


def _context(root: Path, *, workspace: bool = False) -> HarnessContext:
    workspace_dir = None
    if workspace:
        workspace_dir = root / "workspace"
        workspace_dir.mkdir()
    return HarnessContext(home_dir=root / "home", workspace_dir=workspace_dir, guard_home=root / "guard")


def _detected(monkeypatch: pytest.MonkeyPatch, observed: tuple[Any, ...], managed: tuple[Any, ...]) -> None:
    monkeypatch.setattr(cursor, "observable_stdio_servers_with_proxy", lambda detection: observed)
    monkeypatch.setattr(cursor, "managed_stdio_servers", lambda detection: managed)
    monkeypatch.setattr(cursor, "skipped_stdio_server_names", lambda detection: ())


def test_the_request_carries_ordered_origins_rows_and_only_launch_fields(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sent = _fake(monkeypatch, {"origins": [["z", 1], ["a", ["project", "pa"]]], "refresh": [1], "notes": _NOTES})
    _detected(monkeypatch, (_server("a", "project", "pa"),), ())
    managed = (_server("m", "global", "gm"),)
    payload: dict[str, object] = {
        "mcpServers": {
            "text": "hol-guard cursor-mcp-proxy",
            "guard": {"command": "hol-guard", "args": ["cursor-mcp-proxy"], "env": {"TOKEN": "secret"}},
            "bare": {"type": "stdio"},
        }
    }
    previous: dict[str, object] = {"managed_origins": {"z": 1, "a": None}}

    plan = cursor.CursorHarnessAdapter._editor_plan(
        _context(tmp_path, workspace=True), cast(Any, None), cast(Any, managed), previous, payload
    )

    assert plan == ({"z": 1, "a": ["project", "pa"]}, (1,), _NOTES)
    assert sent == [
        (
            "cursor_editor_plan",
            {
                "previous_origins": [["z", 1], ["a", None]],
                "observed": [["a", "project", "pa"]],
                "managed": [["m", "global", "gm"]],
                "servers": [None, {"command": "hol-guard", "args": ["cursor-mcp-proxy"]}, {}],
                "workspace": True,
            },
        )
    ]


@pytest.mark.parametrize(
    ("payload", "previous"),
    [
        (None, {}),
        ({"mcpServers": ["hol-guard"]}, {"managed_origins": [["a", 1]]}),
    ],
)
def test_missing_servers_and_origins_are_sent_as_null(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, payload: dict[str, object] | None, previous: dict[str, object]
) -> None:
    sent = _fake(monkeypatch, {"origins": [], "refresh": [], "notes": []})
    _detected(monkeypatch, (), ())

    cursor.CursorHarnessAdapter._editor_plan(_context(tmp_path), cast(Any, None), (), previous, payload)

    request = sent[0][1]
    assert request["servers"] is None
    assert request["previous_origins"] is None
    assert request["workspace"] is False


@pytest.mark.parametrize(
    "answer",
    [
        {"origins": [], "refresh": [], "notes": [], "extra": 1},
        {"origins": [], "refresh": []},
        {"origins": {}, "refresh": [], "notes": []},
        {"origins": [["a"]], "refresh": [], "notes": []},
        {"origins": [[1, 2]], "refresh": [], "notes": []},
        {"origins": [["a", 1], ["a", 2]], "refresh": [], "notes": []},
        {"origins": [], "refresh": [2], "notes": []},
        {"origins": [], "refresh": [-1], "notes": []},
        {"origins": [], "refresh": [True], "notes": []},
        {"origins": [], "refresh": [1, 1], "notes": []},
        {"origins": [], "refresh": [1, 0], "notes": []},
        {"origins": [], "refresh": [0], "notes": []},
        {"origins": [], "refresh": "1", "notes": []},
        {"origins": [], "refresh": [], "notes": [3]},
        {"origins": [], "refresh": [], "notes": "note"},
    ],
)
def test_a_malformed_answer_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, answer: dict[str, object]
) -> None:
    _fake(monkeypatch, answer)
    _detected(monkeypatch, (), ())
    payload: dict[str, object] = {"mcpServers": {"text": "x", "guard": {"command": "hol-guard"}}}

    with pytest.raises(ValueError, match="Cursor editor plan answer is malformed"):
        cursor.CursorHarnessAdapter._editor_plan(_context(tmp_path), cast(Any, None), (), {}, payload)


def test_refreshed_entries_keep_their_place_and_managed_proxies_follow(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    adapter = cursor.CursorHarnessAdapter()
    monkeypatch.setattr(adapter, "_refresh_guard_proxy_entry", lambda config: {"refreshed": config["command"]})
    monkeypatch.setattr(adapter, "_proxy_server_entry", lambda context, server: {"managed": server.name})
    payload: dict[str, object] = {
        "mcpServers": {"a": {"command": "node"}, "b": {"command": "hol-guard"}, "c": {"command": "py"}},
        "other": 1,
    }

    adapter._apply_editor_servers(_context(tmp_path), payload, (1, 2), cast(Any, (_server("a", "global", "g"),)))

    assert payload == {
        "mcpServers": {"a": {"managed": "a"}, "b": {"refreshed": "hol-guard"}, "c": {"refreshed": "py"}},
        "other": 1,
    }
    assert list(cast(dict[str, object], payload["mcpServers"])) == ["a", "b", "c"]


def _installer(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[cursor.CursorHarnessAdapter, HarnessContext]:
    adapter = cursor.CursorHarnessAdapter()
    monkeypatch.setattr(adapter, "detect", lambda context: None)
    monkeypatch.setattr(adapter, "_refresh_guard_proxy_entry", lambda config: {"refreshed": True})
    monkeypatch.setattr(cursor, "install_cursor_hooks", lambda context: {"managed_hooks_path": "hooks.json"})
    _detected(monkeypatch, (), ())
    return adapter, _context(tmp_path)


def test_install_applies_the_plan_after_asking_before_any_write(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    adapter, context = _installer(monkeypatch, tmp_path)
    target = adapter._target_editor_config_path(context)
    target.parent.mkdir(parents=True)
    target.write_text(json.dumps({"mcpServers": {"a": {"command": "node"}, "b": {"command": "hol-guard"}}}))
    backup = adapter._backup_path(target, context)
    state_path = adapter._state_path(target, context)
    written: list[bool] = []

    def fake_native(kind: str, request: dict[str, object]) -> dict[str, object]:
        written.append(backup.exists() or state_path.exists())
        return {"origins": [["x", ["project", "px"]]], "refresh": [1], "notes": _NOTES}

    monkeypatch.setattr(authority, "native_runner_authority", fake_native)

    manifest = adapter._install_editor(context)

    assert written == [False]
    assert json.loads(target.read_text())["mcpServers"] == {"a": {"command": "node"}, "b": {"refreshed": True}}
    assert json.loads(state_path.read_text())["managed_origins"] == {"x": ["project", "px"]}
    assert manifest["notes"] == _NOTES
    assert manifest["managed_hooks_path"] == "hooks.json"


@pytest.mark.parametrize(
    ("text", "message"),
    [("{not json", "unreadable Cursor editor config"), ("[1]", "non-object Cursor editor config")],
)
def test_install_still_writes_backup_and_state_before_refusing_a_bad_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, text: str, message: str
) -> None:
    adapter, context = _installer(monkeypatch, tmp_path)
    sent = _fake(monkeypatch, {"origins": [], "refresh": [], "notes": _NOTES})
    target = adapter._target_editor_config_path(context)
    target.parent.mkdir(parents=True)
    target.write_text(text)

    with pytest.raises(RuntimeError, match=message):
        adapter._install_editor(context)

    assert sent[0][1]["servers"] is None
    assert json.loads(adapter._backup_path(target, context).read_text()) == {"existed": True, "content": text}
    assert adapter._state_path(target, context).is_file()
    assert target.read_text() == text
