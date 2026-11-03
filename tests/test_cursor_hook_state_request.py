"""The request Guard sends to the native ``cursor_hook_state`` kind and the answers it accepts."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_runner_authority as authority_module
from codex_plugin_scanner.guard.adapters import cursor_hooks
from codex_plugin_scanner.guard.adapters._modules.cursor.cursor_hook_native import CursorNativeBridgeUnavailableError
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cursor_hook_config import _MANAGED_HOOK_EVENTS, _hooks_state_path

_SOURCE = "#!/usr/bin/env python3\nprint('guard')\n"
_IDENTITY = {"schema_version": 1, "command": ["/opt/hol-guard"]}


def _context(tmp_path: Path) -> HarnessContext:
    return HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard")


def _answering(monkeypatch: pytest.MonkeyPatch, answer: object) -> list[tuple[str, dict[str, object]]]:
    calls: list[tuple[str, dict[str, object]]] = []

    def fake(kind: str, args: dict[str, object], **_kwargs: object) -> object:
        calls.append((kind, json.loads(json.dumps(args, allow_nan=False))))
        return answer

    monkeypatch.setattr(authority_module, "native_runner_authority", fake)
    return calls


def _attested(monkeypatch: pytest.MonkeyPatch, failing_entry: str | None = None) -> None:
    guard_cli = SimpleNamespace(command=("/opt/hol-guard",), python=None, manifest_payload=lambda: dict(_IDENTITY))

    def entry(_context: object, *, script_path: Path, event_name: str, python_executable: object) -> object:
        assert python_executable is None
        if event_name == failing_entry:
            raise RuntimeError("entry render failed")
        return {"command": f"{script_path} {event_name}"}

    monkeypatch.setattr(cursor_hooks, "require_cursor_hook_bridge", lambda _home: None)
    monkeypatch.setattr(cursor_hooks, "resolve_attested_guard_cli", lambda _context: guard_cli)
    monkeypatch.setattr(cursor_hooks, "cursor_hook_script_source", lambda _context, **_kwargs: _SOURCE)
    monkeypatch.setattr(cursor_hooks, "_managed_hook_entry", entry)


def _plant(context: HarnessContext) -> None:
    hooks_path = cursor_hooks.cursor_hooks_path(context)
    for path in (cursor_hooks.cursor_hook_script_path(context), cursor_hooks.managed_hook_script_path(context)):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_SOURCE, encoding="utf-8")
    hooks_path.write_text('{"hooks": {}}', encoding="utf-8")
    state_path = _hooks_state_path(hooks_path, context)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text('{"guard_cli_identity": 1}', encoding="utf-8")


def test_request_carries_every_read_and_rendered_entry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    context = _context(tmp_path)
    _attested(monkeypatch)
    _plant(context)
    calls = _answering(monkeypatch, {"integrity_status": "valid", "reason": None})

    state = cursor_hooks.cursor_native_hook_state(context)

    assert state == {
        "protection_active": True,
        "integrity_status": "valid",
        "reason": None,
        "guard_cli_identity": _IDENTITY,
    }
    [(kind, request)] = calls
    assert kind == "cursor_hook_state"
    script_path = cursor_hooks.cursor_hook_script_path(context)
    assert request == {
        "source": _SOURCE,
        "identity": _IDENTITY,
        "state_text": '{"guard_cli_identity": 1}',
        "scripts": [{"regular": True, "text": _SOURCE}, {"regular": True, "text": _SOURCE}],
        "hooks_text": '{"hooks": {}}',
        "entries": {event: {"command": f"{script_path} {event}"} for event in _MANAGED_HOOK_EVENTS},
    }


def test_absent_files_are_sent_as_null(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    context = _context(tmp_path)
    _attested(monkeypatch)
    cursor_hooks.cursor_hook_script_path(context).parent.mkdir(parents=True)
    cursor_hooks.cursor_hook_script_path(context).symlink_to(tmp_path)
    calls = _answering(monkeypatch, {"integrity_status": "missing", "reason": "guard_cursor_hook_state_missing"})

    state = cursor_hooks.cursor_native_hook_state(context)

    assert state == {
        "protection_active": False,
        "integrity_status": "missing",
        "reason": "guard_cursor_hook_state_missing",
    }
    [(_kind, request)] = calls
    assert request["state_text"] is None
    assert request["scripts"] == [None, None]
    assert request["hooks_text"] is None


def test_non_regular_scripts_are_never_opened(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    context = _context(tmp_path)
    _attested(monkeypatch)
    _plant(context)
    script_path = cursor_hooks.cursor_hook_script_path(context)
    managed_path = cursor_hooks.managed_hook_script_path(context)
    script_path.unlink()
    os.mkfifo(script_path)
    target = tmp_path / "target.py"
    target.write_text(_SOURCE, encoding="utf-8")
    managed_path.unlink()
    managed_path.symlink_to(target)
    calls = _answering(monkeypatch, {"integrity_status": "missing", "reason": "guard_cursor_hook_script_missing"})

    cursor_hooks.cursor_native_hook_state(context)

    [(_kind, request)] = calls
    assert request["scripts"] == [None, {"regular": False, "text": ""}]


def test_a_raised_render_is_reraised_only_when_the_answer_names_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = _context(tmp_path)
    _attested(monkeypatch, failing_entry="preToolUse")
    _plant(context)
    calls = _answering(monkeypatch, {"raise": "preToolUse"})

    with pytest.raises(RuntimeError, match="entry render failed"):
        cursor_hooks.cursor_native_hook_state(context)

    [(_kind, request)] = calls
    entries = request["entries"]
    assert isinstance(entries, dict)
    assert entries["preToolUse"] is False
    assert entries["beforeShellExecution"] != False  # noqa: E712


@pytest.mark.parametrize(
    "answer",
    [
        {"raise": "preToolUse"},
        {"raise": "hooks", "reason": None},
        {"integrity_status": "valid", "reason": "guard_cursor_hook_state_missing"},
        {"integrity_status": "attestation-unavailable", "reason": "guard_cursor_cli_attestation_unavailable"},
        {"integrity_status": "tampered", "reason": None},
        {"integrity_status": "stale"},
        {"integrity_status": "valid", "reason": None, "guard_cli_identity": _IDENTITY},
        {},
    ],
)
def test_malformed_answers_are_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: object) -> None:
    context = _context(tmp_path)
    _attested(monkeypatch)
    _plant(context)
    _answering(monkeypatch, answer)

    with pytest.raises(ValueError, match="Cursor hook state answer is malformed"):
        cursor_hooks.cursor_native_hook_state(context)


def test_bridge_and_attestation_failures_never_ask(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    context = _context(tmp_path)
    calls = _answering(monkeypatch, {"integrity_status": "valid", "reason": None})

    def no_bridge(_home: object) -> None:
        raise CursorNativeBridgeUnavailableError("absent")

    def no_attestation(_context: object) -> object:
        raise RuntimeError("unattested")

    monkeypatch.setattr(cursor_hooks, "require_cursor_hook_bridge", no_bridge)
    assert cursor_hooks.cursor_native_hook_state(context)["reason"] == "guard_cursor_native_bridge_unavailable"
    monkeypatch.setattr(cursor_hooks, "require_cursor_hook_bridge", lambda _home: None)
    monkeypatch.setattr(cursor_hooks, "resolve_attested_guard_cli", no_attestation)
    assert cursor_hooks.cursor_native_hook_state(context) == {
        "protection_active": False,
        "integrity_status": "attestation-unavailable",
        "reason": "guard_cursor_cli_attestation_unavailable",
    }
    assert calls == []
