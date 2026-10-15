"""Every Cursor tool routed through preToolUse is reviewed as a file change, and health checks that routing."""

from __future__ import annotations

import shlex
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.cursor_hook_config import (
    HOOK_SCRIPT_NAME,
    live_guard_cursor_hooks_intercept,
)
from codex_plugin_scanner.guard.adapters.cursor_hook_events import (
    CURSOR_FILE_MUTATION_TOOL_MATCHER,
    CURSOR_FILE_MUTATION_TOOLS,
    cursor_entry_guards_file_mutations,
    unsupported_cursor_hook_events,
)
from codex_plugin_scanner.guard.runtime.actions import normalize_cursor_hook_payload
from codex_plugin_scanner.guard.runtime.secret_file_request_services.request_artifacts import (
    extract_sensitive_file_write_request,
)

_TOOL_INPUTS = {
    "Write": lambda path: {"file_path": path, "content": "x"},
    "Edit": lambda path: {"file_path": path, "old_string": "a", "new_string": "b"},
    "StrReplace": lambda path: {"path": path, "old_string": "a", "new_string": "b"},
    "MultiEdit": lambda path: {"file_path": path, "edits": [{"old_string": "a", "new_string": "b"}]},
    "Delete": lambda path: {"path": path},
}


def test_every_routed_tool_has_a_classified_input_shape() -> None:
    assert set(_TOOL_INPUTS) == set(CURSOR_FILE_MUTATION_TOOLS)


@pytest.mark.parametrize("tool_name", CURSOR_FILE_MUTATION_TOOLS)
def test_routed_tool_normalizes_to_file_write_with_target(tool_name: str, tmp_path: Path) -> None:
    target = tmp_path / "workspace" / ".env"
    envelope = normalize_cursor_hook_payload(
        {"hook_event_name": "preToolUse", "tool_name": tool_name, "tool_input": _TOOL_INPUTS[tool_name](str(target))},
        workspace=tmp_path / "workspace",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard",
    )
    assert envelope.action_type == "file_write"
    assert len(envelope.target_paths) == 1
    assert envelope.target_paths[0].endswith(".env")


@pytest.mark.parametrize("tool_name", CURSOR_FILE_MUTATION_TOOLS)
def test_routed_tool_hits_sensitive_write_rules(tool_name: str, tmp_path: Path) -> None:
    home, workspace = tmp_path / "home", tmp_path / "workspace"
    hooks_json = home / ".cursor" / "hooks.json"
    cases = {
        str(workspace / ".env"): ("local .env file", "sensitive local file write"),
        str(home / ".ssh" / "id_ed25519"): ("SSH private key", "sensitive local file write"),
        str(hooks_json): ("Cursor hooks", "guard-managed config write"),
    }
    for path, (path_class, action_class) in cases.items():
        match = extract_sensitive_file_write_request(
            tool_name,
            _TOOL_INPUTS[tool_name](path),
            cwd=workspace,
            home_dir=home,
            protected_paths={str(hooks_json): "Cursor hooks"},
        )
        assert match is not None, path
        assert (match.path_class, match.action_class) == (path_class, action_class)


def test_ordinary_file_change_is_not_sensitive(tmp_path: Path) -> None:
    for tool_name, build in _TOOL_INPUTS.items():
        assert extract_sensitive_file_write_request(tool_name, build("src/app.py"), cwd=tmp_path) is None


def test_unsupported_events_are_reported() -> None:
    hooks = {"beforeShellExecution": [], "beforeWriteFile": [], "beforeEditFile": []}
    assert unsupported_cursor_hook_events(hooks) == ["beforeEditFile", "beforeWriteFile"]


@pytest.mark.parametrize(
    ("entry", "guarded"),
    [
        ({"failClosed": True, "matcher": CURSOR_FILE_MUTATION_TOOL_MATCHER}, True),
        ({"failClosed": True}, True),
        ({"failClosed": True, "matcher": "*"}, True),
        ({"failClosed": True, "matcher": "Shell"}, False),
        ({"failClosed": True, "matcher": "^(Write|Edit)$"}, False),
        ({"failClosed": True, "matcher": "("}, False),
        ({"failClosed": True, "matcher": 7}, False),
        ({"matcher": CURSOR_FILE_MUTATION_TOOL_MATCHER}, False),
        ({"failClosed": False, "matcher": CURSOR_FILE_MUTATION_TOOL_MATCHER}, False),
    ],
)
def test_entry_guards_file_mutations(entry: dict[str, object], guarded: bool) -> None:
    assert cursor_entry_guards_file_mutations(entry) is guarded


def _live_hooks(tmp_path: Path, pre_tool_use: dict[str, object]) -> dict[str, object]:
    script = tmp_path / ".cursor" / "hooks" / HOOK_SCRIPT_NAME
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text("raise SystemExit(0)\n", encoding="utf-8")
    command = shlex.join(["python3", str(script)])
    entry = [{"command": command}]
    return {
        "beforeShellExecution": entry,
        "beforeMCPExecution": entry,
        "beforeReadFile": entry,
        "preToolUse": [{"command": command, **pre_tool_use}],
    }


def test_health_accepts_installed_write_entry(tmp_path: Path) -> None:
    hooks = _live_hooks(tmp_path, {"failClosed": True, "matcher": CURSOR_FILE_MUTATION_TOOL_MATCHER})
    assert live_guard_cursor_hooks_intercept(hooks) is True


@pytest.mark.parametrize(
    "pre_tool_use",
    [
        {"failClosed": True, "matcher": "Shell"},
        {"matcher": CURSOR_FILE_MUTATION_TOOL_MATCHER},
    ],
)
def test_health_rejects_entry_that_leaves_writes_unguarded(tmp_path: Path, pre_tool_use: dict[str, object]) -> None:
    assert live_guard_cursor_hooks_intercept(_live_hooks(tmp_path, pre_tool_use)) is False


def test_health_rejects_unsupported_event(tmp_path: Path) -> None:
    hooks = _live_hooks(tmp_path, {"failClosed": True, "matcher": CURSOR_FILE_MUTATION_TOOL_MATCHER})
    hooks["beforeWriteFile"] = [{"command": "other-tool audit"}]
    assert live_guard_cursor_hooks_intercept(hooks) is False
