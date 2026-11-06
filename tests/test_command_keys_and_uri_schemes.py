"""Tests for command key recognition in harness payloads.

Verifies:
1. _command_from_payload recognizes 'pattern', 'query', 'search', 'regex' keys
2. command_text_from_tool_payload reads the same keys from a hook payload
"""

import pytest

from codex_plugin_scanner.guard.runtime.actions import command_text_from_tool_payload, normalize_harness_payload


@pytest.fixture(autouse=True)
def _bound_native_runtime(native_approval_reuse_runtime):
    """Command text views are answered by the compiled resident; bind it, never emulate it."""

    return native_approval_reuse_runtime


def test_command_from_payload_recognizes_pattern():
    assert command_text_from_tool_payload("", {"pattern": "TODO|FIXME", "path": "src/"}) == "TODO|FIXME"


def test_command_from_payload_recognizes_query():
    assert command_text_from_tool_payload("", {"query": "test_function", "path": "."}) == "test_function"


def test_command_from_payload_recognizes_search():
    assert command_text_from_tool_payload("", {"search": "password"}) == "password"


def test_command_from_payload_recognizes_regex():
    assert command_text_from_tool_payload("", {"regex": r"\d{4}"}) == r"\d{4}"


def test_command_from_payload_preserves_command_priority():
    assert command_text_from_tool_payload("", {"command": "ls -la", "pattern": "foo"}) == "ls -la"


def _hook_command_text(payload):
    return command_text_from_tool_payload(payload.get("tool_name"), payload.get("tool_input"))


def test_hook_command_text_recognizes_pattern():
    payload = {"tool_input": {"pattern": "grep_pattern", "path": "src/"}}
    assert _hook_command_text(payload) == "grep_pattern"


def test_pi_grep_hook_command_text_renders_tool_invocation():
    payload = {
        "tool_name": "grep",
        "tool_input": {"pattern": "SupplyChainContextRow|context.*agent|context.*row", "path": "context"},
    }

    assert _hook_command_text(payload) == "grep 'SupplyChainContextRow|context.*agent|context.*row' context"


def test_pi_grep_action_command_renders_tool_invocation():
    payload = {
        "hook_event_name": "PostToolUse",
        "tool_name": "grep",
        "tool_input": {"pattern": "SupplyChainContextRow|context.*agent|context.*row", "path": "context"},
    }

    envelope = normalize_harness_payload("pi", "PostToolUse", payload, workspace=".", home_dir="/home/user")

    assert envelope.command == "grep 'SupplyChainContextRow|context.*agent|context.*row' context"


def test_hook_command_text_recognizes_query():
    payload = {"tool_input": {"query": "search_term"}}
    assert _hook_command_text(payload) == "search_term"
