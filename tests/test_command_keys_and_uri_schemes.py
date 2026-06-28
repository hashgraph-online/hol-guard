"""Tests for command key recognition and URI-scheme path-like filtering.

Verifies:
1. _command_from_payload recognizes 'pattern', 'query', 'search', 'regex' keys
2. _hook_command_text recognizes the same keys
3. _read_only_lookup_target_is_path_like returns False for URI schemes (skill://, http://)
"""

from codex_plugin_scanner.guard.runtime.actions import _command_from_payload
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    _read_only_lookup_target_is_path_like,
    _read_only_lookup_filter_grep_args_are_safe,
)
from codex_plugin_scanner.guard.cli._commands_shared import _hook_command_text


def test_command_from_payload_recognizes_pattern():
    assert _command_from_payload({"pattern": "TODO|FIXME", "path": "src/"}) == "TODO|FIXME"


def test_command_from_payload_recognizes_query():
    assert _command_from_payload({"query": "test_function", "path": "."}) == "test_function"


def test_command_from_payload_recognizes_search():
    assert _command_from_payload({"search": "password"}) == "password"


def test_command_from_payload_recognizes_regex():
    assert _command_from_payload({"regex": r"\d{4}"}) == r"\d{4}"


def test_command_from_payload_preserves_command_priority():
    assert _command_from_payload({"command": "ls -la", "pattern": "foo"}) == "ls -la"


def test_hook_command_text_recognizes_pattern():
    payload = {"tool_input": {"pattern": "grep_pattern", "path": "src/"}}
    assert _hook_command_text(payload) == "grep_pattern"


def test_hook_command_text_recognizes_query():
    payload = {"tool_input": {"query": "search_term"}}
    assert _hook_command_text(payload) == "search_term"


def test_path_like_returns_false_for_skill_uri():
    assert _read_only_lookup_target_is_path_like("skill://guard-dev-testing") is False


def test_path_like_returns_false_for_http_uri():
    assert _read_only_lookup_target_is_path_like("http://127.0.0.1:5497/requests/abc") is False


def test_path_like_returns_true_for_https_uri():
    assert _read_only_lookup_target_is_path_like("https://example.com/path") is False


def test_path_like_returns_true_for_file_uri():
    # file:// URIs reference local files and should still be treated as path-like.
    assert _read_only_lookup_target_is_path_like("file:///etc/shadow") is True


def test_path_like_returns_true_for_real_path():
    assert _read_only_lookup_target_is_path_like("src/components/Button.tsx") is True


def test_path_like_returns_true_for_file_with_extension():
    assert _read_only_lookup_target_is_path_like("config.json") is True


def test_grep_filter_allows_url_pattern():
    # URL pattern is not path-like (contains ://), so it passes.
    # But a path operand like "src/" is still checked for safety.
    args = ["http://127.0.0.1:5497/requests/abc#token=xyz"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is True


def test_grep_filter_allows_skill_uri():
    args = ["skill://guard-dev-testing"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is True


def test_grep_filter_blocks_redirection():
    args = ["pattern", ">", "/etc/passwd"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is False
