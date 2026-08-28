"""Perl interpreter flag observers that must stay explicitly benign."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    extract_sensitive_tool_action_request,
    is_explicitly_benign_tool_action_request,
)


def test_classifier_skips_perl_warning_flag_sleep_wait() -> None:
    request = extract_sensitive_tool_action_request(
        "bash",
        {"command": "perl -W -e 'sleep 240'"},
    )

    assert request is None


def test_bounded_wait_with_perl_warnings_flag_is_benign(tmp_path: Path) -> None:
    command = "perl -W -e 'sleep 240' && echo WAIT_DONE"

    assert is_explicitly_benign_tool_action_request(
        "bash",
        {"command": command},
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    assert (
        extract_sensitive_tool_action_request(
            "bash",
            {"command": command},
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        is None
    )
