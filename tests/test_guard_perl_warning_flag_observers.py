"""Perl interpreter flag observers that must stay explicitly benign."""

from __future__ import annotations

from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    extract_sensitive_tool_action_request,
)


def test_classifier_skips_perl_warning_flag_sleep_wait() -> None:
    request = extract_sensitive_tool_action_request(
        "bash",
        {"command": "perl -W -e 'sleep 240'"},
    )

    assert request is None
