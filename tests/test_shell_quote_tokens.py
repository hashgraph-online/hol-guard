"""Focused contracts for quote-aware shell token expansion detection."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.secret_file_request_services.shell_quote_tokens import (
    shell_token_has_active_expansion,
    shell_token_has_active_pathname_expansion,
)


@pytest.mark.parametrize(
    ("raw_token", "expected"),
    (
        ("$VALUE", True),
        ('"${VALUE}"', True),
        ("`date`", True),
        ("'$VALUE'", False),
        (r"\$VALUE", False),
        ("'`date`'", False),
        (r"\`date\`", False),
    ),
)
def test_parameter_and_command_expansion_respects_quotes_and_escapes(raw_token: str, expected: bool) -> None:
    assert shell_token_has_active_expansion(raw_token) is expected


@pytest.mark.parametrize(
    ("raw_token", "expected"),
    (
        ("*.md", True),
        ("?", True),
        ("[abc]", True),
        ('"*.md"', False),
        ("'*.md'", False),
        (r"\*.md", False),
        ('"?"', False),
        ("'[abc]'", False),
        (r"\[abc\]", False),
        ("[abc", False),
        ("[", False),
    ),
)
def test_pathname_expansion_respects_quotes_escapes_and_complete_brackets(raw_token: str, expected: bool) -> None:
    assert shell_token_has_active_pathname_expansion(raw_token) is expected
