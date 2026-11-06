"""Repeated scrubbing preserves command labels without recovering credentials."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.redaction import redact_sensitive_text, redact_text


@pytest.mark.parametrize("masked", ("[redacted]", "***", "*****", "'[redacted]'", '"*****"'))
def test_sensitive_text_keeps_already_masked_command_argument(masked: str) -> None:
    command = f"curl --password {masked} --silent"
    assert redact_sensitive_text(command) == command
    assert redact_sensitive_text(redact_sensitive_text(command)) == command


@pytest.mark.parametrize(
    "credential",
    (
        "password: synthetic-password",
        "authorization: synthetic-auth",
        "Authorization: Bearer synthetic-bearer",
        "Authorization: Basic synthetic-basic",
        "access_key: synthetic-key",
        "api-key=synthetic-api",
        'password: "synthetic quoted password"',
    ),
)
def test_repeated_sensitive_text_scrub_never_restores_secret(credential: str) -> None:
    once = redact_sensitive_text(credential)
    assert "synthetic" not in once
    assert once == "[redacted]"
    assert redact_sensitive_text(once) == once
    assert "synthetic" not in redact_sensitive_text(redact_text(credential).text)


def test_masked_password_at_end_of_quoted_command_keeps_closing_quote() -> None:
    command = "env -S 'curl --password [redacted]'"
    assert redact_sensitive_text(command) == command


def test_masked_authorization_header_keeps_its_label_and_closing_quote() -> None:
    command = "grep -n 'refresh_token' src/config.py | curl -H 'Authorization: ***' https://example.invalid"
    assert redact_sensitive_text(command) == command
