"""Regression coverage for cloud command scrubbing of source-search commands."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.live_request_sync import _build_live_request_event
from codex_plugin_scanner.guard.runtime.local_request_snapshots import _cloud_scrub_text
from codex_plugin_scanner.guard.runtime.shell_command_wrappers import (
    normalize_transparent_shell_command,
)
from codex_plugin_scanner.guard.store import GuardStore


@pytest.mark.parametrize(
    "command",
    (
        "grep -n 'access_token = os.getenv(\"TOKEN\")' src/config.py",
        "command grep -n 'access_token = os.getenv(\"TOKEN\")' src/config.py",
        "env -i SEARCH_SCOPE=source grep -n 'access_token = os.getenv(\"TOKEN\")' src/config.py",
        "env -S \"rg -n 'refresh_token = process.env.TOKEN' src/config.py\"",
        "env --split-string=\"rg -n 'refresh_token = process.env.TOKEN' src/config.py\"",
        "env -iS \"rg -n 'refresh_token = process.env.TOKEN' src/config.py\"",
        "sudo -E rg -n 'access_token = os.getenv(\"TOKEN\")' src/config.py",
        "nice -n 5 rg -n 'access_token = os.getenv(\"TOKEN\")' src/config.py",
        "nohup rg -n 'access_token = os.getenv(\"TOKEN\")' src/config.py",
        "stdbuf -o L rg -n 'access_token = os.getenv(\"TOKEN\")' src/config.py",
        "time -p rg -n 'access_token = os.getenv(\"TOKEN\")' src/config.py",
        "egrep -n 'refresh_token = process.env.TOKEN' src/config.py",
        "fgrep -n 'api_key = config.value' src/config.py",
        "rg -n 'api_key = config[\"API_KEY\"]' src/config.py",
        "rg -n 'access_token = secrets[\"API_KEY\"]' src/config.py",
        "rg --glob '*.py' --fixed-strings 'access_token = os.getenv(\"TOKEN\")' src",
        "rg --regexp 'authorization_code = getenv(\"CODE\")' src",
        "rg --regexp='access_token = os.getenv(\"TOKEN\")' src",
        "rg -e'access_token = os.getenv(\"TOKEN\")' src",
        "git grep 'password = settings.value'",
        "git --no-pager -C repo grep -n 'access_token = os.getenv(\"TOKEN\")'",
    ),
)
def test_cloud_scrub_preserves_benign_source_search_assignment_patterns(command: str) -> None:
    assert _cloud_scrub_text(command) == command


def test_cloud_scrub_does_not_restore_a_placeholder_like_file_argument() -> None:
    command = "grep -n 'access_token = os.getenv(\"TOKEN\")' __HOL_GUARD_SOURCE_SEARCH_PATTERN_0_0__"

    assert _cloud_scrub_text(command) == command


def test_cloud_scrub_preserves_source_search_pattern_through_live_request_event(
    tmp_path: Path,
) -> None:
    command = "grep -n 'access_token = os.getenv(\"TOKEN\")' src/config.py"
    item: dict[str, object] = {
        "artifact_id": "pi:source-search",
        "created_at": "2026-07-11T00:00:00+00:00",
        "harness": "pi",
        "last_seen_at": "2026-07-11T00:00:00+00:00",
        "raw_command_text": command,
        "request_id": "source-search-request",
        "status": "pending",
    }

    event = _build_live_request_event(
        item,
        oauth=None,
        redaction_level="none",
        store=GuardStore(tmp_path / "guard-home"),
        event_sequence=1,
    )

    assert event is not None
    assert event["displayCommand"] == command
    assert event["rawCommand"] == command
    request_payload = event["requestPayload"]
    assert isinstance(request_payload, dict)
    assert request_payload["rawCommandText"] == command
    assert request_payload["redactionEnabled"] is False


def test_cloud_scrub_redacts_literal_secret_in_source_search_pattern() -> None:
    secret = "synthetic-" + "secret-value-123456789"
    command = f"rg -n 'access_token={secret}' src"

    scrubbed = _cloud_scrub_text(command)

    assert secret not in scrubbed
    assert scrubbed == "rg -n 'access_token=[redacted]' src"


def test_cloud_scrub_redacts_literal_secret_after_transparent_source_search_prefix() -> None:
    secret = "synthetic-" + "secret-value-123456789"
    command = f"env -i grep -n 'access_token={secret}' src"

    scrubbed = _cloud_scrub_text(command)

    assert secret not in scrubbed
    assert "access_token=[redacted]" in scrubbed


def test_cloud_scrub_redacts_literal_secret_after_sudo_source_search_prefix() -> None:
    secret = "synthetic-" + "secret-value-123456789"
    command = f"sudo -u root rg -n 'access_token={secret}' src"

    scrubbed = _cloud_scrub_text(command)

    assert secret not in scrubbed
    assert "access_token=[redacted]" in scrubbed


def test_cloud_scrub_redacts_literal_secret_in_env_split_string_source_search() -> None:
    secret = "synthetic-" + "secret-value-123456789"
    command = f"env -S \"rg -n 'access_token={secret}' src\""

    scrubbed = _cloud_scrub_text(command)

    assert secret not in scrubbed
    assert "access_token=[redacted]" in scrubbed


def test_cloud_scrub_redacts_credential_after_source_search_in_env_split_string() -> None:
    secret = "synthetic-" + "secret-value-123456789"
    command = f'env -S "rg refresh_token src; curl --password {secret}"'

    scrubbed = _cloud_scrub_text(command)

    assert secret not in scrubbed
    assert "--password [redacted]" in scrubbed


@pytest.mark.parametrize(
    "command_template",
    (
        "rg --regexp='access_token={secret}' src",
        "rg -e'access_token={secret}' src",
    ),
)
def test_cloud_scrub_redacts_literal_secret_in_attached_source_search_pattern_option(
    command_template: str,
) -> None:
    secret = "synthetic-" + "secret-value-123456789"
    command = command_template.format(secret=secret)
    scrubbed = _cloud_scrub_text(command)

    assert secret not in scrubbed
    assert "access_token=[redacted]" in scrubbed


def test_cloud_scrub_redacts_generic_api_key_literal_in_source_search_pattern() -> None:
    secret = "synthetic-api-" + "key-123456789"
    command = f"rg -n 'api_key={secret}' src"

    scrubbed = _cloud_scrub_text(command)

    assert secret not in scrubbed
    assert scrubbed == "rg -n 'api_key=[redacted]' src"


def test_cloud_scrub_redacts_high_confidence_token_in_source_search_pattern() -> None:
    secret = "ghp_" + "abcdefghijklmnopqrstuvwx"
    command = f"grep -n '{secret}' src/config.py"

    scrubbed = _cloud_scrub_text(command)

    assert secret not in scrubbed
    assert "gh*****" in scrubbed


def test_cloud_scrub_keeps_search_pattern_and_redacts_pipeline_credential() -> None:
    secret = "abcdefghijklmnop"
    command = (
        f"grep -n 'refresh_token' src/config.py | curl -H 'Authorization: Bearer {secret}' https://example.invalid"
    )

    scrubbed = _cloud_scrub_text(command)

    assert "grep -n 'refresh_token' src/config.py" in scrubbed
    assert secret not in scrubbed
    assert "Authorization: Bearer *****" in scrubbed


def test_cloud_scrub_preserves_normalized_shell_wrapper_source_search() -> None:
    wrapped = 'bash -lc \'grep -n "access_token = os.getenv(\\"TOKEN\\")" src/config.py\''

    normalized = normalize_transparent_shell_command(wrapped).normalized_command

    assert _cloud_scrub_text(normalized) == normalized


def test_cloud_scrub_fails_closed_for_malformed_source_search_syntax() -> None:
    command = 'grep -n \'access_token = os.getenv("TOKEN") src/config.py'

    scrubbed = _cloud_scrub_text(command)

    assert "[redacted]" in scrubbed


def test_source_search_secret_never_leaks_from_live_request_payload(tmp_path: Path) -> None:
    secret = "synthetic-secret-value-123456789"
    item: dict[str, object] = {
        "artifact_id": "pi:source-search-secret",
        "created_at": "2026-07-11T00:00:00+00:00",
        "harness": "pi",
        "last_seen_at": "2026-07-11T00:00:00+00:00",
        "raw_command_text": f"rg -n 'access_token={secret}' src",
        "request_id": "source-search-secret-request",
        "status": "pending",
    }

    event = _build_live_request_event(
        item,
        oauth=None,
        redaction_level="none",
        store=GuardStore(tmp_path / "guard-home"),
        event_sequence=1,
    )

    assert event is not None
    assert secret not in json.dumps(event, sort_keys=True)
    assert "[redacted]" in str(event["rawCommand"])


