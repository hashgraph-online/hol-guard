"""Workspace CLI credentials must not leave the machine through Cloud sync or telemetry."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.managed_controls.telemetry import (
    TelemetryPrivacyError,
    managed_controls_telemetry_event,
)
from codex_plugin_scanner.guard.runtime import cloud_review_event_projection as projection
from codex_plugin_scanner.guard.runtime.runner import _cloud_sync_receipt_payload
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_cloud_review_sync_worker import Store

ACCESS_VALUE = "fake-access-value-0001"
REFRESH_VALUE = "fake-refresh-value-0002"
CLIENT_SECRET_VALUE = "fake-client-secret-0003"
KEYRING_VALUE = "fake-keyring-value-0004"
CREDENTIALS_FILE = "/Users/alice/.config/gws/client_secret.json"

SECRET_VALUES = (ACCESS_VALUE, REFRESH_VALUE, CLIENT_SECRET_VALUE, KEYRING_VALUE, CREDENTIALS_FILE)

CREDENTIAL_COMMANDS = (
    f"GOOGLE_WORKSPACE_CLI_TOKEN={ACCESS_VALUE} gws gmail +send --to team@example.com",
    f"GOOGLE_WORKSPACE_CLI_CLIENT_SECRET={CLIENT_SECRET_VALUE} gws drive files list",
    f"gws auth login --credentials-file {CREDENTIALS_FILE}",
    f"gws auth login --credentials-file={CREDENTIALS_FILE}",
    f"gws gmail +send --refresh-token {REFRESH_VALUE}",
    f"GOG_ACCESS_TOKEN={ACCESS_VALUE} gog gmail send --to team@example.com",
    f"GOG_KEYRING_PASSWORD={KEYRING_VALUE} gog drive ls",
    f"gog --access-token {ACCESS_VALUE} gmail send",
    f"gog gmail send --client-secret {CLIENT_SECRET_VALUE}",
    f"gog gmail send --client-secret={CLIENT_SECRET_VALUE}",
)

REDACTION_LEVELS = ("full", "partial", "none")


def _decoded_text(payload: dict[str, object]) -> str:
    text = json.dumps(payload, sort_keys=True)
    envelope = payload.get("envelopeRedacted")
    if isinstance(envelope, dict):
        encoded = envelope.get("commandEncoded")
        if isinstance(encoded, str):
            text += base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).decode("utf-8")
    return text


def _assert_no_secret(text: str) -> None:
    for value in SECRET_VALUES:
        assert value not in text


@pytest.mark.parametrize("redaction_level", REDACTION_LEVELS)
@pytest.mark.parametrize("command", CREDENTIAL_COMMANDS)
@pytest.mark.parametrize("has_full_envelope", (True, False))
@pytest.mark.parametrize("stored_key", ("command", "redacted_command"))
def test_receipt_sync_payload_never_carries_cli_credentials(
    command: str,
    redaction_level: str,
    has_full_envelope: bool,
    stored_key: str,
) -> None:
    receipt: dict[str, object] = {
        "receipt_id": "guard-receipt-1",
        "artifact_id": "codex:project:shell",
        "artifact_name": "shell",
        "policy_decision": "review",
        "timestamp": "2026-10-09T00:00:00Z",
        "raw_command_text": command,
        # Receipts written at partial or none keep the locally redacted command.
        "envelope_redacted_json": {"tool_name": "Bash", stored_key: command},
    }
    if has_full_envelope:
        receipt["action_envelope_json"] = {"tool_name": "Bash", "command": command}

    payload = _cloud_sync_receipt_payload(
        receipt,
        device_id="device-1",
        device_name="Workstation",
        redaction_level=redaction_level,
    )

    _assert_no_secret(_decoded_text(payload))
    envelope = payload["envelopeRedacted"]
    assert isinstance(envelope, dict)
    if redaction_level == "full":
        assert "command" not in envelope
        assert "redacted_command" not in envelope


@pytest.mark.parametrize("redaction_level", REDACTION_LEVELS)
@pytest.mark.parametrize("command", CREDENTIAL_COMMANDS)
def test_cloud_review_event_never_carries_cli_credentials(
    tmp_path: Path,
    command: str,
    redaction_level: str,
) -> None:
    event = projection.build_cloud_review_event(
        {
            "request_id": "request-1",
            "status": "pending",
            "harness": "codex",
            "raw_command_text": command,
            "action_envelope_json": {"tool_name": "Bash", "command": command},
            "created_at": "2026-10-09T00:00:00+00:00",
            "last_seen_at": "2026-10-09T00:00:00+00:00",
        },
        oauth=None,
        redaction_level=redaction_level,
        store=cast(GuardStore, cast(object, Store(tmp_path))),
        event_sequence=1,
    )

    assert event is not None
    _assert_no_secret(json.dumps(event, sort_keys=True))


@pytest.mark.parametrize("command", CREDENTIAL_COMMANDS)
def test_telemetry_rejects_cli_command_and_credential_values(command: str) -> None:
    with pytest.raises(TelemetryPrivacyError):
        managed_controls_telemetry_event({"event": "catalog_sync", "command": command})
    with pytest.raises(TelemetryPrivacyError):
        managed_controls_telemetry_event({"event": command})
