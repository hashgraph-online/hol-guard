from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.user_recovery_contract import (
    MAX_EVENT_BYTES,
    RecoveryContractError,
    encode_recovery_event,
    validate_event_sequence,
    validate_recovery_snapshot,
)

FIXTURES = Path(__file__).parent / "fixtures" / "daemon_recovery_v1"


def _fixture(name: str) -> dict[str, object]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", ["valid_reconnected.json", "valid_timeout.json"])
def test_valid_contract_fixtures(name: str) -> None:
    payload = _fixture(name)
    assert validate_recovery_snapshot(payload) == payload
    event = encode_recovery_event(payload)
    assert event.endswith(b"\n")
    assert len(event) <= MAX_EVENT_BYTES + 1


@pytest.mark.parametrize(
    ("name", "code"),
    [
        ("invalid_unknown_reason.json", "recovery_reasonCode_invalid"),
        ("invalid_secret_field.json", "recovery_snapshot_fields_invalid"),
        ("unsupported_schema.json", "unsupported_protocol"),
    ],
)
def test_invalid_contract_fixtures(name: str, code: str) -> None:
    with pytest.raises(RecoveryContractError, match=code):
        validate_recovery_snapshot(_fixture(name))


def test_operation_id_is_required_for_mutation_events() -> None:
    payload = _fixture("invalid_unknown_reason.json")
    payload["reasonCode"] = "unknown"
    with pytest.raises(RecoveryContractError, match="recovery_operation_id_required"):
        validate_recovery_snapshot(payload, allow_inspection=False)


def test_sequence_rejects_late_and_cross_operation_events() -> None:
    previous = _fixture("valid_timeout.json")
    current = {**previous, "sequence": 8}
    assert validate_event_sequence(previous, current)["sequence"] == 8
    with pytest.raises(RecoveryContractError, match="recovery_sequence_not_increasing"):
        validate_event_sequence(previous, previous)
    with pytest.raises(RecoveryContractError, match="recovery_operation_changed"):
        validate_event_sequence(previous, {**current, "operationId": "33333333-3333-4333-8333-333333333333"})


def test_verified_protection_requires_positive_health_check() -> None:
    payload = _fixture("valid_reconnected.json")
    payload["checks"] = []
    with pytest.raises(RecoveryContractError, match="recovery_protection_unverified"):
        validate_recovery_snapshot(payload)


def test_timeout_keeps_retry_disabled_while_worker_is_active() -> None:
    payload = _fixture("valid_timeout.json")
    payload["retryAllowed"] = True
    with pytest.raises(RecoveryContractError, match="recovery_timeout_worker_invalid"):
        validate_recovery_snapshot(payload)
