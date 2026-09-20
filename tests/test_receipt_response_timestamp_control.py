"""Proposed actual-runner control for legacy response timestamps and signed control learning."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import receipt_sync_authority as authority
from codex_plugin_scanner.guard.synced_policy import validated_synced_policy_bundle
from tests.policy_bundle_signing_helpers import policy_bundle_test_keyring, sign_policy_bundle
from tests.test_receipt_runner_preference_integration import (
    _cursor,
    _invoke,
    _ready,
    _Response,
    _rows,
    _Transport,
)
from tests.test_receipt_runner_preference_integration import (
    _local_runtime as _local_runtime,
)
from tests.test_synced_policy import _signed_policy_bundle
from tests.test_workspace_preference_authority import NOW, WORKSPACE


@pytest.mark.parametrize("synced_at", ["2026-09-19", "2026-09-19T03:04:05"])
def test_legacy_response_timestamp_does_not_block_current_preferences_or_signed_control(
    tmp_path: Path, _local_runtime: Callable[[_Transport], None], synced_at: str
) -> None:
    store, _ = _ready(tmp_path)
    _rows(store, 75)
    store.set_sync_payload("policy_bundle_keyring", policy_bundle_test_keyring(workspace_id=WORKSPACE), NOW)
    unsigned = _signed_policy_bundle()
    unsigned["receiptRedactionLevel"] = "partial"
    signed = sign_policy_bundle(unsigned, workspace_id=WORKSPACE)
    transport = _Transport(revision=2)
    _local_runtime(transport)

    def respond(body: dict[str, Any], number: int) -> _Response:
        assert number == 1
        assert body["receipts"]
        return transport.reply(body, syncedAt=synced_at, policyBundle=signed)

    transport.receipt_handler = respond
    _invoke(store)
    assert len(transport.receipt_calls) == 1
    assert _cursor(store) is None
    learned = authority.capture_receipt_sync_state(store).preference_state.preferences
    assert learned is not None and learned.revision == 2
    accepted = validated_synced_policy_bundle(store)
    assert accepted is not None and accepted["receiptRedactionLevel"] == "partial"


@pytest.mark.parametrize(
    "synced_at",
    [
        "2026-04-15T00:01:00Z",
        "2026-04-15T02:01:00+02:00",
        "2026-04-15T00:01:00.125Z",
    ],
)
def test_valid_response_timestamp_spelling_is_retained_in_committed_progress(
    tmp_path: Path, _local_runtime: Callable[[_Transport], None], synced_at: str
) -> None:
    store, _ = _ready(tmp_path)
    rows = _rows(store, 1, commands=False)
    transport = _Transport()
    _local_runtime(transport)

    def respond(body: dict[str, Any], number: int) -> _Response:
        assert number == 1
        assert len(body["receipts"]) == 1
        return transport.reply(body, syncedAt=synced_at)

    transport.receipt_handler = respond
    _invoke(store)

    assert len(transport.receipt_calls) == 1
    assert store.get_sync_payload("receipt_sync_cursor") == {
        "last_rowid": rows[0]["receipt_rowid"],
        "synced_at": synced_at,
    }
