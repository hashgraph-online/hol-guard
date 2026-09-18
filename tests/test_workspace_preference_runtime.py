"""Actual sync keeps optional cursors separate from signed policy progress."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from codex_plugin_scanner.guard.policy_bundle_v2 import (
    canonical_policy_bundle_v2_payload,
    computed_policy_bundle_v2_hash,
    payload_hash_for_policy_bundle_v2,
)
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.runtime.workspace_preferences import (
    accept_workspace_preferences,
    read_workspace_preferences,
)
from codex_plugin_scanner.guard.schemas.guard_event_v1 import GuardEventV1
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_receipt_redaction_cursor import _store_blocked_command_receipt
from tests.test_policy_bundle_v2 import _signed_bundle, _verification_key
from tests.test_policy_bundle_v2_runtime_admission import _generic_v2_payload
from tests.test_workspace_preferences import NOW, WORKSPACE, wire

AUTH: dict[str, object] = {
    "sync_url": "https://hol.org/api/guard/receipts/sync",
    "access_token": "disposable-source-fixture",
    "dpop_key_material": None,
}


@pytest.fixture
def store(tmp_path: Path) -> GuardStore:
    result = GuardStore(tmp_path / "guard")
    result.set_sync_payload("oauth_local_credentials", {"workspace_id": WORKSPACE}, NOW)
    (result.guard_home / "config.toml").write_text('sync = true\ntelemetry = false\nreceipt_redaction_level = "full"\n')
    _store_blocked_command_receipt(result, "optional-source-receipt")
    return result


def respond(monkeypatch: pytest.MonkeyPatch, payload: dict[str, object]) -> list[dict[str, object]]:
    requests: list[dict[str, object]] = []

    def receive(*, request, timeout_seconds, retry_timeout_seconds):
        del timeout_seconds, retry_timeout_seconds
        assert isinstance(request.data, bytes)
        body = json.loads(request.data)
        assert isinstance(body, dict)
        requests.append(body)
        return {"syncedAt": NOW, "receiptsStored": 0, **payload}

    monkeypatch.setattr(runner, "_urlopen_json_with_timeout_retry", receive)
    return requests


def cursor(store: GuardStore) -> object:
    return store.get_sync_payload("receipt_sync_cursor")


def test_first_contact_then_exact_ack_advances_only_the_accepted_batch(
    store: GuardStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    requests = respond(monkeypatch, {"workspacePreferences": wire(), "receiptSyncAccepted": False})
    before = cursor(store)
    runner.sync_receipts(store, auth_context=AUTH)
    assert requests[0]["receipts"] == []
    context = requests[0]["syncContext"]
    assert isinstance(context, dict)
    assert "workspacePreferenceRevision" not in context
    assert cursor(store) == before
    current = read_workspace_preferences(store)
    assert current is not None and current.revision == 1
    requests = respond(monkeypatch, {"workspacePreferences": wire(), "receiptSyncAccepted": True, "receiptsStored": 1})
    runner.sync_receipts(store, auth_context=AUTH)
    context = requests[0]["syncContext"]
    assert isinstance(context, dict)
    assert context["workspacePreferenceRevision"] == 1
    state = cursor(store)
    assert isinstance(state, dict)
    assert state["last_rowid"] == store.latest_receipt_rowid()


@pytest.mark.parametrize(
    "response",
    [
        {},
        {"workspacePreferences": wire()},
        {"workspacePreferences": wire(), "receiptSyncAccepted": False},
        {"workspacePreferences": wire(), "receiptSyncAccepted": "true"},
        {"workspacePreferences": wire(2), "receiptSyncAccepted": True},
        {"workspacePreferences": {"revision": 1}, "receiptSyncAccepted": True},
    ],
)
def test_missing_invalid_or_mismatched_ack_preserves_actual_pending_receipts(
    store: GuardStore, monkeypatch: pytest.MonkeyPatch, response: dict[str, object]
) -> None:
    accept_workspace_preferences(store, wire(), workspace_id=WORKSPACE)
    before = cursor(store)
    respond(monkeypatch, response)
    runner.sync_receipts(store, auth_context=AUTH)
    assert cursor(store) == before
    assert len(store.list_receipts()) == 1


def test_old_server_compatibility_is_limited_to_before_negotiation(
    store: GuardStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    respond(monkeypatch, {"receiptsStored": 1})
    runner.sync_receipts(store, auth_context=AUTH)
    assert cursor(store) is None  # The first legacy interaction is still an empty control negotiation.
    runner.sync_receipts(store, auth_context=AUTH)
    first = cursor(store)
    assert isinstance(first, dict)
    accept_workspace_preferences(store, wire(), workspace_id=WORKSPACE)
    _store_blocked_command_receipt(store, "second-optional-receipt")
    runner.sync_receipts(store, auth_context=AUTH)
    assert cursor(store) == first


def signed_bundle(key: rsa.RSAPrivateKey, *, version: int) -> tuple[dict[str, object], dict[str, object]]:
    verification = _verification_key(key, workspace_id=WORKSPACE)
    bundle = _signed_bundle(
        key,
        verification,
        bundle_version=version,
        payload_base=_generic_v2_payload(
            rule_id=f"rule.{version}",
            artifact_id=f"command:{version}",
        ),
    )
    bundle["workspaceId"] = WORKSPACE
    bundle["payloadHash"] = payload_hash_for_policy_bundle_v2(bundle)
    bundle["bundleHash"] = computed_policy_bundle_v2_hash(bundle)
    verifier = bundle["verifier"]
    assert isinstance(verifier, dict)
    verifier["signature"] = base64.b64encode(
        key.sign(
            canonical_policy_bundle_v2_payload(bundle),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    ).decode("ascii")
    return bundle, verification.to_dict()


def test_pause_keeps_pending_cursor_while_two_real_signed_policies_and_ack_progress(
    store: GuardStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    first, verification = signed_bundle(key, version=8)
    second, _ = signed_bundle(key, version=9)
    store.set_sync_payload("policy_bundle_keyring", {"keys": [verification]}, NOW)
    paused = wire(2, sync=False)
    accept_workspace_preferences(store, paused, workspace_id=WORKSPACE)
    before = cursor(store)
    requests = respond(
        monkeypatch, {"workspacePreferences": paused, "receiptSyncAccepted": False, "policyBundle": first}
    )
    first_summary = runner.sync_receipts(store, auth_context=AUTH)
    assert requests[0]["receipts"] == []
    assert store.get_sync_payload("policy_bundle") == first
    first_ack = store.get_sync_payload("policy_bundle_ack")
    assert isinstance(first_ack, dict)
    assert first_ack["status"] == "applied" and first_ack["bundleHash"] == first["bundleHash"]
    assert first_summary["telemetry_status"] == "paused"
    requests = respond(
        monkeypatch, {"workspacePreferences": paused, "receiptSyncAccepted": False, "policyBundle": second}
    )
    runner.sync_receipts(store, auth_context=AUTH)
    context = requests[0]["syncContext"]
    assert isinstance(context, dict)
    sent_ack = context["policyBundleAcknowledgementV2"]
    assert isinstance(sent_ack, dict)
    assert sent_ack["bundleHash"] == first["bundleHash"]
    assert store.get_sync_payload("policy_bundle") == second
    second_ack = store.get_sync_payload("policy_bundle_ack")
    assert isinstance(second_ack, dict)
    assert second_ack["status"] == "applied" and second_ack["bundleHash"] == second["bundleHash"]
    assert cursor(store) == before
    assert len(store.list_receipts()) == 1


def test_remote_resume_does_not_restore_withdrawn_local_consent(
    store: GuardStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    accept_workspace_preferences(store, wire(2, sync=False), workspace_id=WORKSPACE)
    (store.guard_home / "config.toml").write_text("sync = false\ntelemetry = false\n")
    requests = respond(monkeypatch, {"workspacePreferences": wire(3), "receiptSyncAccepted": False})
    runner.sync_receipts(store, auth_context=AUTH)
    assert requests[0]["receipts"] == []
    current = read_workspace_preferences(store)
    assert current is not None and current.sync_enabled
    requests = respond(monkeypatch, {"workspacePreferences": wire(3), "receiptSyncAccepted": True})
    runner.sync_receipts(store, auth_context=AUTH)
    assert requests[0]["receipts"] == [] and cursor(store) is None
    (store.guard_home / "config.toml").write_text("sync = true\ntelemetry = false\n")
    runner.sync_receipts(store, auth_context=AUTH)
    assert cursor(store) is not None


def test_direct_optional_calls_do_not_write_pending_progress_when_paused(
    store: GuardStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    accept_workspace_preferences(store, wire(2, sync=False), workspace_id=WORKSPACE)
    store.add_event("policy_warn", {"source": "disposable-fixture"}, NOW)
    store.add_guard_event_v1(
        GuardEventV1(
            event_id="pending-source-event",
            idempotency_key="pending-source-event",
            event_type="runtime.session",
            source="edge",
            occurred_at=NOW,
            workspace_id=WORKSPACE,
        )
    )
    pending = store.list_guard_events_v1(uploaded=False)
    assert any(event["event_id"] == "pending-source-event" for event in pending)
    store.set_sync_payload("pain_signal_cursor", {"last_event_id": 0}, NOW)
    store.set_sync_payload("guard_events_v1_summary", {"status": "pending", "pending_events": len(pending)}, NOW)
    before_pain = store.get_sync_payload("pain_signal_cursor")
    before_events = store.get_sync_payload("guard_events_v1_summary")

    def forbidden(**kwargs):
        raise AssertionError("paused optional transport must not run")

    monkeypatch.setattr(runner, "_urlopen_json_with_timeout_retry", forbidden)
    assert runner.sync_pain_signals(store, auth_context=AUTH) == 0
    assert runner.sync_guard_events(store, auth_context=AUTH)["sync_reason"] == "optional_upload_paused"
    assert store.get_sync_payload("pain_signal_cursor") == before_pain
    assert store.get_sync_payload("guard_events_v1_summary") == before_events
    assert store.list_guard_events_v1(uploaded=False) == pending


def test_withdrawal_between_actual_batches_stops_optional_rows_but_keeps_control_poll(
    store: GuardStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    accept_workspace_preferences(store, wire(), workspace_id=WORKSPACE)
    _store_blocked_command_receipt(store, "second-pending-receipt")
    monkeypatch.setattr(runner, "_RECEIPT_SYNC_BATCH_SIZE", 1)
    requests: list[dict[str, object]] = []

    def receive(**kwargs):
        request = kwargs["request"]
        body = json.loads(request.data)
        requests.append(body)
        if len(requests) == 1:
            (store.guard_home / "config.toml").write_text("sync = false\ntelemetry = false\n")
        return {
            "syncedAt": NOW,
            "receiptsStored": int(bool(body["receipts"])),
            "workspacePreferences": wire(),
            "receiptSyncAccepted": True,
        }

    monkeypatch.setattr(runner, "_urlopen_json_with_timeout_retry", receive)
    runner.sync_receipts(store, auth_context=AUTH)
    assert len(requests) == 2
    first_receipts = requests[0]["receipts"]
    assert isinstance(first_receipts, list) and len(first_receipts) == 1
    assert requests[1]["receipts"] == []
    state = cursor(store)
    assert isinstance(state, dict)
    sent_receipt = first_receipts[0]
    assert isinstance(sent_receipt, dict)
    # Exactly the first accepted local row advances, while the other remains pending.
    rows = store.list_receipts_since_rowid(after_rowid=state["last_rowid"], limit=10)
    assert len(rows) == 1


@pytest.mark.parametrize("mutation", ["withdraw", "workspace"])
def test_authentication_retry_rechecks_scope_and_local_consent(
    store: GuardStore,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    import urllib.error
    from email.message import Message

    from tests.test_workspace_preferences import OTHER

    accept_workspace_preferences(store, wire(), workspace_id=WORKSPACE)
    attempts: list[dict[str, object]] = []

    def resolve(_store, *, force_refresh=False):
        if force_refresh:
            if mutation == "withdraw":
                (store.guard_home / "config.toml").write_text("sync = false\ntelemetry = false\n")
            else:
                store.set_sync_payload("oauth_local_credentials", {"workspace_id": OTHER}, NOW)
        return AUTH

    def receive(**kwargs):
        attempts.append(json.loads(kwargs["request"].data))
        if len(attempts) == 1:
            raise urllib.error.HTTPError(str(AUTH["sync_url"]), 401, "expired", Message(), None)
        return {"syncedAt": NOW, "receiptsStored": 0, "workspacePreferences": wire(), "receiptSyncAccepted": True}

    monkeypatch.setattr(runner, "_resolve_guard_sync_auth_context", resolve)
    monkeypatch.setattr(runner, "_urlopen_json_with_timeout_retry", receive)
    if mutation == "workspace":
        with pytest.raises(ValueError, match="scope_changed"):
            runner.sync_receipts(store)
        assert len(attempts) == 1
    else:
        runner.sync_receipts(store)
        assert len(attempts) == 2 and attempts[1]["receipts"] == []
    assert cursor(store) is None


def test_each_request_preparation_uses_the_current_redaction_floor(store: GuardStore) -> None:
    from codex_plugin_scanner.guard.runtime.workspace_optional_sync import prepare_receipt_batch

    accept_workspace_preferences(store, wire(redaction="none"), workspace_id=WORKSPACE)
    (store.guard_home / "config.toml").write_text('sync = true\nreceipt_redaction_level = "none"\n')
    rows = store.list_receipts()

    def encode(batch, level):
        return [
            {"id": row["receipt_id"], "content": "withheld" if level == "full" else "disposable-detail"}
            for row in batch
        ]

    _, first, _ = prepare_receipt_batch(
        store, workspace_id=WORKSPACE, receipt_batch=rows, sync_context={}, serialize=encode
    )
    (store.guard_home / "config.toml").write_text('sync = true\nreceipt_redaction_level = "full"\n')
    _, second, _ = prepare_receipt_batch(
        store, workspace_id=WORKSPACE, receipt_batch=rows, sync_context={}, serialize=encode
    )
    assert b"disposable-detail" in first and b"disposable-detail" not in second


def test_initial_cursor_never_skips_unsent_rows_after_first_batch_withdrawal(
    store: GuardStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.models import GuardReceipt

    accept_workspace_preferences(store, wire(), workspace_id=WORKSPACE)
    for index in range(50):
        store.add_receipt(
            GuardReceipt(
                receipt_id=f"ordered-pending-{index}",
                timestamp=f"2026-09-18T00:00:{index:02d}Z",
                harness="codex",
                artifact_id=f"command:{index}",
                artifact_hash=f"hash-{index}",
                policy_decision="block",
                capabilities_summary="source fixture",
                changed_capabilities=(),
                provenance_summary="disposable source fixture",
            )
        )
    assert len(store.list_receipts(limit=100)) == 51
    sent: list[str] = []
    calls = 0

    def receive(**kwargs):
        nonlocal calls
        calls += 1
        body = json.loads(kwargs["request"].data)
        rows = body["receipts"]
        for row in rows:
            sent.append(row["receiptId"])
        if calls == 1:
            (store.guard_home / "config.toml").write_text("sync = false\ntelemetry = false\n")
        return {
            "syncedAt": NOW,
            "receiptsStored": len(rows),
            "workspacePreferences": wire(),
            "receiptSyncAccepted": True,
        }

    monkeypatch.setattr(runner, "_urlopen_json_with_timeout_retry", receive)
    runner.sync_receipts(store, auth_context=AUTH)
    state = cursor(store)
    assert isinstance(state, dict)
    remaining = store.list_receipts_since_rowid(after_rowid=state["last_rowid"], limit=100)
    assert len(sent) == 50 and len(remaining) == 1, "an unsent row must remain beyond the durable cursor"
    (store.guard_home / "config.toml").write_text("sync = true\ntelemetry = false\n")
    runner.sync_receipts(store, auth_context=AUTH)
    assert len(sent) == len(set(sent)) == 51
    final = cursor(store)
    assert isinstance(final, dict)
    assert store.list_receipts_since_rowid(after_rowid=final["last_rowid"], limit=100) == []
