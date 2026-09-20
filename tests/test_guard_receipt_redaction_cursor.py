from __future__ import annotations

import io
import json
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timezone
from email.message import Message
from pathlib import Path
from typing import Any, cast

import pytest

import codex_plugin_scanner.guard.runtime.runner as runner
from codex_plugin_scanner.guard import policy_bundle_trusted_keys as trusted_keys_module
from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.config import update_guard_settings
from codex_plugin_scanner.guard.models import GuardReceipt
from codex_plugin_scanner.guard.oauth_connection_authority import OAuthConnectionSnapshot
from codex_plugin_scanner.guard.policy_bundle_parser import (
    computed_policy_bundle_hash,
    payload_hash_for_policy_bundle,
)
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import (
    load_policy_bundle_verification_keys,
    migrate_legacy_policy_bundle_anchors,
)
from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope
from codex_plugin_scanner.guard.runtime.local_request_snapshots import (
    _resolve_cloud_receipt_redaction_level as _resolve_snapshot_redaction_level,
)
from codex_plugin_scanner.guard.runtime.runner import (
    _RECEIPT_COMMAND_DETAIL_BACKFILL_MARKER,
    _RELAXED_RECEIPT_REDACTION_RESYNC_MARKER,
    _ensure_relaxed_receipt_redaction_resync,
    _persist_cloud_receipt_redaction_level,
    _receipt_sync_cursor_rowids_from_batch,
    _receipt_sync_rows_with_command_detail_backfill,
    _resolve_cloud_receipt_redaction_level,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.policy_bundle_signing_helpers import (
    policy_bundle_test_keyring,
    policy_bundle_test_verification_key,
    sign_policy_bundle,
)


def _store_blocked_command_receipt(store: GuardStore, receipt_id: str = "guard-receipt-sync-auth") -> None:
    store.add_receipt(
        GuardReceipt(
            receipt_id=receipt_id,
            timestamp=datetime(2026, 4, 15, tzinfo=timezone.utc).isoformat(),
            harness="codex",
            artifact_id="codex:tool-action:sync-auth",
            artifact_hash="hash-sync-auth",
            policy_decision="block",
            capabilities_summary="tool action request",
            changed_capabilities=(),
            provenance_summary="",
            user_override=None,
            artifact_name="bash",
            source_scope="project",
            diff_summary=None,
            approval_source=None,
            approval_request_id=None,
            scanner_evidence=(),
            browser_intent=None,
        ),
        action_envelope=GuardActionEnvelope(
            schema_version=1,
            action_id="action-sync-auth",
            harness="codex",
            event_name="PreToolUse",
            action_type="shell_command",
            workspace=None,
            workspace_hash="workspace",
            tool_name="bash",
            command="cd repo && npx vitest run example.test.ts --reporter=verbose",
            prompt_excerpt=None,
            prompt_text=None,
            target_paths=(),
            network_hosts=(),
            mcp_server=None,
            mcp_tool=None,
            package_manager=None,
            package_name=None,
            package_intent_kind=None,
            package_targets=(),
        ),
    )


def _sync_unauthorized_error() -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        "https://hol.org/api/guard/receipts/sync",
        401,
        "Unauthorized",
        cast(Message, cast(object, {})),
        None,
    )


def _signed_redaction_policy_bundle(
    *,
    level: str | None,
    bundle_version: str = "policy-2026-07-01.1",
    issued_at: str = "2026-07-01T00:00:00Z",
    workspace_id: str = "workspace-1",
) -> dict[str, object]:
    payload: dict[str, object] = {
        "contractVersion": "guard-policy-bundle.v1",
        "bundleVersion": bundle_version,
        "bundleHash": "",
        "issuedAt": issued_at,
        "expiresAt": None,
        "verifier": {},
        "rolloutState": "enforcing",
        "policyDefaults": {
            "mode": "enforce",
            "defaultAction": "block",
            "unknownPublisherAction": "review",
            "changedHashAction": "require-reapproval",
            "newNetworkDomainAction": "block",
            "subprocessAction": "block",
            "telemetryEnabled": False,
            "syncEnabled": True,
        },
        "rules": [],
        "acknowledgements": [],
    }
    if level is not None:
        payload["receiptRedactionLevel"] = level
    return sign_policy_bundle(payload, workspace_id=workspace_id)


def _seed_policy_bundle_trust(store: GuardStore) -> None:
    store.set_sync_payload(
        "oauth_local_credentials",
        {"workspace_id": "workspace-1"},
        "2026-07-01T00:00:00Z",
    )
    store.set_sync_payload(
        "policy_bundle_keyring",
        policy_bundle_test_keyring(workspace_id="workspace-1"),
        "2026-07-01T00:00:00Z",
    )


def test_invalid_cached_bundle_cannot_retain_relaxed_receipt_redaction(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_policy_bundle_trust(store)
    bundle = _signed_redaction_policy_bundle(level="none")
    bundle["verifier"] = {
        "algorithm": "sha256",
        "keyId": "attacker-recomputed-digest",
        "signature": None,
    }
    bundle["bundleHash"] = computed_policy_bundle_hash(bundle)
    bundle["payloadHash"] = payload_hash_for_policy_bundle(bundle)
    bundle["verifier"]["signature"] = bundle["payloadHash"]
    store.set_sync_payload("policy_bundle", bundle, "2026-07-01T00:00:00Z")
    store.set_sync_payload(
        "cloud_receipt_redaction_level",
        {"level": "none", "updated_at": "2026-07-01T00:00:00Z"},
        "2026-07-01T00:00:00Z",
    )

    assert _resolve_cloud_receipt_redaction_level(store) == "full"
    assert _resolve_snapshot_redaction_level(store) == "full"


def test_valid_signed_bundle_can_relax_receipt_redaction(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_policy_bundle_trust(store)
    store.set_sync_payload(
        "policy_bundle",
        _signed_redaction_policy_bundle(level="none"),
        "2026-07-01T00:00:00Z",
    )

    assert _resolve_cloud_receipt_redaction_level(store) == "none"
    assert _resolve_snapshot_redaction_level(store) == "none"


def test_sync_migrates_legacy_anchor_and_restores_cloud_redaction_choice(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_policy_bundle_trust(store)
    policy_key = policy_bundle_test_verification_key(workspace_id="workspace-1")
    legacy_key = policy_key.to_dict()
    for field in ("purpose", "workspaceId", "validFrom"):
        legacy_key.pop(field)
    store.set_sync_payload(
        "policy_bundle_keyring",
        {"keys": [legacy_key], "workspace_id": "workspace-1"},
        "2026-07-01T00:00:00Z",
    )
    assert migrate_legacy_policy_bundle_anchors(
        stored_keyring={"keys": [legacy_key], "workspace_id": "workspace-1"},
        sync_keys=(policy_key,),
        expected_workspace_id="workspace-1",
    ) == (policy_key,)
    monkeypatch.setattr(
        trusted_keys_module,
        "managed_policy_bundle_verification_keys",
        lambda: (False, ()),
    )
    monkeypatch.setattr(
        runner,
        "_urlopen_json_with_timeout_retry",
        lambda **_kwargs: {
            "syncedAt": "2026-07-01T00:00:01Z",
            "receiptsStored": 0,
            "policyBundle": _signed_redaction_policy_bundle(level="none"),
            "policyBundleVerificationKeys": [policy_key.to_dict()],
        },
    )
    monkeypatch.setattr(runner, "sync_pain_signals", lambda _store, auth_context=None: 0)
    monkeypatch.setattr(
        runner,
        "sync_guard_events",
        lambda _store, auth_context=None: {"accepted": 0, "statuses": []},
    )

    auth_context: dict[str, object] = {
        "sync_url": "https://hol.org/api/guard/receipts/sync",
        "access_token": "test-access-token",
        "dpop_key_material": None,
    }
    runner.sync_receipts(store, auth_context=auth_context)

    assert store.get_sync_payload("policy_bundle_last_error") == {}
    assert _resolve_cloud_receipt_redaction_level(store) == "none"
    persisted_keyring = store.get_sync_payload("policy_bundle_keyring")
    assert isinstance(persisted_keyring, dict)
    assert persisted_keyring["contractVersion"] == "guard-policy-keyring.v1"
    assert persisted_keyring["purpose"] == "policy_bundle"
    assert persisted_keyring["workspaceId"] == "workspace-1"
    assert load_policy_bundle_verification_keys(
        persisted_keyring,
        require_keyring_contract=True,
    ) == (policy_key,)


def test_signed_receipt_redaction_authority_can_clear_and_relax_again(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.receipt_sync_authority import ReceiptSyncCompletion
    from tests.support.optional_uploads import (
        OPTIONAL_UPLOAD_WORKSPACE,
        confirm_legacy_optional_uploads,
        seed_optional_upload_source,
    )

    store = GuardStore(tmp_path / "guard-home")
    seed_optional_upload_source(store, monkeypatch)
    update_guard_settings(
        store.guard_home,
        {"sync": True, "telemetry": False, "receipt_redaction_level": "none"},
        cloud_sync_entitled=True,
    )
    auth_context = confirm_legacy_optional_uploads(store)
    store.set_sync_payload(
        "policy_bundle_keyring",
        policy_bundle_test_keyring(workspace_id=OPTIONAL_UPLOAD_WORKSPACE),
        "2026-07-01T00:00:00Z",
    )
    clock = {"now": "2026-07-01T00:00:00Z"}
    monkeypatch.setattr(runner, "_now", lambda: clock["now"])
    responses = iter(
        [
            {
                "syncedAt": "2026-07-01T00:00:01Z",
                "receiptsStored": 0,
                "policyBundle": _signed_redaction_policy_bundle(
                    workspace_id=OPTIONAL_UPLOAD_WORKSPACE,
                    level="none",
                    bundle_version="policy-2026-07-01.1",
                    issued_at="2026-07-01T00:00:01Z",
                ),
            },
            {
                "syncedAt": "2026-07-01T00:00:02Z",
                "receiptsStored": 0,
                "policyBundle": _signed_redaction_policy_bundle(
                    workspace_id=OPTIONAL_UPLOAD_WORKSPACE,
                    level=None,
                    bundle_version="policy-2026-07-01.2",
                    issued_at="2026-07-01T00:00:02Z",
                ),
            },
            {
                "syncedAt": "2026-07-01T00:00:03Z",
                "receiptsStored": 0,
                "policyBundle": _signed_redaction_policy_bundle(
                    workspace_id=OPTIONAL_UPLOAD_WORKSPACE,
                    level="none",
                    bundle_version="policy-2026-07-01.3",
                    issued_at="2026-07-01T00:00:03Z",
                ),
            },
        ]
    )

    class Response(io.BytesIO):
        status = 200

        def __init__(self, payload: Mapping[str, object]) -> None:
            super().__init__(json.dumps(payload).encode("utf-8"))
            self.headers = Message()
            self.headers["Content-Type"] = "application/json"

        def getcode(self) -> int:
            return self.status

    def transport(request: urllib.request.Request, *, timeout: float) -> Response:
        assert request.full_url.endswith("/api/guard/receipts/sync")
        assert timeout == runner._SYNC_HTTP_TIMEOUT_SECONDS
        assert request.data is not None
        assert isinstance(request.data, bytes)
        assert json.loads(request.data)["receipts"] == []
        return Response(next(responses))

    monkeypatch.setattr(runner, "managed_urlopen", transport)
    actual_complete = runner.ReceiptUploadPreparation.complete
    completion_observations: list[dict[str, object]] = []

    def complete(
        preparation: runner.ReceiptUploadPreparation,
        payload: object,
        *,
        candidate: runner.ReceiptProgressCandidate,
    ) -> ReceiptSyncCompletion | None:
        attempt = preparation.attempt
        assert attempt is not None
        previous = store.get_sync_payload("policy_bundle")
        result = actual_complete(preparation, payload, candidate=candidate)
        completion_observations.append(
            {
                "rows_sent": attempt.rows_sent,
                "authorized_empty_exhaustion": attempt.authorized_empty_exhaustion,
                "redaction_level": attempt.redaction_level,
                "prior_bundle_version": previous.get("bundleVersion") if isinstance(previous, dict) else None,
                "cursor_rowid": candidate.cursor_rowid,
                "backfill": None if candidate.backfill is None else candidate.backfill.to_payload(),
                "receipt_acknowledged": result is not None and result.receipt_acknowledged,
                "progress_committed": result is not None and result.progress_committed,
            }
        )
        return result

    monkeypatch.setattr(runner.ReceiptUploadPreparation, "complete", complete)
    monkeypatch.setattr(runner, "sync_pain_signals", lambda _store, auth_context=None: 0)
    monkeypatch.setattr(
        runner,
        "sync_guard_events",
        lambda _store, auth_context=None: {"accepted": 0, "statuses": []},
    )
    runner.sync_receipts(store, auth_context=auth_context)
    committed = store.get_sync_payload("policy_bundle")
    assert isinstance(committed, dict)
    assert committed["bundleVersion"] == "policy-2026-07-01.1"
    assert committed["receiptRedactionLevel"] == "none"
    assert committed["bundleHash"] == computed_policy_bundle_hash(committed)

    assert _resolve_cloud_receipt_redaction_level(store) == "none"
    assert _resolve_snapshot_redaction_level(store) == "none"
    assert store.get_sync_payload(_RELAXED_RECEIPT_REDACTION_RESYNC_MARKER) == {
        "level": "none",
        "updated_at": "2026-07-01T00:00:01Z",
    }
    store.set_sync_payload(
        "receipt_sync_cursor",
        {"last_rowid": 41, "synced_at": "2026-07-01T00:00:01Z"},
        "2026-07-01T00:00:01Z",
    )
    store.set_sync_payload(
        _RECEIPT_COMMAND_DETAIL_BACKFILL_MARKER,
        {
            "level": "none",
            "updated_at": "2026-07-01T00:00:01Z",
            "complete": True,
        },
        "2026-07-01T00:00:01Z",
    )

    # The user explicitly tightens local privacy before requesting the next policy.
    update_guard_settings(
        store.guard_home,
        {"receipt_redaction_level": "full"},
        cloud_sync_entitled=True,
    )
    clock["now"] = "2026-07-01T00:00:01.500Z"
    runner.sync_receipts(store, auth_context=auth_context)
    committed = store.get_sync_payload("policy_bundle")
    assert isinstance(committed, dict)
    assert committed["bundleVersion"] == "policy-2026-07-01.2"
    assert "receiptRedactionLevel" not in committed
    assert committed["bundleHash"] == computed_policy_bundle_hash(committed)

    assert _resolve_cloud_receipt_redaction_level(store) == "full"
    assert _resolve_snapshot_redaction_level(store) == "full"
    assert store.get_sync_payload("cloud_receipt_redaction_level") == {
        "level": "full",
        "updated_at": "2026-07-01T00:00:02Z",
    }
    assert store.get_sync_payload(_RELAXED_RECEIPT_REDACTION_RESYNC_MARKER) is None
    assert store.get_sync_payload(_RECEIPT_COMMAND_DETAIL_BACKFILL_MARKER) is None
    # Zero sent receipts preserve upload progress despite newer privacy metadata.
    assert store.get_sync_payload("receipt_sync_cursor") == {
        "last_rowid": 41,
        "synced_at": "2026-07-01T00:00:01Z",
    }

    # Explicit local consent permits relaxation before this final request.
    update_guard_settings(
        store.guard_home,
        {"receipt_redaction_level": "none"},
        cloud_sync_entitled=True,
    )
    clock["now"] = "2026-07-01T00:00:03Z"
    runner.sync_receipts(store, auth_context=auth_context)
    committed = store.get_sync_payload("policy_bundle")
    assert isinstance(committed, dict)
    assert committed["bundleVersion"] == "policy-2026-07-01.3"
    assert committed["receiptRedactionLevel"] == "none"
    assert committed["bundleHash"] == computed_policy_bundle_hash(committed)

    assert _resolve_cloud_receipt_redaction_level(store) == "none"
    assert _resolve_snapshot_redaction_level(store) == "none"
    assert store.get_sync_payload("receipt_sync_cursor") == {
        "last_rowid": 0,
        "synced_at": "2026-07-01T00:00:03Z",
        "reason": "cloud_receipt_redaction_level_relaxed",
        "receipt_redaction_level": "none",
    }
    assert store.get_sync_payload(_RELAXED_RECEIPT_REDACTION_RESYNC_MARKER) == {
        "level": "none",
        "updated_at": "2026-07-01T00:00:03Z",
    }
    assert len(completion_observations) == 3
    assert completion_observations[1]["progress_committed"] is False
    assert completion_observations[2] == {
        "rows_sent": 0,
        "authorized_empty_exhaustion": True,
        "redaction_level": "none",
        "prior_bundle_version": "policy-2026-07-01.2",
        "cursor_rowid": None,
        "backfill": {
            "before_rowid": None,
            "complete": True,
            "days": 30,
            "level": "none",
            "limit": 200,
            "queried": 0,
            "receipts": 0,
            "updated_at": "2026-07-01T00:00:03Z",
        },
        "receipt_acknowledged": True,
        "progress_committed": True,
    }
    # This actual empty scan completed under the pre-request privacy authority.
    assert store.get_sync_payload(_RECEIPT_COMMAND_DETAIL_BACKFILL_MARKER) == {
        "level": "none",
        "updated_at": "2026-07-01T00:00:03Z",
        "days": 30,
        "limit": 200,
        "receipts": 0,
        "queried": 0,
        "before_rowid": None,
        "complete": True,
    }


def test_cloud_receipt_redaction_relaxation_resets_receipt_cursor_before_storing_level(tmp_path) -> None:
    store = GuardStore(tmp_path)
    writes: list[tuple[str, Mapping[str, object] | Sequence[object], str]] = []
    original_set_sync_payload = store.set_sync_payload

    def record_set_sync_payload(state_key: str, payload: Mapping[str, object] | Sequence[object], now: str) -> None:
        writes.append((state_key, payload, now))
        original_set_sync_payload(state_key, payload, now)

    store.set_sync_payload = record_set_sync_payload  # type: ignore[method-assign]
    original_set_sync_payload(
        "receipt_sync_cursor",
        {"last_rowid": 17, "synced_at": "2026-04-15T00:00:00Z"},
        "2026-04-15T00:00:00Z",
    )

    _persist_cloud_receipt_redaction_level(
        store,
        level="none",
        synced_at="2026-04-15T00:01:00Z",
    )

    assert [write[0] for write in writes] == [
        "receipt_sync_cursor",
        "cloud_receipt_redaction_level",
        _RELAXED_RECEIPT_REDACTION_RESYNC_MARKER,
    ]
    assert store.get_sync_payload("cloud_receipt_redaction_level") == {
        "level": "none",
        "updated_at": "2026-04-15T00:01:00Z",
    }
    assert store.get_sync_payload(_RELAXED_RECEIPT_REDACTION_RESYNC_MARKER) == {
        "level": "none",
        "updated_at": "2026-04-15T00:01:00Z",
    }
    assert store.get_sync_payload("receipt_sync_cursor") == {
        "last_rowid": 0,
        "synced_at": "2026-04-15T00:01:00Z",
        "reason": "cloud_receipt_redaction_level_relaxed",
        "receipt_redaction_level": "none",
    }


def test_cloud_receipt_redaction_tightening_keeps_receipt_cursor(tmp_path) -> None:
    store = GuardStore(tmp_path)
    store.set_sync_payload(
        "cloud_receipt_redaction_level",
        {"level": "none", "updated_at": "2026-04-15T00:00:00Z"},
        "2026-04-15T00:00:00Z",
    )
    store.set_sync_payload(
        "receipt_sync_cursor",
        {"last_rowid": 17, "synced_at": "2026-04-15T00:00:00Z"},
        "2026-04-15T00:00:00Z",
    )

    _persist_cloud_receipt_redaction_level(
        store,
        level="full",
        synced_at="2026-04-15T00:01:00Z",
    )

    assert store.get_sync_payload("cloud_receipt_redaction_level") == {
        "level": "full",
        "updated_at": "2026-04-15T00:01:00Z",
    }
    assert store.get_sync_payload("receipt_sync_cursor") == {
        "last_rowid": 17,
        "synced_at": "2026-04-15T00:00:00Z",
    }


def test_command_detail_backfill_rows_do_not_advance_receipt_cursor() -> None:
    rowids = _receipt_sync_cursor_rowids_from_batch(
        [
            {"receipt_id": "cursor-1", "receipt_rowid": 101},
            {"receipt_id": "backfill-1", "receipt_rowid": 5000},
            {"receipt_id": "cursor-2", "receipt_rowid": 102},
        ],
        cursor_receipt_ids={"cursor-1", "cursor-2"},
    )

    assert rowids == [101, 102]


def test_receipt_sync_401_with_explicit_auth_context_keeps_cursor_and_backfill_marker(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path)
    _store_blocked_command_receipt(store)

    def reject_sync(**_kwargs: object) -> dict[str, object]:
        raise _sync_unauthorized_error()

    monkeypatch.setattr(runner, "_urlopen_json_with_timeout_retry", reject_sync)

    with pytest.raises(runner.GuardSyncAuthorizationExpiredError):
        runner.sync_receipts(
            store,
            auth_context={
                "sync_url": "https://hol.org/api/guard/receipts/sync",
                "access_token": "stale",
            },
        )

    assert store.get_sync_payload("receipt_sync_cursor") is None
    assert store.get_sync_payload(_RECEIPT_COMMAND_DETAIL_BACKFILL_MARKER) is None


def test_receipt_sync_401_forces_oauth_refresh_before_retry(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests.oauth_refresh_connection_support import _token
    from tests.support.optional_uploads import (
        confirm_legacy_optional_uploads,
        seed_optional_upload_source,
    )

    store = GuardStore(tmp_path)
    seed_optional_upload_source(store, monkeypatch, access_token="stale")
    update_guard_settings(
        store.guard_home,
        {"sync": True, "telemetry": False, "receipt_redaction_level": "full"},
        cloud_sync_entitled=True,
    )
    confirm_legacy_optional_uploads(store)
    _store_blocked_command_receipt(store)
    refresh_flags: list[bool] = []
    post_attempts = 0
    actual_resolver = runner._resolve_guard_sync_auth_context
    initial_source = store.capture_oauth_connection()
    assert initial_source is not None
    initial_credentials = initial_source.credentials()
    fresh_token = _token({**initial_credentials, "device_id": initial_credentials.get("device_id")})

    def resolve_auth_context(
        _store: GuardStore,
        *,
        allow_primary_repair: bool = True,
        force_refresh: bool = False,
        required_connection: OAuthConnectionSnapshot | None = None,
        validate_request: Callable[[], None] | None = None,
        connection_observer: Callable[[OAuthConnectionSnapshot], None] | None = None,
    ) -> dict[str, object]:
        refresh_flags.append(force_refresh)
        return actual_resolver(
            _store,
            allow_primary_repair=allow_primary_repair,
            force_refresh=force_refresh,
            required_connection=required_connection,
            validate_request=validate_request,
            connection_observer=connection_observer,
        )

    class Response(io.BytesIO):
        status = 200

        def __init__(self, payload: dict[str, object]) -> None:
            super().__init__(json.dumps(payload).encode("utf-8"))
            self.headers = Message()
            self.headers["Content-Type"] = "application/json"

        def getcode(self) -> int:
            return self.status

    def post_sync(request: urllib.request.Request, *, timeout: float) -> Response:
        nonlocal post_attempts
        assert timeout == runner._SYNC_HTTP_TIMEOUT_SECONDS
        if request.full_url == runner.resolve_guard_oauth_client_config("https://hol.org").token_endpoint:
            assert post_attempts == 1
            assert request.data is not None
            assert isinstance(request.data, bytes)
            assert b"grant_type=refresh_token" in request.data
            return Response({"access_token": fresh_token, "token_type": "DPoP", "expires_in": 3600})
        assert request.full_url.endswith("/api/guard/receipts/sync")
        assert request.data is not None
        assert isinstance(request.data, bytes)
        wire = json.loads(request.data)
        assert len(wire["receipts"]) == 1
        post_attempts += 1
        assert request.get_header("Authorization") == (
            "Bearer stale" if post_attempts == 1 else f"Bearer {fresh_token}"
        )
        if post_attempts == 1:
            raise _sync_unauthorized_error()
        return Response({"syncedAt": "2026-04-15T00:01:00Z", "receiptsStored": 1})

    monkeypatch.setattr(runner, "_resolve_guard_sync_auth_context", resolve_auth_context)
    monkeypatch.setattr(runner, "managed_urlopen", post_sync)

    runner.sync_receipts(store)

    assert refresh_flags[:2] == [False, True]
    assert post_attempts >= 2
    assert store.get_sync_payload("receipt_sync_cursor") == {
        "last_rowid": 1,
        "synced_at": "2026-04-15T00:01:00Z",
    }
    current_source = store.capture_oauth_connection()
    assert current_source is not None
    assert initial_source.same_authority(current_source)
    assert current_source.credentials()["access_token"] == fresh_token


def test_forced_oauth_refresh_persists_same_refresh_token_access_token(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path, allow_system_keyring=False)
    key = generate_dpop_key_pair()
    credentials: dict[str, Any] = {
        "issuer": "https://hol.org",
        "client_id": "guard-local-daemon",
        "refresh_token": "same-refresh-token",
        "access_token": "stale-access-token",
        "access_token_expires_at": "2099-04-15T00:30:00+00:00",
        "dpop_private_key_pem": key.private_key_pem,
        "dpop_public_jwk": key.public_jwk,
        "dpop_public_jwk_thumbprint": key.public_jwk_thumbprint,
    }
    store.set_oauth_local_credentials(**credentials, now="2026-04-15T00:00:00+00:00")
    persisted: list[dict[str, object]] = []

    class OAuthClient:
        issuer = "https://hol.org"
        token_endpoint = "https://hol.org/api/guard/oauth/token"

    def fake_refresh(**_kwargs: object) -> dict[str, object]:
        return {
            "access_token": "fresh-access-token",
            "access_token_expires_at": "2026-04-15T00:30:00+00:00",
            "refresh_token": "same-refresh-token",
        }

    monkeypatch.setattr(runner, "resolve_guard_oauth_client_config", lambda _issuer: OAuthClient())
    monkeypatch.setattr(runner, "_refresh_guard_oauth_access_token", fake_refresh)
    actual_set = store.set_oauth_local_credentials

    def recording_set(**kwargs: Any):
        persisted.append(kwargs)
        return actual_set(**kwargs)

    monkeypatch.setattr(store, "set_oauth_local_credentials", recording_set)

    auth_context = runner._resolve_guard_sync_auth_context_from_oauth_credentials(
        store,
        credentials,
        force_refresh=True,
    )

    assert auth_context["access_token"] == "fresh-access-token"
    assert persisted
    assert persisted[0]["refresh_token"] == "same-refresh-token"
    assert persisted[0]["access_token"] == "fresh-access-token"
    assert persisted[0]["access_token_expires_at"] == "2026-04-15T00:30:00+00:00"
    assert persisted[0]["force_primary_secret_rewrite"] is True


def test_oauth_local_credentials_forwards_primary_rewrite_flag(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path)
    captured: list[dict[str, object]] = []

    monkeypatch.setattr(store, "_set_oauth_local_credentials_unlocked", lambda **kwargs: captured.append(kwargs))

    store.set_oauth_local_credentials(
        issuer="http://127.0.0.1:3000",
        client_id="guard-local-daemon",
        refresh_token="refresh-token",
        dpop_private_key_pem="private-key",
        dpop_public_jwk={"kty": "EC"},
        dpop_public_jwk_thumbprint="thumbprint",
        now="2026-04-15T00:01:00Z",
        access_token="access-token",
        access_token_expires_at="2026-04-15T00:30:00Z",
        force_primary_secret_rewrite=True,
    )

    assert captured
    assert captured[0]["force_primary_secret_rewrite"] is True


def test_relaxed_redaction_sync_adds_recent_blocked_command_detail_backfill(tmp_path) -> None:
    store = GuardStore(tmp_path)
    store.add_receipt(
        GuardReceipt(
            receipt_id="guard-receipt-backfill",
            timestamp=datetime.now(timezone.utc).isoformat(),
            harness="codex",
            artifact_id="codex:tool-action:backfill",
            artifact_hash="hash-backfill",
            policy_decision="block",
            capabilities_summary="tool action request",
            changed_capabilities=(),
            provenance_summary="",
            user_override=None,
            artifact_name="bash",
            source_scope="project",
            diff_summary=None,
            approval_source=None,
            approval_request_id=None,
            scanner_evidence=(),
            browser_intent=None,
        ),
        action_envelope=GuardActionEnvelope(
            schema_version=1,
            action_id="action-backfill",
            harness="codex",
            event_name="PreToolUse",
            action_type="shell_command",
            workspace=None,
            workspace_hash="workspace",
            tool_name="bash",
            command="cd repo && npx vitest run example.test.ts --reporter=verbose",
            prompt_excerpt=None,
            prompt_text=None,
            target_paths=(),
            network_hosts=(),
            mcp_server=None,
            mcp_tool=None,
            package_manager=None,
            package_name=None,
            package_intent_kind=None,
            package_targets=(),
            pre_execution_result="block",
            script_name=None,
            raw_payload_redacted={},
        ),
    )

    rows, marker = _receipt_sync_rows_with_command_detail_backfill(
        store,
        receipts=[],
        redaction_level="partial",
        synced_at="2026-04-15T00:01:00Z",
    )

    assert [row["receipt_id"] for row in rows] == ["guard-receipt-backfill"]
    assert marker == {
        "level": "partial",
        "updated_at": "2026-04-15T00:01:00Z",
        "days": 30,
        "limit": 200,
        "receipts": 1,
        "queried": 1,
        "before_rowid": 1,
        "complete": True,
    }


def test_relaxed_redaction_command_detail_backfill_marker_prevents_repeat(tmp_path) -> None:
    store = GuardStore(tmp_path)
    store.set_sync_payload(
        _RECEIPT_COMMAND_DETAIL_BACKFILL_MARKER,
        {"level": "partial", "updated_at": "2026-04-15T00:01:00Z", "complete": True},
        "2026-04-15T00:01:00Z",
    )

    rows, marker = _receipt_sync_rows_with_command_detail_backfill(
        store,
        receipts=[],
        redaction_level="partial",
        synced_at="2026-04-15T00:02:00Z",
    )

    assert rows == []
    assert marker is None


def test_capped_command_detail_backfill_pages_remaining_receipts(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(runner, "_RECEIPT_COMMAND_DETAIL_BACKFILL_LIMIT", 1)
    store = GuardStore(tmp_path)
    for index in range(2):
        store.add_receipt(
            GuardReceipt(
                receipt_id=f"guard-receipt-backfill-{index}",
                timestamp=f"2099-04-15T00:0{index}:00+00:00",
                harness="codex",
                artifact_id=f"codex:tool-action:backfill-{index}",
                artifact_hash=f"hash-backfill-{index}",
                policy_decision="block",
                capabilities_summary="tool action request",
                changed_capabilities=(),
                provenance_summary="",
                user_override=None,
                artifact_name="bash",
                source_scope="project",
                diff_summary=None,
                approval_source=None,
                approval_request_id=None,
                scanner_evidence=(),
                browser_intent=None,
            ),
            action_envelope=GuardActionEnvelope(
                schema_version=1,
                action_id=f"action-backfill-{index}",
                harness="codex",
                event_name="PreToolUse",
                action_type="shell_command",
                workspace=None,
                workspace_hash="workspace",
                tool_name="bash",
                command=f"cd repo && npm test -- --runInBand case-{index}",
                prompt_excerpt=None,
                prompt_text=None,
                target_paths=(),
                network_hosts=(),
                mcp_server=None,
                mcp_tool=None,
                package_manager=None,
                package_name=None,
                package_intent_kind=None,
                package_targets=(),
                pre_execution_result="block",
                script_name=None,
                raw_payload_redacted={},
            ),
        )

    first_rows, first_marker = _receipt_sync_rows_with_command_detail_backfill(
        store,
        receipts=[],
        redaction_level="partial",
        synced_at="2026-04-15T00:02:00Z",
    )

    assert [row["receipt_id"] for row in first_rows] == ["guard-receipt-backfill-1"]
    assert first_marker is not None
    assert first_marker["complete"] is False
    assert first_marker["before_rowid"] == 2
    store.set_sync_payload(
        _RECEIPT_COMMAND_DETAIL_BACKFILL_MARKER,
        first_marker,
        "2026-04-15T00:02:00Z",
    )

    second_rows, second_marker = _receipt_sync_rows_with_command_detail_backfill(
        store,
        receipts=[],
        redaction_level="partial",
        synced_at="2026-04-15T00:03:00Z",
    )

    assert [row["receipt_id"] for row in second_rows] == ["guard-receipt-backfill-0"]
    assert second_marker is not None
    assert second_marker["complete"] is False
    assert second_marker["before_rowid"] == 1


def test_existing_relaxed_receipt_redaction_resets_cursor_once(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard.db")
    store.set_sync_payload(
        "cloud_receipt_redaction_level",
        {"level": "none", "updated_at": "2026-04-15T00:00:00Z"},
        "2026-04-15T00:00:00Z",
    )
    store.set_sync_payload(
        "receipt_sync_cursor",
        {"last_rowid": 42, "synced_at": "2026-04-15T00:00:00Z"},
        "2026-04-15T00:00:00Z",
    )

    _ensure_relaxed_receipt_redaction_resync(
        store,
        level="none",
        synced_at="2026-04-15T00:01:00Z",
    )

    assert store.get_sync_payload("receipt_sync_cursor") == {
        "last_rowid": 0,
        "synced_at": "2026-04-15T00:01:00Z",
        "reason": "cloud_receipt_redaction_level_relaxed_existing",
        "receipt_redaction_level": "none",
    }
    assert store.get_sync_payload(_RELAXED_RECEIPT_REDACTION_RESYNC_MARKER) == {
        "level": "none",
        "updated_at": "2026-04-15T00:01:00Z",
    }

    _ensure_relaxed_receipt_redaction_resync(
        store,
        level="none",
        synced_at="2026-04-15T00:02:00Z",
    )

    assert store.get_sync_payload("receipt_sync_cursor") == {
        "last_rowid": 0,
        "synced_at": "2026-04-15T00:01:00Z",
        "reason": "cloud_receipt_redaction_level_relaxed_existing",
        "receipt_redaction_level": "none",
    }


def test_first_cloud_redaction_level_matches_relaxed_local_config_without_cursor_reset(tmp_path) -> None:
    store = GuardStore(tmp_path)
    update_guard_settings(tmp_path, {"receipt_redaction_level": "none"})
    store.set_sync_payload(
        "receipt_sync_cursor",
        {"last_rowid": 17, "synced_at": "2026-04-15T00:00:00Z"},
        "2026-04-15T00:00:00Z",
    )

    _persist_cloud_receipt_redaction_level(
        store,
        level="none",
        synced_at="2026-04-15T00:01:00Z",
    )

    assert store.get_sync_payload("cloud_receipt_redaction_level") == {
        "level": "none",
        "updated_at": "2026-04-15T00:01:00Z",
    }
    assert store.get_sync_payload("receipt_sync_cursor") == {
        "last_rowid": 17,
        "synced_at": "2026-04-15T00:00:00Z",
    }


@pytest.mark.parametrize("change", ["none", "source", "preference", "cursor", "unacknowledged", "rejected", "policy"])
def test_signed_receipt_response_privacy_requires_current_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    from codex_plugin_scanner.guard import workspace_preference_authority as preference_authority
    from codex_plugin_scanner.guard.receipt_sync_authority import ReceiptSyncCapture, capture_receipt_sync_state
    from tests.support.optional_uploads import (
        OPTIONAL_UPLOAD_WORKSPACE,
        confirm_legacy_optional_uploads,
        seed_optional_upload_source,
    )

    store = GuardStore(tmp_path / "guard-home")
    seed_optional_upload_source(store, monkeypatch)
    local_level = "full" if change == "none" else "none"
    update_guard_settings(
        store.guard_home,
        {"sync": True, "telemetry": False, "receipt_redaction_level": local_level},
        cloud_sync_entitled=True,
    )
    auth_context = confirm_legacy_optional_uploads(store)
    prepared_at = "2026-07-01T00:00:00Z"
    response_at = "2026-07-01T00:00:01Z"
    monkeypatch.setattr(runner, "_now", lambda: prepared_at)
    store.set_sync_payload(
        "policy_bundle_keyring",
        policy_bundle_test_keyring(workspace_id=OPTIONAL_UPLOAD_WORKSPACE),
        prepared_at,
    )
    bundle = _signed_redaction_policy_bundle(
        level="none",
        bundle_version="policy-2026-07-01.1",
        issued_at=response_at,
        workspace_id=OPTIONAL_UPLOAD_WORKSPACE,
    )
    wire = {
        "contractVersion": preference_authority.CONTRACT,
        "workspaceId": OPTIONAL_UPLOAD_WORKSPACE,
        "revision": 1,
        "updatedAt": prepared_at,
        "preferences": {"syncEnabled": True, "telemetryEnabled": False, "receiptRedactionLevel": "none"},
    }

    def accept_current_preferences() -> None:
        captured = preference_authority.capture_workspace_preference_state(store)
        result = preference_authority.accept_workspace_preference_response(
            store,
            captured,
            {"workspacePreferences": wire, "receiptSyncAccepted": False},
            sent_revision=None,
        )
        assert result.state.preferences is not None
        assert result.state.preferences.revision == 1

    if change == "unacknowledged":
        accept_current_preferences()
    if change == "none":
        _store_blocked_command_receipt(store)
    if change == "rejected":
        # Mutating a signed field must not grant response metadata authority.
        bundle["receiptRedactionLevel"] = "full"
    payload: dict[str, object] = {
        "syncedAt": response_at,
        "receiptsStored": 1 if change == "none" else 0,
        "policyBundle": bundle,
    }
    if change == "unacknowledged":
        payload.update({"workspacePreferences": wire, "receiptSyncAccepted": False})

    class Response(io.BytesIO):
        status = 200

        def __init__(self) -> None:
            super().__init__(json.dumps(payload).encode("utf-8"))
            self.headers = Message()
            self.headers["Content-Type"] = "application/json"

        def getcode(self) -> int:
            return self.status

    requests_seen: list[dict[str, object]] = []
    peer = GuardStore(store.guard_home, allow_system_keyring=False)

    def transport(request: urllib.request.Request, *, timeout: float) -> Response:
        assert timeout == runner._SYNC_HTTP_TIMEOUT_SECONDS
        with peer.hold_oauth_credential_lock(timeout_seconds=0):
            pass
        assert request.data is not None
        assert isinstance(request.data, bytes)
        body = json.loads(request.data)
        assert isinstance(body, dict)
        requests_seen.append(body)
        if change == "none":
            assert len(body["receipts"]) == 1
            assert "cd repo && npx vitest run example.test.ts --reporter=verbose" not in request.data.decode()
        else:
            assert body["receipts"] == []
        return Response()

    monkeypatch.setattr(runner, "managed_urlopen", transport)
    monkeypatch.setattr(runner, "sync_pain_signals", lambda _store, auth_context=None: 0)
    monkeypatch.setattr(runner, "sync_guard_events", lambda _store, auth_context=None: {"accepted": 0, "statuses": []})
    actual_activate = runner.activate_with_reason
    activations: list[object] = []
    activation_call: tuple[tuple[object, ...], dict[str, object]] | None = None

    def activate(
        activation: Callable[..., dict[str, object] | None], *args: object, **kwargs: object
    ) -> tuple[dict[str, object] | None, str]:
        nonlocal activation_call
        result = actual_activate(activation, *args, **kwargs)
        if result[0] is not None:
            committed = store.get_sync_payload("policy_bundle")
            assert isinstance(committed, dict)
            assert committed["bundleVersion"] == "policy-2026-07-01.1"
            assert committed["receiptRedactionLevel"] == "none"
            assert committed["bundleHash"] == computed_policy_bundle_hash(committed)
            activations.append(result[0])
            # Activation is one local response commit. A competing credential
            # writer cannot enter here, including through a test interposer.
            with (
                pytest.raises(TimeoutError, match="credential lock"),
                peer.hold_oauth_credential_lock(timeout_seconds=0),
            ):
                pass
            activation_call = ((activation, *args), kwargs)
        return result

    actual_select = runner._prepare_optional_receipt_selection
    privacy_boundaries: list[str] = []

    def select(
        selected_store: GuardStore,
        connection: OAuthConnectionSnapshot | None,
        *,
        synced_at: str,
        required_capture: ReceiptSyncCapture | None = None,
        required_policy_bundle: dict[str, object] | None = None,
    ) -> tuple[ReceiptSyncCapture | None, bool, str]:
        if required_capture is not None:
            # Race after the real signed activation has committed and released
            # its response lease, before privacy rechecks that exact response.
            # Probe the actual same-home advisory lock, then release it before
            # invoking supported writers which acquire their own authority.
            assert activation_call is not None
            assert not privacy_boundaries
            assert required_policy_bundle == bundle
            with peer.hold_oauth_credential_lock(timeout_seconds=0):
                pass
            privacy_boundaries.append(change)
            args, kwargs = activation_call
            if change == "source":
                seed_optional_upload_source(
                    peer,
                    monkeypatch,
                    workspace_id="00000000-0000-4000-8000-000000000043",
                )
                peer.set_sync_payload("sync_summary", {"source": "newer-connection"}, prepared_at)
            elif change == "preference":
                accept_current_preferences()
            elif change == "cursor":
                peer.set_sync_payload("receipt_sync_cursor", {"last_rowid": 73, "synced_at": prepared_at}, prepared_at)
            elif change == "policy":
                captured = capture_receipt_sync_state(store)
                later_at = "2026-07-01T00:00:02Z"
                later_bundle = _signed_redaction_policy_bundle(
                    level="full",
                    bundle_version="policy-2026-07-01.2",
                    issued_at=later_at,
                    workspace_id=OPTIONAL_UPLOAD_WORKSPACE,
                )
                device_id, device_name = runner._guard_device_metadata(store)
                later_ack = runner.effective_policy_bundle_acknowledgement(
                    device_id=device_id,
                    device_name=device_name,
                    effective_policy_bundle=later_bundle,
                    validated_policy_bundle=later_bundle,
                    validated_delivery=None,
                    stored_acknowledgement=store.get_sync_payload("policy_bundle_ack"),
                    synced_at=later_at,
                    applied=False,
                )
                later_kwargs = {
                    **kwargs,
                    "policy_bundle": later_bundle,
                    "policy_bundle_ack": later_ack,
                    "policy_bundle_checkpoint": runner._policy_bundle_acceptance_checkpoint(later_bundle),
                }
                assert len(args) == 3
                later_result = actual_activate(peer.apply_policy_bundle_authority, args[1], later_at, **later_kwargs)
                assert later_result[0] is not None
                assert runner.validated_synced_policy_bundle(store) == later_bundle
                assert capture_receipt_sync_state(store) == captured
        return actual_select(
            selected_store,
            connection,
            synced_at=synced_at,
            required_capture=required_capture,
            required_policy_bundle=required_policy_bundle,
        )

    monkeypatch.setattr(runner, "activate_with_reason", activate)
    monkeypatch.setattr(runner, "_prepare_optional_receipt_selection", select)
    if change == "source":
        with pytest.raises(RuntimeError, match="connection changed"):
            _ = runner.sync_receipts(store, auth_context=auth_context)
        assert peer.get_sync_payload("sync_summary") == {"source": "newer-connection"}
    else:
        _ = runner.sync_receipts(store, auth_context=auth_context)

    assert len(requests_seen) == 1
    assert privacy_boundaries == ([] if change in {"unacknowledged", "rejected"} else [change])
    if change == "rejected":
        assert not activations
        assert store.get_sync_payload("policy_bundle") is None
    else:
        assert len(activations) == 1
    assert store.get_sync_payload("cloud_receipt_redaction_level") == {
        "level": local_level,
        "updated_at": response_at if change == "none" else prepared_at,
    }
    if change == "none":
        assert store.get_sync_payload(_RELAXED_RECEIPT_REDACTION_RESYNC_MARKER) is None
        assert store.get_sync_payload(_RECEIPT_COMMAND_DETAIL_BACKFILL_MARKER) is None
    else:
        assert store.get_sync_payload(_RELAXED_RECEIPT_REDACTION_RESYNC_MARKER) == {
            "level": "none",
            "updated_at": prepared_at,
        }
    if change == "cursor":
        assert store.get_sync_payload("receipt_sync_cursor") == {"last_rowid": 73, "synced_at": prepared_at}
