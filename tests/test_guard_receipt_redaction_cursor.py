from __future__ import annotations

import urllib.error
from datetime import datetime, timezone

import pytest

import codex_plugin_scanner.guard.runtime.runner as runner
from codex_plugin_scanner.guard.config import update_guard_settings
from codex_plugin_scanner.guard.models import GuardReceipt
from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope
from codex_plugin_scanner.guard.runtime.runner import (
    _RECEIPT_COMMAND_DETAIL_BACKFILL_MARKER,
    _RELAXED_RECEIPT_REDACTION_RESYNC_MARKER,
    _ensure_relaxed_receipt_redaction_resync,
    _persist_cloud_receipt_redaction_level,
    _receipt_sync_cursor_rowids_from_batch,
    _receipt_sync_rows_with_command_detail_backfill,
)
from codex_plugin_scanner.guard.store import GuardStore


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
        {},
        None,
    )


def test_cloud_receipt_redaction_relaxation_resets_receipt_cursor_before_storing_level(tmp_path) -> None:
    store = GuardStore(tmp_path)
    writes: list[tuple[str, dict[str, object], str]] = []
    original_set_sync_payload = store.set_sync_payload

    def record_set_sync_payload(state_key: str, payload: dict[str, object], now: str) -> None:
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
    store = GuardStore(tmp_path)
    _store_blocked_command_receipt(store)
    refresh_flags: list[bool] = []
    post_attempts = 0

    def resolve_auth_context(
        _store: GuardStore,
        *,
        allow_primary_repair: bool = True,
        force_refresh: bool = False,
    ) -> dict[str, object]:
        refresh_flags.append(force_refresh)
        return {
            "sync_url": "https://hol.org/api/guard/receipts/sync",
            "access_token": "fresh" if force_refresh else "stale",
        }

    def post_sync(**_kwargs: object) -> dict[str, object]:
        nonlocal post_attempts
        post_attempts += 1
        if post_attempts == 1:
            raise _sync_unauthorized_error()
        return {
            "syncedAt": "2026-04-15T00:01:00Z",
            "receiptsStored": 1,
        }

    monkeypatch.setattr(runner, "_resolve_guard_sync_auth_context", resolve_auth_context)
    monkeypatch.setattr(runner, "_urlopen_json_with_timeout_retry", post_sync)

    runner.sync_receipts(store)

    assert refresh_flags[:2] == [False, True]
    assert post_attempts >= 2
    assert store.get_sync_payload("receipt_sync_cursor") == {
        "last_rowid": 1,
        "synced_at": "2026-04-15T00:01:00Z",
    }


def test_forced_oauth_refresh_persists_same_refresh_token_access_token(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path)
    persisted: list[dict[str, object]] = []

    class OAuthClient:
        issuer = "http://127.0.0.1:3000"
        token_endpoint = "http://127.0.0.1:3000/oauth/token"

    def fake_refresh(**_kwargs: object) -> dict[str, object]:
        return {
            "access_token": "fresh-access-token",
            "access_token_expires_at": "2026-04-15T00:30:00+00:00",
            "refresh_token": "same-refresh-token",
        }

    monkeypatch.setattr(runner, "resolve_guard_oauth_client_config", lambda _issuer: OAuthClient())
    monkeypatch.setattr(runner, "_oauth_dpop_key_material", lambda _credentials: None)
    monkeypatch.setattr(runner, "_refresh_guard_oauth_access_token", fake_refresh)
    monkeypatch.setattr(store, "set_oauth_local_credentials", lambda **kwargs: persisted.append(kwargs))

    auth_context = runner._resolve_guard_sync_auth_context_from_oauth_credentials(
        store,
        {
            "issuer": "http://127.0.0.1:3000",
            "client_id": "guard-local-daemon",
            "refresh_token": "same-refresh-token",
            "access_token": "stale-access-token",
            "access_token_expires_at": "2099-04-15T00:30:00+00:00",
            "dpop_private_key_pem": "private-key",
            "dpop_public_jwk": {"kty": "EC", "crv": "P-256"},
            "dpop_public_jwk_thumbprint": "thumbprint",
        },
        force_refresh=True,
    )

    assert auth_context["access_token"] == "fresh-access-token"
    assert persisted
    assert persisted[0]["refresh_token"] == "same-refresh-token"
    assert persisted[0]["access_token"] == "fresh-access-token"
    assert persisted[0]["access_token_expires_at"] == "2026-04-15T00:30:00+00:00"


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
        "days": 7,
        "limit": 5000,
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
