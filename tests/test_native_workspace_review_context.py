from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard.review_contracts import GuardReviewOAuthMetadata
from codex_plugin_scanner.guard.runtime import cloud_review_event_projection as projection
from codex_plugin_scanner.guard.runtime import native_workspace_review_context as context
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_cloud_review_sync_worker import Store


def _authority() -> dict[str, object]:
    return {
        "schema": "guard-native-workspace-review-authority.v1",
        "version": 1,
        "purpose": "cloud_review_team_delegation",
        "key_algorithm": "ed25519",
        "key_id": "a" * 64,
        "public_key": "b" * 64,
        "workspace_binding": "c" * 64,
        "device_binding": "d" * 64,
        "installation_binding": "e" * 64,
        "enrollment_generation": 1,
        "previous_key_id": None,
        "scope_contract_version": "guard-native-workspace-review-scope.v1",
        "scope_binding": "f" * 64,
        "issued_at_ms": 1,
        "expires_at_ms": 2,
        "status": "active",
        "enrollment_signature": "1" * 128,
    }


def _response(request_id: str = "request-1") -> dict[str, object]:
    authority = _authority()
    return {
        "schema": "guard-native-workspace-review-context.v1",
        "version": 1,
        "request_id": request_id,
        "authority_record": authority,
        "authority_record_digest": "2" * 64,
        "authority_generation": 1,
        "authority_key_id": authority["key_id"],
        "workspace_binding": authority["workspace_binding"],
        "device_binding": authority["device_binding"],
        "installation_binding": authority["installation_binding"],
        "scope_binding": authority["scope_binding"],
        "request_snapshot_digest": "3" * 64,
        "request_binding": "4" * 64,
        "action_binding": "5" * 64,
        "intent_binding": "6" * 64,
        "revision_binding": "7" * 64,
        "policy_binding": "8" * 64,
        "retry_scope_binding": "9" * 64,
    }


def _status() -> SimpleNamespace:
    return SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=Path("/native/hol-guard-runtime")),
        capabilities=SimpleNamespace(
            features=(
                "resident-protocol-v2",
                "native-workspace-review-context-v1",
            )
        ),
    )


def test_context_uses_resident_response_without_reimplementing_bindings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setattr(context, "native_runtime_status", _status)
    monkeypatch.setattr(context, "_isolated_environment", lambda: {})
    monkeypatch.setattr(context, "stage_workspace_review_request", lambda *_args: {})

    def request(**kwargs: object) -> bytes:
        captured.update(kwargs)
        return json.dumps(_response()).encode("utf-8")

    monkeypatch.setattr(context, "native_resident_client_request", request)
    result = context.build_native_workspace_review_context(
        cast(context.NativeWorkspaceReviewStore, object()), tmp_path, "request-1"
    )
    assert result == _response()
    payload = cast(bytes, captured["payload"])
    assert json.loads(payload.decode("utf-8")) == {
        "operation": "workspace_review_context",
        "request": {"request_id": "request-1"},
    }


def test_context_stages_the_frozen_snapshot_including_browser_and_launch_fields(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(context, "native_runtime_status", _status)
    monkeypatch.setattr(context, "_isolated_environment", lambda: {})
    captured: dict[str, object] = {}

    def stage(_store: object, _home: Path, _request_id: str, request_snapshot: object) -> dict[str, object]:
        captured["snapshot"] = request_snapshot
        return {}

    monkeypatch.setattr(context, "stage_workspace_review_request", stage)
    monkeypatch.setattr(
        context,
        "native_resident_client_request",
        lambda **_kwargs: json.dumps(_response()).encode("utf-8"),
    )
    frozen_snapshot: dict[str, object] = {
        "request_id": "request-1",
        "status": "pending",
        "launch_target": "frozen-target",
        "browser_intent_json": {"url": "https://frozen.example"},
    }

    result = context.build_native_workspace_review_context(
        cast(context.NativeWorkspaceReviewStore, object()),
        tmp_path,
        "request-1",
        frozen_snapshot,
    )

    assert result == _response()
    assert captured["snapshot"] == frozen_snapshot


def test_invalid_authority_context_is_omitted(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(context, "native_runtime_status", _status)
    monkeypatch.setattr(context, "_isolated_environment", lambda: {})
    monkeypatch.setattr(context, "stage_workspace_review_request", lambda *_args: {})
    invalid = _response()
    authority = invalid["authority_record"]
    assert isinstance(authority, dict)
    authority["status"] = "revoked"
    monkeypatch.setattr(
        context,
        "native_resident_client_request",
        lambda **_kwargs: json.dumps(invalid).encode("utf-8"),
    )
    assert (
        context.build_native_workspace_review_context(
            cast(context.NativeWorkspaceReviewStore, object()), tmp_path, "request-1"
        )
        is None
    )


def test_cloud_projection_attaches_optional_context_only_for_pending_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(projection, "build_local_review_request_claim", lambda **_kwargs: None)
    monkeypatch.setattr(
        projection,
        "build_native_workspace_review_context",
        lambda *_args: {"schema": "guard-native-workspace-review-context.v1"},
    )
    event = projection.build_cloud_review_event(
        {
            "request_id": "request-1",
            "status": "pending",
            "harness": "guard-review",
            "raw_command_text": "git status",
            "created_at": "2026-09-25T12:00:00+00:00",
            "last_seen_at": "2026-09-25T12:00:00+00:00",
        },
        oauth=cast(GuardReviewOAuthMetadata, object()),
        redaction_level="none",
        store=cast(GuardStore, cast(object, Store(tmp_path))),
        event_sequence=1,
    )
    assert event is not None
    request_payload = event["requestPayload"]
    assert isinstance(request_payload, dict)
    assert request_payload["nativeWorkspaceReview"] == {"schema": "guard-native-workspace-review-context.v1"}


def test_cloud_projection_caches_exact_snapshot_and_bounds_resident_probes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(projection, "build_local_review_request_claim", lambda **_kwargs: None)
    calls: list[dict[str, object]] = []

    def probe(*_args: object) -> dict[str, object]:
        calls.append(cast(dict[str, object], _args[3]))
        return {"schema": "guard-native-workspace-review-context.v1"}

    monkeypatch.setattr(projection, "build_native_workspace_review_context", probe)
    item: dict[str, object] = {
        "request_id": "request-1",
        "status": "pending",
        "harness": "guard-review",
        "raw_command_text": "git status",
        "launch_target": "frozen-target",
        "browser_intent_json": {"url": "https://frozen.example"},
        "created_at": "2026-09-25T12:00:00+00:00",
        "last_seen_at": "2026-09-25T12:00:00+00:00",
    }
    state = context.NativeWorkspaceReviewContextProbeState(remaining=1)
    store = cast(GuardStore, cast(object, Store(tmp_path)))
    oauth = cast(GuardReviewOAuthMetadata, object())

    first = projection.build_cloud_review_event(
        item,
        oauth=oauth,
        redaction_level="none",
        store=store,
        event_sequence=1,
        native_context_probe_state=state,
    )
    second = projection.build_cloud_review_event(
        dict(item),
        oauth=oauth,
        redaction_level="none",
        store=store,
        event_sequence=2,
        native_context_probe_state=state,
    )
    third = projection.build_cloud_review_event(
        {**item, "request_id": "request-2"},
        oauth=oauth,
        redaction_level="none",
        store=store,
        event_sequence=3,
        native_context_probe_state=state,
    )

    assert first is not None and second is not None and third is not None
    assert len(calls) == 1
    assert calls[0]["launch_target"] == "frozen-target"
    assert calls[0]["browser_intent_json"] == {"url": "https://frozen.example"}
    first_payload = cast(dict[str, object], first["requestPayload"])
    second_payload = cast(dict[str, object], second["requestPayload"])
    third_payload = cast(dict[str, object], third["requestPayload"])
    assert first_payload["nativeWorkspaceReview"] == second_payload["nativeWorkspaceReview"]
    assert "nativeWorkspaceReview" not in third_payload


def test_requeued_context_omits_only_expired_capability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base_claim: dict[str, object] = {
        "actionEnvelopeHash": "action-hash",
        "actionIdentity": "action-identity",
        "claimHash": "claim-hash",
        "expiresAt": "2026-09-27T00:00:00+00:00",
        "exactReviewCapability": {"expiresAt": "2000-01-01T00:00:00+00:00", "sourceClaimHash": "claim-hash"},
    }
    monkeypatch.setattr(projection, "build_local_review_request_claim", lambda **_kwargs: dict(base_claim))
    monkeypatch.setattr(
        projection,
        "build_native_workspace_review_context",
        lambda *_args: {"schema": "guard-native-workspace-review-context.v1"},
    )
    item: dict[str, object] = {
        "request_id": "request-1",
        "status": "pending",
        "harness": "guard-review",
        "raw_command_text": "git status",
        "created_at": "2026-09-26T23:00:00+00:00",
        "last_seen_at": "2026-09-26T23:00:00+00:00",
    }
    store = cast(GuardStore, cast(object, Store(tmp_path)))
    oauth = cast(GuardReviewOAuthMetadata, object())
    replayed = projection.build_cloud_review_event(
        item,
        oauth=oauth,
        redaction_level="none",
        store=store,
        event_sequence=1,
        strip_expired_capability=True,
    )
    assert replayed is not None
    replayed_claim = replayed["reviewClaim"]
    assert isinstance(replayed_claim, dict)
    assert replayed_claim["claimHash"] == base_claim["claimHash"]
    assert replayed_claim["expiresAt"] == base_claim["expiresAt"]
    assert "exactReviewCapability" not in replayed_claim

    ordinary = projection.build_cloud_review_event(
        item,
        oauth=oauth,
        redaction_level="none",
        store=store,
        event_sequence=2,
    )
    assert ordinary is not None
    assert ordinary["reviewClaim"] == base_claim

    monkeypatch.setattr(projection, "build_native_workspace_review_context", lambda *_args: None)
    contextless = projection.build_cloud_review_event(
        item,
        oauth=oauth,
        redaction_level="none",
        store=store,
        event_sequence=3,
        strip_expired_capability=True,
    )
    assert contextless is not None
    assert contextless["reviewClaim"] == base_claim
