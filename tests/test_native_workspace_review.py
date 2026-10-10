from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.runtime import native_workspace_review as native
from codex_plugin_scanner.guard.runtime import native_workspace_review_staging as staging
from codex_plugin_scanner.guard.runtime import native_workspace_review_transport as transport
from codex_plugin_scanner.guard.runtime.native_workspace_review_error import (
    NativeWorkspaceReviewError,
    _canonical_json_bytes,
)
from codex_plugin_scanner.guard.store_native_workspace_review import NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX
from tests.native_workspace_review_test_support import (
    _bind_native_client,
    _request,
    _staged_digest,
    _status,
    _Store,
    _verified_body,
)


def test_apply_reconciles_native_claim_into_local_queue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _Store(_request())
    monkeypatch.setattr(transport, "native_runtime_status", _status)
    monkeypatch.setattr(transport, "_isolated_environment", lambda: {})
    monkeypatch.setattr(
        transport,
        "native_resident_client_request",
        lambda **kwargs: json.dumps(
            {
                "status": "verified",
                "replayed": False,
                "request_id": "request-1",
                "decision": "allow",
                "claim_id": "a" * 64,
                "envelope_digest": "b" * 64,
                "request_snapshot_digest": _staged_digest(cast(Path, kwargs["guard_home"]), "request-1"),
            }
        ).encode("utf-8"),
    )
    result = native.apply_native_workspace_review_decision(
        store,
        tmp_path,
        "request-1",
        {"signed": "native-envelope"},
    )
    assert result["status"] == "verified"
    assert result["decision"] == "allow"
    assert result["resolution_action"] == "allow"
    assert store.request["status"] == "resolved"


@pytest.mark.parametrize(
    ("code", "retryable", "certainty"),
    [
        ("native_overloaded", True, "pre_commit"),
        ("native_overloaded", False, "unknown"),
        ("future_native_error", True, "unknown"),
    ],
)
def test_only_authenticated_dispatch_overload_proves_precommit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: str, retryable: bool, certainty: str
) -> None:
    store = _Store(_request())
    _bind_native_client(monkeypatch, lambda _kwargs: json.dumps({"error": code, "retryable": retryable}).encode())
    with pytest.raises(NativeWorkspaceReviewError) as failure:
        native.apply_native_workspace_review_decision(store, tmp_path, "request-1", {"signed": "envelope"})
    assert failure.value.call_stage == "read"
    assert failure.value.commit_certainty == certainty
    assert store.request["status"] == "pending"


def test_structured_overload_does_not_apply_or_resend(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.runtime.command_executors import execute_guard_command_job

    store = _Store(_request())
    store.guard_home = tmp_path
    payloads: list[bytes] = []

    def responder(kwargs: dict[str, object]) -> bytes | None:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        payloads.append(payload)
        kwargs["failure_code"] = "native_overloaded"
        return json.dumps({"error": "native_overloaded", "retryable": True}).encode("utf-8")

    _bind_native_client(monkeypatch, responder)
    result = execute_guard_command_job(
        {
            "operation": "guard.review.resolveExact",
            "payload": {
                "envelope": {"signed": "native-envelope"},
                "localRequestId": "request-1",
                "receiptId": "receipt-1",
            },
        },
        context=HarnessContext(home_dir=tmp_path, workspace_dir=tmp_path, guard_home=tmp_path),
        store=store,  # type: ignore[arg-type]
        now=lambda: "2026-10-04T05:00:00+00:00",
    )
    assert result["failureCode"] == "native_overloaded"
    assert "status" not in result
    assert store.request["status"] == "pending"
    assert len(payloads) == 1


def test_stream_loss_reconciles_the_consumed_decision_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _Store(_request())
    resolutions: list[bool] = []
    original_resolve = store.resolve_native_workspace_review_request

    def resolve(request_id: str, **kwargs: object) -> dict[str, object]:
        resolutions.append(kwargs.get("native_replayed") is True)
        return original_resolve(request_id, **kwargs)

    store.resolve_native_workspace_review_request = resolve  # type: ignore[method-assign]

    consumptions = 0

    def responder(kwargs: dict[str, object]) -> bytes | None:
        nonlocal consumptions
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        operation = json.loads(payload)["operation"]
        if operation == "workspace_review_decision":
            consumptions += 1
            kwargs["failure_code"] = "native_client_stream_write_failed"
            return None
        guard_home = kwargs["guard_home"]
        assert isinstance(guard_home, Path)
        if consumptions == 0:
            return json.dumps({"status": "unknown"}).encode()
        return _verified_body(digest=_staged_digest(guard_home, "request-1"), replayed=True)

    _bind_native_client(monkeypatch, responder)
    result = native.apply_native_workspace_review_decision(
        store,
        tmp_path,
        "request-1",
        {"signed": "native-envelope"},
    )
    assert result["status"] == "replayed"
    assert result["native_replayed"] is True
    assert store.request["status"] == "resolved"
    assert resolutions == [True]
    assert consumptions == 1


@pytest.mark.parametrize("query_status", ["unknown", "verified", "malformed"])
def test_unconfirmed_consumption_never_resends_or_applies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, query_status: str
) -> None:
    store = _Store(_request())
    consumptions = 0

    def responder(kwargs: dict[str, object]) -> bytes | None:
        nonlocal consumptions
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        operation = json.loads(payload)["operation"]
        if operation == "workspace_review_decision":
            consumptions += 1
            kwargs["failure_code"] = "native_frame_read_failed"
            return None
        if query_status == "unknown":
            return json.dumps({"status": "unknown"}).encode()
        if query_status == "malformed":
            return b"not-a-native-response"
        guard_home = kwargs["guard_home"]
        assert isinstance(guard_home, Path)
        return _verified_body(digest=_staged_digest(guard_home, "request-1"), replayed=False)

    _bind_native_client(monkeypatch, responder)
    with pytest.raises(NativeWorkspaceReviewError, match="native_frame_read_failed") as error:
        native.apply_native_workspace_review_decision(store, tmp_path, "request-1", {"signed": "native-envelope"})
    assert error.value.commit_certainty == "unknown"
    assert store.request["status"] == "pending"
    assert consumptions == 1


def test_old_runtime_cannot_reconcile_by_consuming_again(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _Store(_request())
    consumptions = 0
    queries = 0

    def responder(kwargs: dict[str, object]) -> bytes | None:
        nonlocal consumptions, queries
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        if json.loads(payload)["operation"] == "workspace_review_decision":
            consumptions += 1
        else:
            queries += 1
        kwargs["failure_code"] = "native_frame_read_failed"
        return None

    _bind_native_client(monkeypatch, responder)
    old_status = _status()
    old_status.capabilities.features = ("resident-protocol-v2", "native-workspace-review-decision-v1")
    monkeypatch.setattr(transport, "native_runtime_status", lambda: old_status)
    with pytest.raises(NativeWorkspaceReviewError, match="native_frame_read_failed"):
        native.apply_native_workspace_review_decision(store, tmp_path, "request-1", {"signed": "native-envelope"})
    assert store.request["status"] == "pending"
    assert consumptions == 1
    assert queries == 0


@pytest.mark.parametrize("replayed", [False, True])
def test_post_consumption_reverify_failure_cannot_be_reported_as_precommit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, replayed: bool
) -> None:
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.runtime.command_executors import execute_guard_command_job

    store = _Store(_request())
    store.guard_home = tmp_path
    staging.stage_workspace_review_request(store, tmp_path, "request-1")
    digest = _staged_digest(tmp_path, "request-1")
    store.request.update(status="resolved", resolution_action="allow")
    store.sync_payloads[NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX + "request-1"] = {
        "request_id": "request-1",
        "request_snapshot_digest": digest,
    }
    if replayed:
        store.resolve_native_workspace_review_request = (  # type: ignore[method-assign]
            lambda *_args, **_kwargs: {"resolved": False, "error": "native_workspace_review_apply_failed"}
        )

    def consumed_response(_kwargs: dict[str, object]) -> bytes:
        return _verified_body(digest=digest, replayed=replayed)

    _bind_native_client(monkeypatch, consumed_response)
    result = execute_guard_command_job(
        {
            "operation": "guard.review.resolveExact",
            "payload": {
                "envelope": {"signed": "native-envelope"},
                "localRequestId": "request-1",
                "receiptId": "receipt-1",
            },
        },
        context=HarnessContext(home_dir=tmp_path, workspace_dir=tmp_path, guard_home=tmp_path),
        store=store,  # type: ignore[arg-type]
        now=lambda: "2026-10-04T05:00:00+00:00",
    )
    assert result["failureCode"] == (
        "native_workspace_review_apply_failed" if replayed else "native_workspace_review_decision_replay"
    )
    assert result["callStage"] == "verify"
    assert result["commitCertainty"] == "committed"
    assert store.request["status"] == "resolved"


def test_unconfirmed_query_security_rejection_does_not_apply(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _Store(_request())
    calls = 0

    def responder(kwargs: dict[str, object]) -> bytes | None:
        nonlocal calls
        calls += 1
        kwargs["failure_code"] = "native_client_stream_write_failed" if calls == 1 else "native_client_auth_rejected"
        return None

    _bind_native_client(monkeypatch, responder)
    with pytest.raises(NativeWorkspaceReviewError, match="native_client_auth_rejected"):
        native.apply_native_workspace_review_decision(
            store,
            tmp_path,
            "request-1",
            {"signed": "native-envelope"},
        )
    assert store.request["status"] == "pending"


def test_repeated_stream_loss_keeps_the_original_unknown_outcome(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _Store(_request())
    calls = 0

    def responder(kwargs: dict[str, object]) -> bytes | None:
        nonlocal calls
        calls += 1
        kwargs["failure_code"] = "native_frame_write_failed"
        return None

    _bind_native_client(monkeypatch, responder)
    with pytest.raises(NativeWorkspaceReviewError, match="native_frame_write_failed"):
        native.apply_native_workspace_review_decision(
            store,
            tmp_path,
            "request-1",
            {"signed": "native-envelope"},
        )
    assert store.request["status"] == "pending"


def test_expired_native_proof_does_not_apply_or_resend(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.runtime.command_executors import execute_guard_command_job

    store = _Store(_request())
    store.guard_home = tmp_path
    payloads: list[bytes] = []

    def responder(kwargs: dict[str, object]) -> bytes | None:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        payloads.append(payload)
        return json.dumps({"error": "native_workspace_review_decision_expired", "retryable": False}).encode("utf-8")

    _bind_native_client(monkeypatch, responder)
    result = execute_guard_command_job(
        {
            "operation": "guard.review.resolveExact",
            "payload": {
                "envelope": {"signed": "native-envelope"},
                "localRequestId": "request-1",
                "receiptId": "receipt-1",
            },
        },
        context=HarnessContext(home_dir=tmp_path, workspace_dir=tmp_path, guard_home=tmp_path),
        store=store,  # type: ignore[arg-type]
        now=lambda: "2026-10-04T05:00:00+00:00",
    )
    assert result["failureCode"] == "native_workspace_review_decision_expired"
    assert "status" not in result
    assert store.request["status"] == "pending"
    assert len(payloads) == 1


def test_second_grant_replay_error_does_not_apply_or_resend(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.runtime.command_executors import execute_guard_command_job

    store = _Store(_request())
    store.guard_home = tmp_path
    payloads: list[bytes] = []

    def responder(kwargs: dict[str, object]) -> bytes | None:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        payloads.append(payload)
        return json.dumps({"error": "native_workspace_review_decision_replay"}).encode("utf-8")

    _bind_native_client(monkeypatch, responder)
    result = execute_guard_command_job(
        {
            "operation": "guard.review.resolveExact",
            "payload": {
                "envelope": {"signed": "native-envelope"},
                "localRequestId": "request-1",
                "receiptId": "receipt-1",
            },
        },
        context=HarnessContext(home_dir=tmp_path, workspace_dir=tmp_path, guard_home=tmp_path),
        store=store,  # type: ignore[arg-type]
        now=lambda: "2026-10-04T05:00:00+00:00",
    )
    assert result["failureCode"] == "native_workspace_review_decision_replay"
    assert "status" not in result
    assert store.request["status"] == "pending"
    assert len(payloads) == 1


def test_staged_snapshot_substitution_is_rejected_before_sqlite_application(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _Store(_request())
    monkeypatch.setattr(transport, "native_runtime_status", _status)
    monkeypatch.setattr(transport, "_isolated_environment", lambda: {})

    def substitute_and_respond(**kwargs: object) -> bytes:
        guard_home = cast(Path, kwargs["guard_home"])
        path = guard_home / "native-runtime" / "workspace-review-requests" / "request-1.json"
        substituted = json.loads(path.read_text(encoding="utf-8"))
        substituted["action"]["raw_command_text"] = "git log --oneline"
        path.write_bytes(_canonical_json_bytes(substituted))
        return json.dumps(
            {
                "status": "verified",
                "replayed": False,
                "request_id": "request-1",
                "decision": "allow",
                "claim_id": "a" * 64,
                "envelope_digest": "b" * 64,
                "request_snapshot_digest": _staged_digest(guard_home, "request-1"),
            }
        ).encode("utf-8")

    monkeypatch.setattr(transport, "native_resident_client_request", substitute_and_respond)
    with pytest.raises(NativeWorkspaceReviewError) as error:
        native.apply_native_workspace_review_decision(
            store,
            tmp_path,
            "request-1",
            {"signed": "native-envelope"},
        )
    assert error.value.code == "native_workspace_review_response_invalid"
    assert store.request["status"] == "pending"
