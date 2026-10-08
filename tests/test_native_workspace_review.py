from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.cli import _build_parser
from codex_plugin_scanner.guard.adapters.grok_approval_resume import wait_for_grok_live_approval
from codex_plugin_scanner.guard.approvals import wait_for_approval_requests
from codex_plugin_scanner.guard.cli.commands_dispatch_cloud_review import _run_guard_cloud_review_command
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.runtime import native_workspace_review as native
from codex_plugin_scanner.guard.runtime.exact_cloud_review import EXACT_CLOUD_REVIEW_REVOCATION_STATE_KEY
from codex_plugin_scanner.guard.store import GuardStore


def _request(request_id: str = "request-1") -> dict[str, object]:
    return {
        "request_id": request_id,
        "status": "pending",
        "harness": "codex",
        "artifact_id": "artifact-1",
        "artifact_type": "command",
        "workspace": "/workspace",
        "action_identity": "action-1",
        "action_envelope_json": {"command": "git status"},
        "launch_target": "git",
        "raw_command_text": "git status",
        "browser_intent_json": None,
        "created_at": "2026-09-25T12:00:00+00:00",
        "last_seen_at": "2026-09-25T12:00:00+00:00",
        "dedupe_count": 1,
        "guard_version": "3.0.0",
        "first_seen_guard_version": "3.0.0",
        "last_seen_guard_version": "3.0.0",
        "policy_action": "review",
        "recommended_scope": "artifact",
        "source_scope": "artifact",
        "decision_v2_json": {"action": "review"},
        "resolution_action": None,
        "resolution_scope": None,
    }


class _Store:
    def __init__(self, request: dict[str, object]):
        self.request = request
        self.sync_payloads: dict[str, object] = {}

    def get_approval_request(self, request_id: str) -> dict[str, object] | None:
        if request_id != self.request["request_id"]:
            return None
        return copy.deepcopy(self.request)

    def get_sync_payload(self, state_key: str) -> dict[str, object] | list[object] | None:
        return cast(dict[str, object] | list[object] | None, self.sync_payloads.get(state_key))

    def resolve_native_workspace_review_request(self, request_id: str, **kwargs: object) -> dict[str, object]:
        assert request_id == self.request["request_id"]
        expected = cast(dict[str, object], kwargs["expected_request"])
        assert expected["status"] == "pending"
        action = kwargs["resolution_action"]
        self.request["status"] = "resolved"
        self.request["resolution_action"] = action
        self.request["resolution_scope"] = "artifact"
        return {"resolved": True, "resolved_request": copy.deepcopy(self.request), "replayed": False}


def _status() -> SimpleNamespace:
    return SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=Path("/native/hol-guard-runtime")),
        capabilities=SimpleNamespace(features=(
            "resident-protocol-v2",
            "native-workspace-review-decision-v1",
            "native-workspace-review-consumption-query-v1",
        )),
    )


def _staged_digest(guard_home: Path, request_id: str) -> str:
    path = guard_home / "native-runtime" / "workspace-review-requests" / f"{request_id}.json"
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_staging_uses_only_persisted_request_material(tmp_path: Path) -> None:
    store = _Store(_request())
    staged = native.stage_workspace_review_request(store, tmp_path, "request-1")
    assert staged["action_identity"] == "action-1"
    path = tmp_path / "native-runtime" / "workspace-review-requests" / "request-1.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["action"]["action_identity"] == "action-1"
    assert "decision" not in payload
    assert "dpop" not in json.dumps(payload).lower()
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_uploaded_snapshot_only_survives_scope_narrowing() -> None:
    current = _request()
    current["decision_v2_json"] = {"action": "review", "approval_scopes": ["artifact"]}
    uploaded = copy.deepcopy(current)
    cast(dict[str, object], uploaded["decision_v2_json"])["approval_scopes"] = ["artifact", "task"]
    assert native._compatible_uploaded_snapshot("request-1", current, uploaded)

    altered = copy.deepcopy(uploaded)
    altered["raw_command_text"] = "git push"
    assert not native._compatible_uploaded_snapshot("request-1", current, altered)
    altered = copy.deepcopy(uploaded)
    cast(dict[str, object], altered["decision_v2_json"])["action"] = "allow"
    assert not native._compatible_uploaded_snapshot("request-1", current, altered)
    altered = copy.deepcopy(uploaded)
    cast(dict[str, object], altered["decision_v2_json"])["approval_scopes"] = ["task"]
    assert not native._compatible_uploaded_snapshot("request-1", current, altered)


def test_native_delivery_selects_matching_authenticated_upload(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    current = _request()
    current["decision_v2_json"] = {"action": "review", "approval_scopes": ["artifact"]}
    uploaded = copy.deepcopy(current)
    cast(dict[str, object], uploaded["decision_v2_json"])["approval_scopes"] = ["artifact", "task"]
    unrelated = copy.deepcopy(uploaded)
    unrelated["raw_command_text"] = "git push"

    class StoreWithSnapshots(_Store):
        def list_review_event_snapshots(self, request_id: str) -> list[dict[str, object]]:
            assert request_id == "request-1"
            return [unrelated, uploaded, copy.deepcopy(uploaded)]

    probes: list[dict[str, object]] = []

    def context_probe(_store: object, _home: Path, _request_id: str, snapshot: object) -> dict[str, object]:
        assert isinstance(snapshot, dict)
        probes.append(snapshot)
        marker = "a" if snapshot == uploaded else "b"
        return {
            field: marker
            for field in (
                "request_binding",
                "action_binding",
                "intent_binding",
                "revision_binding",
                "policy_binding",
                "retry_scope_binding",
            )
        }

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.native_workspace_review_context.build_native_workspace_review_context",
        context_probe,
    )
    decision = {
        field: "a"
        for field in (
            "request_binding",
            "action_binding",
            "intent_binding",
            "revision_binding",
            "policy_binding",
            "retry_scope_binding",
        )
    }
    store = StoreWithSnapshots(current)
    assert native.matching_workspace_review_snapshot(store, tmp_path, "request-1", decision, current) == uploaded
    assert probes == [current, uploaded]
    with pytest.raises(native.NativeWorkspaceReviewError, match="native_workspace_review_decision_binding_mismatch"):
        native.matching_workspace_review_snapshot(
            store, tmp_path, "request-1", {**decision, "policy_binding": "wrong"}, current
        )


def test_windows_staging_uses_acl_bound_atomic_writer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _Store(_request())
    ensured: list[Path] = []
    bindings: list[Path] = []

    @contextmanager
    def bind_directory(path: Path):
        path.mkdir(parents=True, exist_ok=True)
        bindings.append(path)
        yield SimpleNamespace(path=path, handle=object(), handles=[])

    def ensure_private_directory(path: Path) -> None:
        ensured.append(path)
        path.mkdir(parents=True, exist_ok=True)

    def write_atomic(**kwargs: object) -> None:
        assert kwargs["maximum_bytes"] == native._MAX_REQUEST_STATE_BYTES
        assert kwargs["kind"] == "workspace_review_request"
        destination = cast(Path, kwargs["parent_path"]) / cast(str, kwargs["destination_name"])
        destination.write_bytes(cast(bytes, kwargs["payload"]))

    monkeypatch.setattr(
        native,
        "_native_policy_snapshot",
        SimpleNamespace(
            _windows_ensure_private_directory=ensure_private_directory,
            _windows_private_directory_binding=bind_directory,
            _windows_write_private_file_atomic=write_atomic,
        ),
    )
    monkeypatch.setattr(native.os, "name", "nt")
    for function_name in ("fchmod", "open", "fsync"):
        monkeypatch.setattr(
            native.os,
            function_name,
            lambda *args, _function_name=function_name, **kwargs: pytest.fail(_function_name),
        )

    native.stage_workspace_review_request(store, tmp_path, "request-1")
    path = tmp_path / "native-runtime" / "workspace-review-requests" / "request-1.json"
    expected = native._canonical_json_bytes(native._request_state("request-1", _request()))
    assert path.read_bytes() == expected
    assert _staged_digest(tmp_path, "request-1") == hashlib.sha256(expected).hexdigest()
    assert ensured == [tmp_path, tmp_path / "native-runtime", path.parent]
    assert bindings == [path.parent]


def test_apply_reconciles_native_claim_into_local_queue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _Store(_request())
    monkeypatch.setattr(native, "native_runtime_status", _status)
    monkeypatch.setattr(native, "_isolated_environment", lambda: {})
    monkeypatch.setattr(
        native,
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


def _verified_body(*, digest: str, replayed: bool) -> bytes:
    return json.dumps(
        {
            "status": "replayed" if replayed else "verified",
            "replayed": replayed,
            "request_id": "request-1",
            "decision": "allow",
            "claim_id": "a" * 64,
            "envelope_digest": "b" * 64,
            "request_snapshot_digest": digest,
        }
    ).encode("utf-8")


def _bind_native_client(monkeypatch: pytest.MonkeyPatch, responder) -> None:
    from codex_plugin_scanner.guard.native_resident_client import record_native_resident_client_failure_code
    monkeypatch.setattr(native, "native_resident_client_failure_context", lambda: None)

    monkeypatch.setattr(native, "native_runtime_status", _status)
    monkeypatch.setattr(native, "_isolated_environment", lambda: {})

    def request(**kwargs: object) -> bytes | None:
        encoded = responder(kwargs)
        if encoded is None:
            code = kwargs.get("failure_code")
            if isinstance(code, str):
                record_native_resident_client_failure_code(code)
        return encoded

    monkeypatch.setattr(native, "native_resident_client_request", request)


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
    _bind_native_client(
        monkeypatch, lambda _kwargs: json.dumps({"error": code, "retryable": retryable}).encode()
    )
    with pytest.raises(native.NativeWorkspaceReviewError) as failure:
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
    with pytest.raises(native.NativeWorkspaceReviewError, match="native_frame_read_failed") as error:
        native.apply_native_workspace_review_decision(
            store, tmp_path, "request-1", {"signed": "native-envelope"}
        )
    assert error.value.commit_certainty == "unknown"
    assert store.request["status"] == "pending"
    assert consumptions == 1


def test_old_runtime_cannot_reconcile_by_consuming_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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
    monkeypatch.setattr(native, "native_runtime_status", lambda: old_status)
    with pytest.raises(native.NativeWorkspaceReviewError, match="native_frame_read_failed"):
        native.apply_native_workspace_review_decision(
            store, tmp_path, "request-1", {"signed": "native-envelope"}
        )
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
    native.stage_workspace_review_request(store, tmp_path, "request-1")
    digest = _staged_digest(tmp_path, "request-1")
    store.request.update(status="resolved", resolution_action="allow")
    store.sync_payloads[native.NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX + "request-1"] = {
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


def test_unconfirmed_query_security_rejection_does_not_apply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _Store(_request())
    calls = 0

    def responder(kwargs: dict[str, object]) -> bytes | None:
        nonlocal calls
        calls += 1
        kwargs["failure_code"] = "native_client_stream_write_failed" if calls == 1 else "native_client_auth_rejected"
        return None

    _bind_native_client(monkeypatch, responder)
    with pytest.raises(native.NativeWorkspaceReviewError, match="native_client_auth_rejected"):
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
    with pytest.raises(native.NativeWorkspaceReviewError, match="native_frame_write_failed"):
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


def test_signed_deny_is_block_to_real_waiter_and_grok_harness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    request = GuardApprovalRequest(
        request_id="request-deny",
        harness="grok",
        artifact_id="grok:project:request-deny",
        artifact_name="request-deny",
        artifact_hash="hash-request-deny",
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("args",),
        source_scope="project",
        config_path=str(tmp_path / "grok-config.toml"),
        review_command="hol-guard approvals approve request-deny",
        approval_url="http://127.0.0.1/pending/request-deny",
        workspace=str(tmp_path),
        artifact_type="command",
        launch_target="git status",
        action_envelope_json={"command": "git status"},
    )
    store.add_approval_request(request, "2026-09-25T12:00:00+00:00")
    monkeypatch.setattr(
        native,
        "matching_workspace_review_snapshot",
        lambda _store, _home, _request_id, _decision, current: dict(current),
    )
    monkeypatch.setattr(native, "native_runtime_status", _status)
    monkeypatch.setattr(native, "_isolated_environment", lambda: {})
    monkeypatch.setattr(
        native,
        "native_resident_client_request",
        lambda **kwargs: json.dumps(
            {
                "status": "verified",
                "replayed": False,
                "request_id": "request-deny",
                "decision": "deny",
                "claim_id": "a" * 64,
                "authority_record_digest": "c" * 64,
                "workspace_binding": "4" * 64,
                "device_binding": "5" * 64,
                "installation_binding": "6" * 64,
                "scope_binding": "7" * 64,
                "request_binding": "d" * 64,
                "action_binding": "e" * 64,
                "intent_binding": "f" * 64,
                "revision_binding": "1" * 64,
                "policy_binding": "2" * 64,
                "retry_scope_binding": "3" * 64,
                "envelope_digest": "b" * 64,
                "request_snapshot_digest": _staged_digest(cast(Path, kwargs["guard_home"]), "request-deny"),
            }
        ).encode("utf-8"),
    )

    result = native.apply_native_workspace_review_decision(
        store,
        tmp_path / "guard-home",
        "request-deny",
        {"signed": "native-envelope"},
    )
    assert result["decision"] == "deny"
    assert result["resolution_action"] == "block"
    native_receipt = result["native_receipt"]
    assert isinstance(native_receipt, dict)
    assert native_receipt["decision"] == "deny"
    resolved = store.get_approval_request("request-deny")
    assert resolved is not None
    assert resolved["resolution_action"] == "block"

    waited = wait_for_approval_requests(
        store=store,
        request_ids=["request-deny"],
        timeout_seconds=0,
    )
    assert waited["resolved"] is True
    waited_items = waited["items"]
    assert isinstance(waited_items, list)
    assert isinstance(waited_items[0], dict)
    assert waited_items[0]["resolution_action"] == "block"
    payload: dict[str, object] = {"approval_requests": [{"request_id": "request-deny"}]}
    assert (
        wait_for_grok_live_approval(
            event_name="PreToolUse",
            policy_action="require-reapproval",
            response_payload=payload,
            store=store,
            timeout_seconds=1,
            json_mode=False,
        )
        == "block"
    )


def test_staged_snapshot_substitution_is_rejected_before_sqlite_application(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _Store(_request())
    monkeypatch.setattr(native, "native_runtime_status", _status)
    monkeypatch.setattr(native, "_isolated_environment", lambda: {})

    def substitute_and_respond(**kwargs: object) -> bytes:
        guard_home = cast(Path, kwargs["guard_home"])
        path = guard_home / "native-runtime" / "workspace-review-requests" / "request-1.json"
        substituted = json.loads(path.read_text(encoding="utf-8"))
        substituted["action"]["raw_command_text"] = "git log --oneline"
        path.write_bytes(native._canonical_json_bytes(substituted))
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

    monkeypatch.setattr(native, "native_resident_client_request", substitute_and_respond)
    with pytest.raises(native.NativeWorkspaceReviewError) as error:
        native.apply_native_workspace_review_decision(
            store,
            tmp_path,
            "request-1",
            {"signed": "native-envelope"},
        )
    assert error.value.code == "native_workspace_review_response_invalid"
    assert store.request["status"] == "pending"


def test_request_selector_rejects_path_traversal(tmp_path: Path) -> None:
    with pytest.raises(native.NativeWorkspaceReviewError) as error:
        native.stage_workspace_review_request(_Store(_request("../escape")), tmp_path, "../escape")
    assert error.value.code == "native_workspace_review_request_invalid"


def test_native_apply_is_reachable_from_cloud_review_cli() -> None:
    parser = _build_parser("hol-guard", program_mode="combined")
    args = parser.parse_args(["guard", "cloud-review", "native-apply", "--request-id", "request-1", "--json"])
    assert args.cloud_review_command == "native-apply"
    assert args.request_id == "request-1"


def test_native_apply_fails_closed_after_local_cloud_review_disable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    store = _Store(_request())
    store.sync_payloads[EXACT_CLOUD_REVIEW_REVOCATION_STATE_KEY] = {"revoked": True}
    monkeypatch.setattr(
        native,
        "apply_native_workspace_review_decision",
        lambda *args, **kwargs: pytest.fail("native apply must be gated after local disable"),
    )
    args = _build_parser("hol-guard", program_mode="combined").parse_args(
        ["guard", "cloud-review", "native-apply", "--request-id", "request-1", "--json"]
    )
    result = _run_guard_cloud_review_command(
        args,
        guard_home=tmp_path,
        store=cast(GuardStore, cast(object, store)),
        input_text="{}",
    )
    assert result == 2
    assert "native_workspace_review_cloud_review_disabled" in capsys.readouterr().out


def test_native_runtime_rejects_local_disable_before_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _Store(_request())
    store.sync_payloads[EXACT_CLOUD_REVIEW_REVOCATION_STATE_KEY] = {"revoked": True}
    monkeypatch.setattr(native, "_native_response", lambda **kwargs: pytest.fail("verification must not run"))
    with pytest.raises(native.NativeWorkspaceReviewError) as error:
        native.apply_native_workspace_review_decision(store, tmp_path, "request-1", {})
    assert error.value.code == "native_workspace_review_cloud_review_disabled"


def test_native_sqlite_application_rechecks_local_disable(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_payload(EXACT_CLOUD_REVIEW_REVOCATION_STATE_KEY, {"revoked": True}, "2026-09-26T00:00:00Z")
    result = store.resolve_native_workspace_review_request(
        "request-1",
        resolution_action="allow",
        expected_request=_request(),
        resolved_at="2026-09-26T00:00:00Z",
        native_replayed=False,
    )
    assert result == {"resolved": False, "error": "native_workspace_review_cloud_review_disabled"}
