from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from hashlib import sha256
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.codex_live_decision import (
    complete_codex_live_decision,
    resolve_codex_live_allow_authority,
)
from codex_plugin_scanner.guard.local_authority_integrity import sign_local_authority_payload
from codex_plugin_scanner.guard.native_guard_store import NativeGuardStoreUnavailable
from codex_plugin_scanner.guard.runtime.exact_cloud_review import enable_exact_cloud_review
from codex_plugin_scanner.guard.runtime.exact_cloud_review_apply import apply_exact_cloud_review
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_exact_cloud_local_once import StoreExactCloudLocalOnceMixin
from tests.guard_exact_cloud_review_support import (
    connected_exact_review_store,
    remote_approval,
)
from tests.test_codex_live_decision import _seed_waiting_request


def _workspace_key(value: str) -> str:
    return f"workspace:{sha256(str(Path(value).resolve()).encode('utf-8')).hexdigest()}"


def test_new_legacy_local_once_authority_preserves_generic_package_path(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    approval_id = store.record_local_once_approval(
        request_id="legacy-local-request",
        harness="codex",
        artifact_id="codex:project:tool-action:legacy",
        artifact_hash="hash-legacy",
        workspace="/workspace/repo",
        publisher=None,
        action="allow",
        created_at="2026-07-17T12:00:00+00:00",
        expires_at="2026-07-17T14:00:00+00:00",
    )
    assert approval_id is not None
    lookup = store.resolve_policy_decision_lookup(
        "codex",
        "codex:project:tool-action:legacy",
        artifact_hash="hash-legacy",
        workspace="/workspace/repo",
        now="2026-07-17T12:30:00+00:00",
        consume_one_shot=False,
    )
    assert lookup["decision"] is not None
    assert lookup["decision"]["authority_kind"] == "legacy"


def test_valid_old_mac_without_provenance_is_quarantined(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    key, key_id = store._policy_integrity_secret_material(create=True)  # pyright: ignore[reportPrivateUsage]
    assert key is not None and key_id is not None
    row = {
        "approval_id": "old-mac-row",
        "request_id": "old-exact-cloud-request",
        "harness": "codex",
        "artifact_id": "codex:project:tool-action:old",
        "artifact_hash": "hash-old",
        "workspace": _workspace_key("/workspace/repo"),
        "publisher": None,
        "action": "allow",
        "created_at": "2026-07-17T12:00:00+00:00",
        "expires_at": "2026-07-17T14:00:00+00:00",
        "claimed_at": None,
    }
    integrity = sign_local_authority_payload(
        row,
        key=key,
        key_id=key_id,
        purpose="guard-local-once-approval",
        signed_at=str(row["created_at"]),
    )
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            """
            insert into guard_local_once_approvals (
              approval_id, request_id, harness, artifact_id, artifact_hash, workspace, publisher, action,
              created_at, expires_at, claimed_at, integrity_version, payload_hash, payload_mac,
              integrity_key_id, signed_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                *row.values(),
                integrity["integrity_version"],
                integrity["payload_hash"],
                integrity["payload_mac"],
                integrity["integrity_key_id"],
                integrity["signed_at"],
            ),
        )

    lookup = store.resolve_policy_decision_lookup(
        "codex",
        "codex:project:tool-action:old",
        artifact_hash="hash-old",
        workspace="/workspace/repo",
        now="2026-07-17T12:30:00+00:00",
        consume_one_shot=False,
    )
    assert lookup["decision"] is None
    ignored = lookup["ignored_local_integrity"]
    assert isinstance(ignored, dict)
    assert ignored["integrity_status"] == "ambiguous_legacy"


def test_live_completion_consumes_only_original_exact_cloud_request(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    shared_artifact_id = "codex:project:identical-artifact"
    shared_artifact_hash = "hash-identical-artifact"
    store, _ = _seed_waiting_request(
        tmp_path,
        request_id="exact-live-original",
        store=store,
        artifact_id=shared_artifact_id,
        artifact_hash=shared_artifact_hash,
    )
    store, sibling_now = _seed_waiting_request(
        tmp_path,
        request_id="exact-live-sibling",
        store=store,
        artifact_id=shared_artifact_id,
        artifact_hash=shared_artifact_hash,
        target_path="/workspace/project/other.txt",
    )
    enable_exact_cloud_review(store)
    resolution = apply_exact_cloud_review(
        store,
        remote_approval=remote_approval(store, "exact-live-original", receipt_id="exact-live-receipt"),
    )
    resolved_at = str(resolution.resolved_request["resolved_at"])
    assert store.resolve_one_request_only(
        "exact-live-sibling",
        resolution_action="allow",
        resolution_scope="artifact",
        reason="identical artifact must remain request-bound",
        resolved_at=sibling_now,
    )

    sibling_result = complete_codex_live_decision(
        store,
        request_id="exact-live-sibling",
        now=sibling_now,
        fresh_allow_authorized=True,
    )
    assert sibling_result == {"completed": False, "error": "exact_approval_authority_missing"}
    assert _live_authority(store, "exact-live-original", resolved_at) is not None

    original_result = complete_codex_live_decision(
        store,
        request_id="exact-live-original",
        now=resolved_at,
        fresh_allow_authorized=True,
    )
    assert original_result["completed"] is True
    assert original_result["action"] == "allow"
    assert _live_authority(store, "exact-live-original", resolved_at) is None
    resume = store.get_request_resume("exact-live-original")
    assert resume is not None and resume["status"] == "sent"


def _live_authority(store: GuardStore, request_id: str, now: str) -> dict[str, object] | None:
    request = store.get_approval_request(request_id)
    assert request is not None
    return resolve_codex_live_allow_authority(store, request=request, request_id=request_id, now=now)


class _Evidence:
    def __init__(self, degraded: bool) -> None:
        self.degraded_trust_status = {"status": "degraded"} if degraded else None


class _OneCallStore(StoreExactCloudLocalOnceMixin):
    def __init__(
        self,
        *,
        key: bool = True,
        degraded: bool = False,
        evidence_error: Exception | None = None,
        reply: object = None,
    ) -> None:
        self.key = key
        self.degraded = degraded
        self.evidence_error = evidence_error
        self.reply = reply
        self.steps: list[object] = []

    def _policy_integrity_secret_material(self, *, create: bool) -> tuple[bytes | None, str | None]:
        assert create is False
        return (b"k" * 32, "key-1") if self.key else (None, None)

    def _provision_resident_verifier(self, key: bytes | None = None) -> None:
        self.steps.append(("provision", key))

    def policy_lookup_evidence(self, *, now: str | None = None) -> _Evidence:
        self.steps.append(("evidence", now))
        if self.evidence_error is not None:
            raise self.evidence_error
        return _Evidence(self.degraded)

    def policy_decision_lookup_request(
        self,
        evidence: object,
        *,
        harness: str,
        artifact_id: str | None,
        artifact_hash: str | None,
        workspace: str | None,
        publisher: str | None,
        runtime_exact_match_context: str | None,
        consume_one_shot: bool,
    ) -> dict[str, object]:
        self.steps.append(("lookup", {"workspace": workspace, "consume_one_shot": consume_one_shot}))
        return {
            "schema": "guard-policy-decision-lookup-request.v1",
            "integrity_key_b64": "a2V5",
            "integrity_key_id": "key-1",
            "local_once_integrity_key_b64": "a2V5",
            "local_once_integrity_key_id": "key-1",
        }

    def _native_store_call(self, method: str, args: Mapping[str, object]) -> object:
        self.steps.append((method, dict(args)))
        if self.reply is None:
            raise NativeGuardStoreUnavailable("dropped")
        return self.reply


def _authority(store: _OneCallStore) -> dict[str, object] | None:
    request = {
        "request_id": "r1",
        "harness": "codex",
        "artifact_id": "codex:bash",
        "artifact_hash": "sha256:abc",
        "workspace": "/work/a",
    }
    return store.codex_live_allow_authority(request, now="2026-10-30T00:00:00+00:00")


def test_live_authority_asks_the_resident_once_with_a_non_consuming_lookup() -> None:
    store = _OneCallStore()
    with pytest.raises(NativeGuardStoreUnavailable):
        _authority(store)

    assert store.steps[0] == ("evidence", "2026-10-30T00:00:00+00:00")
    lookup = store.steps[1]
    assert isinstance(lookup, tuple) and lookup[0] == "lookup"
    assert store.steps[2] == ("provision", b"k" * 32)
    assert lookup[1]["consume_one_shot"] is False
    assert lookup[1]["workspace"] == "/work/a"
    calls = [step for step in store.steps if isinstance(step, tuple) and step[0] == "codex_live_allow_authority"]
    assert len(calls) == 1
    args = calls[0][1]
    assert args["request_id"] == "r1"
    assert args["integrity_key_id"] == "key-1"
    # Key bytes stay out of the digested lookup; only their ids remain.
    assert args["lookup"] == {
        "schema": "guard-policy-decision-lookup-request.v1",
        "integrity_key_id": "key-1",
        "local_once_integrity_key_id": "key-1",
    }


def test_live_authority_without_trusted_evidence_reads_only_the_exact_cloud_allow() -> None:
    store = _OneCallStore(key=False, degraded=True)
    with pytest.raises(NativeGuardStoreUnavailable):
        _authority(store)

    (call,) = [step for step in store.steps if isinstance(step, tuple) and step[0] == "codex_live_allow_authority"]
    assert "lookup" not in call[1]
    assert "integrity_key_b64" not in call[1]
    assert not any(isinstance(step, tuple) and step[0] in {"provision", "lookup"} for step in store.steps)


def test_live_authority_reads_the_exact_cloud_allow_when_evidence_fails() -> None:
    allow = {"action": "allow", "source": "approval-gate-once", "request_id": "r1"}
    store = _OneCallStore(evidence_error=OSError("policy store unreadable"), reply=allow)

    assert _authority(store) == allow
    (call,) = [step for step in store.steps if isinstance(step, tuple) and step[0] == "codex_live_allow_authority"]
    assert "lookup" not in call[1]


def test_live_authority_without_an_exact_allow_reports_the_evidence_failure() -> None:
    store = _OneCallStore(evidence_error=OSError("policy store unreadable"), reply=[])

    with pytest.raises(OSError, match="policy store unreadable"):
        _authority(store)
    assert sum(1 for step in store.steps if isinstance(step, tuple) and step[0] == "codex_live_allow_authority") == 1


def _complete(store: _OneCallStore, *, action: str, fresh: bool) -> dict[str, object]:
    request = {
        "request_id": "r1",
        "harness": "codex",
        "artifact_id": "codex:bash",
        "artifact_hash": "sha256:abc",
        "workspace": "/work/a",
        "resolution_action": action,
    }
    return store.complete_codex_live_decision(request, now="2026-10-30T00:00:00+00:00", fresh_allow_authorized=fresh)


def _completion_call(store: _OneCallStore) -> dict[str, object]:
    (call,) = [step for step in store.steps if isinstance(step, tuple) and step[0] == "complete_codex_live_decision"]
    return call[1]


def test_live_completion_of_a_fresh_allow_carries_its_authority_lookup() -> None:
    store = _OneCallStore(reply={"completed": True, "action": "allow"})

    assert _complete(store, action="allow", fresh=True) == {"completed": True, "action": "allow"}
    args = _completion_call(store)
    assert args["fresh_allow_authorized"] is True
    assert args["integrity_key_id"] == "key-1"
    assert args["lookup"] == {
        "schema": "guard-policy-decision-lookup-request.v1",
        "integrity_key_id": "key-1",
        "local_once_integrity_key_id": "key-1",
    }


def test_live_completion_of_a_block_sends_no_authority() -> None:
    store = _OneCallStore(reply={"completed": True, "action": "block"})

    _complete(store, action="block", fresh=True)
    args = _completion_call(store)
    assert set(args) == {"request_id", "now", "cwd", "fresh_allow_authorized"}
    assert not any(isinstance(step, tuple) and step[0] in {"evidence", "lookup", "provision"} for step in store.steps)


def test_live_completion_without_an_exact_allow_reports_the_evidence_failure() -> None:
    store = _OneCallStore(
        evidence_error=OSError("policy store unreadable"),
        reply={"completed": False, "error": "exact_approval_authority_missing"},
    )

    with pytest.raises(OSError, match="policy store unreadable"):
        _complete(store, action="allow", fresh=True)


def test_live_completion_without_a_resident_reply_is_not_recorded() -> None:
    store = _OneCallStore(reply=[])

    assert _complete(store, action="allow", fresh=False) == {"completed": False, "error": "continuation_not_recorded"}
