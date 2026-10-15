# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false
# pyright: reportUnknownLambdaType=false, reportUnusedCallResult=false

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.commands_hook_github_workflow import prepare_github_workflow_hook_state
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.models import GuardApprovalRequest, GuardArtifact, GuardReceipt
from codex_plugin_scanner.guard.native_github_workflow import GitHubWorkflowDescriptor
from codex_plugin_scanner.guard.runtime.github_workflow_approval_record import GitHubWorkflowApprovalRecord
from codex_plugin_scanner.guard.runtime.github_workflow_authorization import issue_github_workflow_capability_binding
from codex_plugin_scanner.guard.runtime.github_workflow_runtime import approval_record_from_approval_request
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.workflow_capabilities import format_utc_timestamp
from tests.github_workflow_test_support import descriptor as build_descriptor

_NOW = datetime.now(timezone.utc)
_REPOSITORY = "privacy-owner/privacy-repo"
_THREAD = "PRRT_PRIVACY_SENTINEL"
_PATH_SENTINEL = "/private/privacy-path-sentinel"
_VIEWER = "privacy-viewer-sentinel"


def _descriptor() -> GitHubWorkflowDescriptor:
    return build_descriptor(
        "gh api graphql -f "
        "query='mutation($threadId:ID!){resolveReviewThread(input:{threadId:$threadId}){thread{id __typename}}}' "
        f"-f threadId={_THREAD}",
        operation="resolve-review-thread",
        resource_type="github-review-thread",
        resource=_THREAD,
        repository=_REPOSITORY,
    )


def test_persisted_approval_receipt_and_events_expose_only_sanitized_record(tmp_path: Path) -> None:
    now = datetime.now(timezone.utc)
    record = _descriptor().record
    evidence: tuple[dict[str, object], ...] = (
        {"source": "github_workflow_approval_record", "record": record.to_dict()},
    )
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    store.add_approval_request(
        GuardApprovalRequest(
            request_id="request-privacy",
            harness="codex",
            artifact_id="codex:project:tool-action:github",
            artifact_name="GitHub workflow",
            artifact_hash="guard-approval-context:v1:privacy",
            policy_action="require-reapproval",
            recommended_scope="artifact",
            changed_fields=("tool_action_request",),
            source_scope="project",
            config_path="redacted",
            workspace=None,
            artifact_type="tool_action_request",
            review_command="hol-guard approvals approve request-privacy",
            approval_url="http://127.0.0.1/requests/request-privacy",
            scanner_evidence=evidence,
            raw_command_text=None,
        ),
        format_utc_timestamp(_NOW),
    )
    store.add_receipt(
        GuardReceipt(
            receipt_id="receipt-privacy",
            timestamp=format_utc_timestamp(_NOW),
            harness="codex",
            artifact_id="codex:project:tool-action:github",
            artifact_hash="guard-approval-context:v1:privacy",
            policy_decision="require-reapproval",
            capabilities_summary="GitHub workflow",
            changed_capabilities=(),
            provenance_summary="Guard",
            scanner_evidence=evidence,
        )
    )
    key, key_id = store._policy_integrity_secret_material(create=True)
    assert key is not None and key_id is not None
    issue_github_workflow_capability_binding(
        store,
        record.binding,
        capability_id="privacy-capability",
        approval_provenance_id="request-privacy",
        task_id="operation-privacy",
        nonce="a" * 32,
        issuer_id="guard.local",
        subject_id="session-privacy",
        issued_at=format_utc_timestamp(_NOW),
        not_before=format_utc_timestamp(_NOW),
        expires_at=format_utc_timestamp(now + timedelta(hours=1)),
        max_uses=1,
        key=key,
        key_id=key_id,
    )
    approval = store.get_approval_request("request-privacy")
    assert approval is not None
    surfaces = {
        "approval_api": approval["scanner_evidence"],
        "receipt_api": store.list_receipts(limit=1)[0]["scanner_evidence"],
        "events": store.list_events(event_name="workflow_capability.issued"),
    }
    encoded = json.dumps(surfaces, sort_keys=True)
    for sentinel in (_REPOSITORY, _THREAD, _PATH_SENTINEL, _VIEWER):
        assert sentinel not in encoded
    assert "resource_sha256" in encoded
    assert "repository_sha256" in encoded


def test_raw_descriptor_or_extra_sensitive_record_fields_fail_closed() -> None:
    descriptor = _descriptor()
    assert (
        approval_record_from_approval_request(
            {"scanner_evidence": [{"source": "github_workflow_descriptor", "descriptor": asdict(descriptor)}]}
        )
        is None
    )
    payload = descriptor.record.to_dict()
    payload["repository"] = _REPOSITORY
    with pytest.raises(ValueError):
        GitHubWorkflowApprovalRecord.from_dict(payload)


def test_hook_artifact_metadata_persists_only_sanitized_record(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import codex_plugin_scanner.guard.cli.commands_hook_github_workflow as workflow_hook

    descriptor = _descriptor()
    monkeypatch.setattr(workflow_hook, "_runtime_github_workflow_descriptor", lambda *_args, **_kwargs: descriptor)
    artifact = GuardArtifact(
        artifact_id="codex:project:tool-action:github",
        name="GitHub workflow",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path="redacted",
        command=None,
    )
    state = prepare_github_workflow_hook_state(
        artifact,
        workspace=tmp_path,
        guard_home=tmp_path / "guard",
        config=GuardConfig(guard_home=tmp_path / "guard", workspace=tmp_path),
        store=GuardStore(tmp_path / "guard", prime_policy_integrity=False),
        approval_request_id=None,
    )
    encoded = json.dumps(state.artifact.metadata, sort_keys=True)
    for sentinel in (_REPOSITORY, _THREAD, _PATH_SENTINEL, _VIEWER):
        assert sentinel not in encoded
    assert "github_workflow_approval_record" in encoded
