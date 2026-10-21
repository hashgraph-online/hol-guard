# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportUnusedCallResult=false

from __future__ import annotations

import json
import shlex
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.approval_scope_support import request_scope_contract
from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.native_approval_resolution import native_approval_resolution_plan
from codex_plugin_scanner.guard.native_github_workflow import GitHubWorkflowDescriptor
from codex_plugin_scanner.guard.runtime.effect_decision import FinalDisposition
from codex_plugin_scanner.guard.runtime.github_capability_interaction import GITHUB_MAINTENANCE_ACTION_CLASS
from codex_plugin_scanner.guard.runtime.github_workflow_runtime import (
    claim_resolved_github_workflow_authorization,
    github_workflow_capability_required,
    issue_resolved_github_workflow_capability,
)
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_workflow_capability_common import WORKFLOW_CAPABILITY_STORE_CLOCK
from codex_plugin_scanner.guard.workflow_capabilities import format_utc_timestamp
from tests.github_workflow_test_support import descriptor as build_descriptor
from tests.github_workflow_test_support import digest as _digest
from tests.github_workflow_test_support import native_lineage_verified as native_lineage_verified
from tests.github_workflow_test_support import with_binding
from tests.native_workflow_test_support import evaluate_native_workflow_command

_ISSUED = datetime(2026, 7, 20, 12, tzinfo=timezone.utc)
_GH_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "github-workflow" / "gh"
_COMMAND = f"{shlex.quote(str(_GH_FIXTURE))} issue lock 17 --repo example/repo"


@pytest.fixture(autouse=True)
def fixed_authority(monkeypatch: pytest.MonkeyPatch, native_lineage_verified: None) -> None:
    def authority(_store: object, **_kwargs: object) -> tuple[bytes, str]:
        return b"r" * 32, "guard-policy-integrity-key:github-runtime-test"

    monkeypatch.setattr(GuardStore, "_policy_integrity_secret_material", authority)
    monkeypatch.setattr(WORKFLOW_CAPABILITY_STORE_CLOCK, "now", lambda: format_utc_timestamp(_ISSUED))


def _descriptor(command: str = _COMMAND) -> GitHubWorkflowDescriptor:
    return build_descriptor(command)


def _seed_resolved_request(
    store: GuardStore,
    descriptor: GitHubWorkflowDescriptor,
    *,
    request_id: str = "request-github-1",
    action: str = "allow",
    linked: bool = True,
    resolved: bool = True,
) -> dict[str, object]:
    request = GuardApprovalRequest(
        request_id=request_id,
        harness="codex",
        artifact_id="codex:project:tool-action:github",
        artifact_name="Bash GitHub maintenance",
        artifact_hash="guard-approval-context:v1:test",
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("tool_action_request",),
        source_scope="project",
        config_path="/guard/config.toml",
        workspace="/workspace",
        artifact_type="tool_action_request",
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1/requests/{request_id}",
        scanner_evidence=(
            {
                "source": "github_workflow_approval_record",
                "record": descriptor.record.to_dict(),
            },
        ),
        raw_command_text=_COMMAND,
    )
    store.add_approval_request(request, format_utc_timestamp(_ISSUED))
    session = store.upsert_guard_session(
        session_id="session-github-1",
        harness="codex",
        surface="harness-adapter",
        status="waiting_on_approval",
        client_name="codex-hook",
        client_title=None,
        client_version=None,
        workspace="/workspace",
        capabilities=["approval-resolution"],
        now=format_utc_timestamp(_ISSUED),
    )
    if linked:
        _ = store.upsert_guard_operation(
            operation_id="operation-github-1",
            session_id=str(session["session_id"]),
            harness="codex",
            operation_type="tool_call",
            status="waiting_on_approval",
            approval_request_ids=[request_id],
            resume_token="resume-token",
            metadata={
                "command_text": _COMMAND,
                "hook_event_name": "PreToolUse",
                "workspace": "/workspace",
            },
            now=format_utc_timestamp(_ISSUED),
        )
    if resolved:
        with store._connect() as connection:
            connection.execute(
                """update approval_requests
                set status = 'resolved', resolution_action = ?, resolved_at = ?
                where request_id = ?""",
                (action, format_utc_timestamp(_ISSUED), request_id),
            )
    stored = store.get_approval_request(request_id)
    assert stored is not None
    return stored


def test_approval_resolution_issues_from_guard_owned_operation_lineage(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    descriptor = _descriptor()
    request = _seed_resolved_request(store, descriptor, resolved=False)

    resolved = apply_approval_resolution(
        store=store,
        request_id="request-github-1",
        action="allow",
        scope="artifact",
        workspace=None,
        reason="reviewed exact maintenance task",
        now=format_utc_timestamp(_ISSUED),
    )

    assert resolved["resolution_action"] == "allow"
    planned = native_approval_resolution_plan(
        request,
        guard_home=store.guard_home,
        action="allow",
        scope="artifact",
        persist_policy=None,
        temporary_mcp=False,
        local_tool=False,
        resolve_scope_matches=True,
        requires_local_once=False,
        resolved_workspace=None,
        native_exact_token=None,
        resolved_at=format_utc_timestamp(_ISSUED),
    )
    lookup = store.resolve_policy_decision_lookup(
        "codex",
        "codex:project:tool-action:github",
        artifact_hash=cast(Mapping[str, object], planned["decision"])["artifact_hash"],
        now=format_utc_timestamp(_ISSUED),
        consume_one_shot=False,
    )
    saved_decision = cast(Mapping[str, object], lookup["decision"])
    assert saved_decision["source"] == "approval-gate-once"
    assert saved_decision["request_id"] == "request-github-1"
    assert claim_resolved_github_workflow_authorization(store, "request-github-1", descriptor) is not None


def test_workflow_marker_lookup_errors_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)

    def fail_lookup(_request_id: str) -> None:
        raise OSError("unavailable")

    monkeypatch.setattr(store, "get_approval_request", fail_lookup)
    assert github_workflow_capability_required(store, "request-github-1")


def test_resolved_guard_lineage_issues_bounded_retry_capability(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    descriptor = _descriptor()
    request = _seed_resolved_request(store, descriptor)

    contract = request_scope_contract(request)
    assert contract.task_capability_eligible
    assert contract.task_capability_reason_codes == ("exact_github_workflow_record",)
    assert issue_resolved_github_workflow_capability(store, request, resolved_at=format_utc_timestamp(_ISSUED))
    assert issue_resolved_github_workflow_capability(store, request, resolved_at=format_utc_timestamp(_ISSUED))
    authorization = claim_resolved_github_workflow_authorization(store, "request-github-1", descriptor)
    assert authorization is not None
    evaluation = evaluate_native_workflow_command(
        _COMMAND,
        compatibility_action_class=GITHUB_MAINTENANCE_ACTION_CLASS,
        workflow_authorization=authorization,
    )
    assert evaluation.decision_plane.disposition is FinalDisposition.WORKFLOW_AUTHORIZED
    assert all(
        claim_resolved_github_workflow_authorization(store, "request-github-1", descriptor) is not None
        for _ in range(9)
    )
    assert claim_resolved_github_workflow_authorization(store, "request-github-1", descriptor) is None


@pytest.mark.parametrize("action,linked", (("block", True), ("allow", False)))
def test_blocked_or_unlinked_approval_never_issues(tmp_path: Path, action: str, linked: bool) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    request = _seed_resolved_request(store, _descriptor(), action=action, linked=linked)
    assert not issue_resolved_github_workflow_capability(store, request, resolved_at=format_utc_timestamp(_ISSUED))


def test_spoofed_ids_and_binding_drift_fail_closed(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    descriptor = _descriptor()
    request = _seed_resolved_request(store, descriptor)
    assert issue_resolved_github_workflow_capability(store, request, resolved_at=format_utc_timestamp(_ISSUED))
    assert claim_resolved_github_workflow_authorization(store, "payload-spoof", descriptor) is None
    assert not any(
        claim_resolved_github_workflow_authorization(
            store,
            "request-github-1",
            with_binding(descriptor, **{field: _digest(f"other-{field}")}),
        )
        is not None
        for field in ("workspace_sha256", "executable_sha256", "launch_sha256")
    )
    assert all(
        claim_resolved_github_workflow_authorization(store, "request-github-1", descriptor) is not None
        for _ in range(10)
    )
    assert claim_resolved_github_workflow_authorization(store, "request-github-1", descriptor) is None


def test_workflow_events_do_not_expose_remote_identity(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    descriptor = _descriptor()
    request = _seed_resolved_request(store, descriptor)
    assert issue_resolved_github_workflow_capability(store, request, resolved_at=format_utc_timestamp(_ISSUED))
    assert claim_resolved_github_workflow_authorization(store, "request-github-1", descriptor) is not None
    events = store.list_events(event_name="workflow_capability.issued") + store.list_events(
        event_name="workflow_capability.claimed"
    )
    encoded = json.dumps(events)
    assert "example/repo" not in encoded
    assert "issue lock 17" not in encoded
