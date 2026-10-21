"""Fixture builders for GitHub workflow control-plane tests.

Rust owns operation parsing, context collection and digest derivation; its
parity vectors cover that. These builders only synthesise the sanitized record
the native side would return, so the Python claim/store plumbing can be driven
without a resident.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_github_workflow import GitHubWorkflowDescriptor, GitHubWorkflowLineage
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.github_workflow_approval_record import (
    GITHUB_WORKFLOW_APPROVAL_RECORD_SCHEMA,
    GitHubWorkflowApprovalRecord,
)
from codex_plugin_scanner.guard.workflow_capabilities import (
    WorkflowCapabilityBinding,
    WorkflowCapabilityRuleBinding,
    canonical_framed_payload,
)

REPOSITORY = "example/repo"
LOCK_COMMAND = f"gh issue lock 17 --repo {REPOSITORY}"
THREAD_COMMAND = (
    "gh api graphql -f "
    "query='mutation($threadId:ID!){resolveReviewThread(input:{threadId:$threadId}){thread{id}}}' "
    "-f threadId=THREAD_1"
)


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def framed_digest(purpose: str, payload: object) -> str:
    return hashlib.sha256(canonical_framed_payload(purpose, payload)).hexdigest()


def capability_id(request_id: str) -> str:
    """The id a workflow capability for ``request_id`` is stored under.

    Spelled out here rather than imported from the runtime, so a drift in the
    resident's derivation fails a test instead of silently renaming every
    capability the store already holds.
    """

    return f"gwc-{framed_digest('github-workflow-capability', request_id)}"


def binding(
    *,
    operation: str = "lock-issue",
    resource_type: str = "github-issue",
    resource: str = "17",
    repository: str = REPOSITORY,
    **changes: object,
) -> WorkflowCapabilityBinding:
    base = WorkflowCapabilityBinding(
        operation_id=f"github.{operation}.v1",
        resource_type=resource_type,
        resource_sha256=framed_digest("github-workflow-resource", resource),
        repository_sha256=framed_digest("github-workflow-repository", repository),
        workspace_sha256=framed_digest("github-workspace", str(Path("/workspace").resolve())),
        executable_sha256=digest("executable"),
        launch_sha256=digest("launch"),
        policy_id="guard.command-policy",
        policy_version="policy.v1",
        effect_id="github.maintain-remote",
        effect_version="effect.v1",
        decision_id="github.workflow-authorized",
        decision_version="decision.v1",
        rules=(WorkflowCapabilityRuleBinding("github.maintain-remote", "rule.v1"),),
    )
    return replace(base, **changes)  # type: ignore[arg-type]


def descriptor(
    command: str = LOCK_COMMAND,
    *,
    operation: str = "lock-issue",
    resource_type: str = "github-issue",
    resource: str = "17",
    **binding_changes: object,
) -> GitHubWorkflowDescriptor:
    identity = parse_shell_command(command).security_identity
    record = GitHubWorkflowApprovalRecord(
        schema_version=GITHUB_WORKFLOW_APPROVAL_RECORD_SCHEMA,
        operation_kind=operation,
        resource_type=resource_type,
        command_identity_sha256=framed_digest("github-workflow-command-identity", identity),
        operation_digest_sha256=framed_digest("github-workflow-operation-digest", f"{identity}:{resource}"),
        binding=binding(operation=operation, resource_type=resource_type, resource=resource, **binding_changes),
    )
    return GitHubWorkflowDescriptor(record=record, command_identity=identity)


def with_binding(source: GitHubWorkflowDescriptor, **changes: object) -> GitHubWorkflowDescriptor:
    return replace(source, record=replace(source.record, binding=replace(source.record.binding, **changes)))  # type: ignore[arg-type]


@pytest.fixture
def native_lineage_verified(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stand in for the resident's lineage verdict so the store plumbing can be driven.

    The resident decides whether the three rows are one lineage; every way that
    decision can go against the request is covered by
    `guard-command`'s `github_workflow_lineage_tests`. This stub says yes and
    reads back the identities the rows already carry -- it compares nothing, so
    it cannot drift into a second Python oracle for the verdict.
    """
    import codex_plugin_scanner.guard.runtime.github_workflow_runtime as runtime_module

    def verified(
        approval_request: Mapping[str, object],
        operation: Mapping[str, object],
        session: Mapping[str, object],
        **_kwargs: object,
    ) -> GitHubWorkflowLineage | None:
        record = runtime_module.approval_record_from_approval_request(approval_request)
        if record is None:
            return None
        request_id = str(approval_request["request_id"])
        return GitHubWorkflowLineage(
            request_id=request_id,
            operation_id=str(operation["operation_id"]),
            session_id=str(session["session_id"]),
            record=record,
            capability_id=f"gwc-{framed_digest('github-workflow-capability', request_id)}",
            nonce=framed_digest("github-workflow-nonce", request_id),
        )

    monkeypatch.setattr(runtime_module, "github_workflow_validated_lineage", verified)
