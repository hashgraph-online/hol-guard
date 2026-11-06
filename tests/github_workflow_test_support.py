"""Fixture builders for GitHub workflow control-plane tests.

Rust owns operation parsing, context collection and digest derivation; its
parity vectors cover that. These builders only synthesise the sanitized record
the native side would return, so the Python claim/store plumbing can be driven
without a resident.
"""

from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.github_workflow_approval_record import (
    GITHUB_WORKFLOW_APPROVAL_RECORD_SCHEMA,
    GitHubWorkflowApprovalRecord,
)
from codex_plugin_scanner.guard.workflow_capabilities import (
    WorkflowCapabilityBinding,
    WorkflowCapabilityRuleBinding,
)
from tests.workflow_capability_frame_support import canonical_framed_payload

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


def approval_record(
    command: str = LOCK_COMMAND,
    *,
    operation: str = "lock-issue",
    resource_type: str = "github-issue",
    resource: str = "17",
    **binding_changes: object,
) -> GitHubWorkflowApprovalRecord:
    identity = parse_shell_command(command).security_identity
    return GitHubWorkflowApprovalRecord(
        schema_version=GITHUB_WORKFLOW_APPROVAL_RECORD_SCHEMA,
        operation_kind=operation,
        resource_type=resource_type,
        command_identity_sha256=framed_digest("github-workflow-command-identity", identity),
        operation_digest_sha256=framed_digest("github-workflow-operation-digest", f"{identity}:{resource}"),
        binding=binding(operation=operation, resource_type=resource_type, resource=resource, **binding_changes),
    )
