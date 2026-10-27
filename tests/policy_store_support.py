"""Policy-store conveniences only tests use.

Production resolves saved decisions through
``resolve_policy_decision_lookup_with_memory_pattern`` and writes Cloud
policies through the signed policy-bundle authority. These helpers keep the
older one-call shapes for fixtures that seed or read a store directly.
"""

from __future__ import annotations

from codex_plugin_scanner.guard.approval_gate_types import ApprovalGateGrant
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.store import GuardStore


def resolve_policy(
    store: GuardStore,
    harness: str,
    artifact_id: str | None,
    artifact_hash: str | None = None,
    workspace: str | None = None,
    publisher: str | None = None,
    now: str | None = None,
    *,
    memory_command: str | None = None,
    memory_artifact_type: str | None = None,
    memory_artifact_name: str | None = None,
    consume_one_shot: bool = True,
) -> str | None:
    lookup = store.resolve_policy_decision_lookup_with_memory_pattern(
        harness,
        artifact_id,
        artifact_hash=artifact_hash,
        workspace=workspace,
        publisher=publisher,
        now=now,
        memory_command=memory_command,
        memory_artifact_type=memory_artifact_type,
        memory_artifact_name=memory_artifact_name,
        consume_one_shot=consume_one_shot,
    )
    decision = lookup["decision"]
    return str(decision["action"]) if decision is not None else None


def replace_remote_policies(
    store: GuardStore,
    decisions: list[PolicyDecision],
    now: str,
    *,
    approval_gate_grant: ApprovalGateGrant | None = None,
    remote_write_authorized: bool = False,
) -> None:
    now, rows = store._prepared_remote_policy_rows(
        decisions,
        now,
        approval_gate_grant=approval_gate_grant,
        remote_write_authorized=remote_write_authorized,
    )
    with store._connect() as connection:
        store._replace_remote_policy_rows_locked(connection, rows)
