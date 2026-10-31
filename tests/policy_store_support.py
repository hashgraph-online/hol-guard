"""Policy-store conveniences only tests use.

Production resolves saved decisions through the resident's non-consuming
probe groups and writes Cloud policies through the signed policy-bundle
authority. These helpers keep the older one-call shapes for fixtures that seed
or read a store directly, including the consuming direct, exact-command and
memory-pattern probe order.
"""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from typing import cast

from codex_plugin_scanner.guard.approval_gate_types import ApprovalGateGrant
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.native_hook_artifact_compose import native_hook_compose
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_base import (
    _SCOPED_RUNTIME_EXACT_FAMILIES,
    PolicyDecisionLookupResult,
    _artifact_family_key,
    _family_key_value,
)
from codex_plugin_scanner.guard.store_policy import _DEGRADED_AUTHORITY_REVISION, memory_lookup_candidates


def _remembered_rules_disabled(lookup: PolicyDecisionLookupResult) -> bool:
    trust = lookup.get("trust_status")
    return (
        lookup["decision"] is None
        and lookup["authority_revision"] == _DEGRADED_AUTHORITY_REVISION
        and isinstance(trust, dict)
        and trust.get("remembered_rules") == "disabled_degraded"
    )


def _most_restrictive(store: GuardStore, lookups: list[PolicyDecisionLookupResult]) -> PolicyDecisionLookupResult:
    if len(lookups) == 1 and lookups[0]["decision"] is None:
        return lookups[0]
    composed = native_hook_compose(
        "policy_lookup_select",
        {"lookups": [dict(lookup) for lookup in lookups]},
        guard_home=Path(store.guard_home),
    )
    return cast("PolicyDecisionLookupResult", cast("object", composed))


def resolve_policy_lookup(
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
) -> PolicyDecisionLookupResult:
    """Probe the direct, exact-command and memory-pattern ids one lookup at a time.

    Consuming, the first matched probe wins; peeking, the resident selects the
    most restrictive of them.
    """

    def lookup(candidate_id: str | None) -> PolicyDecisionLookupResult:
        return store.resolve_policy_decision_lookup(
            harness,
            candidate_id,
            artifact_hash=artifact_hash,
            workspace=workspace,
            publisher=publisher,
            now=now,
            consume_one_shot=consume_one_shot,
        )

    def matched(candidate: PolicyDecisionLookupResult) -> bool:
        return candidate["decision"] is not None or candidate.get("ignored_local_integrity") is not None

    direct_lookup = lookup(artifact_id)
    if _remembered_rules_disabled(direct_lookup) or (consume_one_shot and matched(direct_lookup)):
        return direct_lookup
    exact_command_artifact_ids, memory_artifact_id = memory_lookup_candidates(
        harness,
        artifact_id,
        memory_command=memory_command,
        memory_artifact_type=memory_artifact_type,
        memory_artifact_name=memory_artifact_name,
        guard_home=Path(store.guard_home),
    )
    candidate_lookups = [direct_lookup]
    for exact_command_artifact_id in exact_command_artifact_ids:
        exact_command_lookup = lookup(exact_command_artifact_id)
        if consume_one_shot and matched(exact_command_lookup):
            return exact_command_lookup
        candidate_lookups.append(exact_command_lookup)
    if memory_artifact_id is None:
        return _most_restrictive(store, candidate_lookups)
    memory_lookup = lookup(memory_artifact_id)
    if consume_one_shot:
        return memory_lookup if matched(memory_lookup) else direct_lookup
    return _most_restrictive(store, [*candidate_lookups, memory_lookup])


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
    lookup = resolve_policy_lookup(
        store,
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


def runtime_tool_action_policy_artifact_id(artifact_id: str | None) -> str | None:
    """Return a scoped family identity for one exact runtime tool action."""

    if artifact_id is None or not artifact_id.strip():
        return None
    family_key = _artifact_family_key(artifact_id)
    if family_key is not None and _family_key_value(family_key) in _SCOPED_RUNTIME_EXACT_FAMILIES:
        return artifact_id
    digest = sha256(artifact_id.strip().encode("utf-8")).hexdigest()
    return f"guard:runtime:tool-action:{digest}"
