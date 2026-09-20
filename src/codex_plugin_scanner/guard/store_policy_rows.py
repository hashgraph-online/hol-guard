"""Materialized policy row identity and source-scoped replacement operations."""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence

from .models import PolicyDecision
from .policy_integrity import BUNDLE_OWNED_POLICY_SOURCES, PolicyIntegrityVerificationResult, is_remote_policy_source
from .store_base import (
    _artifact_family_key,
    _is_approval_context_token,
    _is_runtime_scoped_exact_match_key,
    _scoped_runtime_row_requires_exact_match,
    _workspace_policy_key,
)


def materialized_policy_row_identity(row: sqlite3.Row) -> tuple[object, ...]:
    return (
        row["harness"],
        row["scope"],
        row["artifact_id"],
        row["artifact_hash"],
        row["workspace"],
        row["publisher"],
        row["exact_command_sha256"],
        row["action"],
        row["reason"],
        row["owner"],
        row["source"],
        row["expires_at"],
    )


def replace_remote_policy_rows_locked(
    connection: sqlite3.Connection,
    rows: Sequence[tuple[object, ...]],
    *,
    sources: Sequence[str] | None = None,
) -> None:
    selected = tuple(sorted(sources if sources is not None else BUNDLE_OWNED_POLICY_SOURCES))
    if selected:
        placeholders = "(" + ",".join("?" for _ in selected) + ")"
        connection.execute(
            f"delete from policy_decisions where source in {placeholders}",
            selected,
        )
    connection.executemany(
        """
        insert into policy_decisions (
          harness, scope, artifact_id, artifact_hash, workspace, publisher, exact_command_sha256,
          action, reason, owner, source,
          expires_at, updated_at, integrity_version, integrity_generation, payload_hash, payload_mac,
          integrity_key_id, signed_at
        )
        values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )


def runtime_policy_row_is_eligible(
    candidate,
    *,
    policy_bundle_decision_identities: frozenset[tuple[object, ...]],
    memory_decision_identities: frozenset[tuple[object, ...]],
    artifact_id: str | None,
    artifact_hash: str | None,
    runtime_exact_match_key: str | None,
    portable_runtime_exact_match_key: str | None,
    global_runtime_exact_match_key: str | None,
) -> bool:
    """Return True when a stored runtime policy row may serve this lookup."""

    if str(candidate["source"]) in {"cloud-sync", "team-policy"}:
        return False
    if (
        str(candidate["source"]) in {"policy-bundle", "policy-bundle-canonical"}
        and (*materialized_policy_row_identity(candidate), candidate["updated_at"])
        not in policy_bundle_decision_identities
    ):
        return False
    if (
        str(candidate["source"]) == "cloud-signed-memory"
        and (*materialized_policy_row_identity(candidate), candidate["updated_at"]) not in memory_decision_identities
    ):
        return False
    return not _scoped_runtime_row_requires_exact_match(
        scope=str(candidate["scope"]),
        stored_artifact_id=str(candidate["artifact_id"]) if isinstance(candidate["artifact_id"], str) else None,
        stored_artifact_hash=(str(candidate["artifact_hash"]) if isinstance(candidate["artifact_hash"], str) else None),
        source=str(candidate["source"]),
        requested_artifact_id=artifact_id,
        requested_artifact_hash=artifact_hash,
        requested_runtime_exact_match_key=runtime_exact_match_key,
        requested_portable_exact_match_key=portable_runtime_exact_match_key,
        requested_global_exact_match_key=global_runtime_exact_match_key,
    )


def policy_row_payload(
    row: sqlite3.Row,
    *,
    integrity_result: PolicyIntegrityVerificationResult | None = None,
    state: dict[str, object] | None = None,
) -> dict[str, object]:
    source = str(row["source"])
    payload: dict[str, object] = {
        "action": str(row["action"]),
        "artifact_hash": row["artifact_hash"],
        "artifact_id": row["artifact_id"],
        "decision_id": int(row["decision_id"]) if row["decision_id"] is not None else None,
        "expires_at": row["expires_at"],
        "harness": str(row["harness"]),
        "owner": row["owner"],
        "publisher": row["publisher"],
        "exact_command_sha256": row["exact_command_sha256"],
        "reason": row["reason"],
        "scope": str(row["scope"]),
        "source": source,
        "updated_at": str(row["updated_at"]),
        "workspace": row["workspace"],
    }
    if integrity_result is not None and not is_remote_policy_source(source):
        payload["integrity_status"] = integrity_result.status
        payload["integrity_message"] = integrity_result.message
    if state is not None and not is_remote_policy_source(source):
        payload["integrity_mode"] = state.get("mode")
        payload["integrity_enforcement"] = state.get("enforcement")
    if row["integrity_version"] is not None:
        payload["integrity_version"] = int(row["integrity_version"])
    if row["integrity_generation"] is not None:
        payload["integrity_generation"] = int(row["integrity_generation"])
    if row["integrity_key_id"] is not None:
        payload["integrity_key_id"] = str(row["integrity_key_id"])
    if row["signed_at"] is not None:
        payload["signed_at"] = str(row["signed_at"])
    return payload


def normalized_policy_keys(decision: PolicyDecision) -> tuple[str | None, str | None, str | None, str | None]:
    if decision.scope in {"harness", "global"}:
        artifact_id = _artifact_family_key(decision.artifact_id)
    else:
        artifact_id = decision.artifact_id if decision.scope in {"artifact", "workspace"} else None
    artifact_hash = (
        decision.artifact_hash
        if decision.scope in {"artifact", "workspace"}
        or _is_runtime_scoped_exact_match_key(decision.artifact_hash)
        or _is_approval_context_token(decision.artifact_hash)
        else None
    )
    workspace = _workspace_policy_key(decision.workspace) if decision.scope == "workspace" else None
    publisher = decision.publisher if decision.scope == "publisher" else None
    return artifact_id, artifact_hash, workspace, publisher
