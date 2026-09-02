"""Approval queue insert and deduplication writes."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping, Sequence

from .continuation_snapshot import non_resumable_continuation_snapshot, validated_continuation_snapshot
from .decision_boundaries import CanonicalApprovalSurfaces, canonical_approval_surfaces
from .models import GuardApprovalRequest
from .store_approvals import (
    _begin_immediate,
    _normalized_identity_key,
    approval_queue_identity_for_request,
)


def add_approval_request(
    connection: sqlite3.Connection,
    request: GuardApprovalRequest,
    now: str,
    *,
    oauth_source: str = "default",
) -> str:
    canonical_decision = canonical_approval_surfaces(
        request.policy_action,
        request.decision_v2_json,
        request.action_envelope_json,
        reject_contradiction=True,
    )
    _begin_immediate(connection)
    normalized_oauth_source = oauth_source.strip().lower() or "default"
    identity_key = _normalized_identity_key(request.launch_target)
    action_identity, queue_group_id = approval_queue_identity_for_request(request)
    request_id = _existing_request_id(
        connection,
        request,
        oauth_source=normalized_oauth_source,
        identity_key=identity_key,
        queue_group_id=queue_group_id,
    )
    if request_id is not None:
        _update_request(
            connection,
            request,
            canonical_decision,
            request_id=request_id,
            oauth_source=normalized_oauth_source,
            identity_key=identity_key,
            action_identity=action_identity,
            queue_group_id=queue_group_id,
            now=now,
        )
        return request_id
    _insert_request(
        connection,
        request,
        canonical_decision,
        oauth_source=normalized_oauth_source,
        identity_key=identity_key,
        action_identity=action_identity,
        queue_group_id=queue_group_id,
        now=now,
    )
    return request.request_id


def _existing_request_id(
    connection: sqlite3.Connection,
    request: GuardApprovalRequest,
    *,
    oauth_source: str,
    identity_key: str,
    queue_group_id: str,
) -> str | None:
    queries = (
        (
            """select request_id from approval_requests
               where queue_group_id = ? and harness = ? and oauth_source = ? and status = 'pending'
               order by last_seen_at desc, request_id desc limit 1""",
            (queue_group_id, request.harness, oauth_source),
        ),
        (
            """select request_id from approval_requests
               where harness = ? and oauth_source = ? and artifact_id = ? and workspace IS ?
                 and normalized_identity_key = ? and queue_group_id IS NULL and status = 'pending'
               order by created_at desc limit 1""",
            (request.harness, oauth_source, request.artifact_id, request.workspace, identity_key),
        ),
        (
            """select request_id from approval_requests
               where harness = ? and oauth_source = ? and artifact_id = ? and workspace IS ?
                 and launch_target IS ? and normalized_identity_key IS NULL and queue_group_id IS NULL
                 and status = 'pending' order by created_at desc limit 1""",
            (request.harness, oauth_source, request.artifact_id, request.workspace, request.launch_target),
        ),
    )
    for query, params in queries:
        row = connection.execute(query, params).fetchone()
        if row is not None:
            return str(row["request_id"])
    return None


def _update_request(
    connection: sqlite3.Connection,
    request: GuardApprovalRequest,
    canonical: CanonicalApprovalSurfaces,
    *,
    request_id: str,
    oauth_source: str,
    identity_key: str,
    action_identity: str,
    queue_group_id: str,
    now: str,
) -> None:
    connection.execute(
        """update approval_requests
           set harness = ?, artifact_name = ?, artifact_type = ?, artifact_hash = ?, publisher = ?, policy_action = ?,
               recommended_scope = ?, changed_fields_json = ?, source_scope = ?, config_path = ?, workspace = ?,
               launch_target = ?, normalized_identity_key = ?, action_identity = ?, queue_group_id = ?,
               dedupe_count = coalesce(dedupe_count, 1) + 1, last_seen_at = ?, transport = ?, risk_summary = ?,
               risk_signals_json = ?, artifact_label = ?, source_label = ?, trigger_summary = ?, why_now = ?,
               launch_summary = ?, risk_headline = ?, action_envelope_json = ?, decision_v2_json = ?,
               fallback_cli_command = ?, scanner_evidence_json = ?,
               watch_only_observation = case when watch_only_observation = 1 and ? = 1 then 1 else 0 end,
               browser_intent_json = ?, review_command = ?, approval_url = ?, raw_command_text = ?, guard_version = ?,
               continuation_snapshot_json = ?,
               first_seen_guard_version = coalesce(first_seen_guard_version, ?), last_seen_guard_version = ?
           where request_id = ? and oauth_source = ?""",
        _update_values(
            request,
            canonical,
            request_id=request_id,
            oauth_source=oauth_source,
            identity_key=identity_key,
            action_identity=action_identity,
            queue_group_id=queue_group_id,
            now=now,
        ),
    )


def _update_values(
    request: GuardApprovalRequest,
    canonical: CanonicalApprovalSurfaces,
    *,
    request_id: str,
    oauth_source: str,
    identity_key: str,
    action_identity: str,
    queue_group_id: str,
    now: str,
) -> tuple[object, ...]:
    return (
        request.harness,
        request.artifact_name,
        request.artifact_type,
        request.artifact_hash,
        request.publisher,
        canonical.policy_action,
        request.recommended_scope,
        json.dumps(list(request.changed_fields)),
        request.source_scope,
        request.config_path,
        request.workspace,
        request.launch_target,
        identity_key,
        action_identity,
        queue_group_id,
        now,
        request.transport,
        request.risk_summary,
        json.dumps(list(request.risk_signals)),
        request.artifact_label,
        request.source_label,
        request.trigger_summary,
        request.why_now,
        request.launch_summary,
        request.risk_headline,
        _optional_json(canonical.action_envelope_json),
        json.dumps(canonical.decision_v2_json),
        _rewrite_review_command(request.fallback_cli_command, request_id) if request.fallback_cli_command else None,
        json.dumps(list(request.scanner_evidence), sort_keys=True),
        int(_scanner_evidence_is_watch_only(request.scanner_evidence)),
        _optional_json(request.browser_intent, sort_keys=True),
        _rewrite_review_command(request.review_command, request_id),
        _rewrite_approval_url(request.approval_url, request_id),
        request.raw_command_text,
        request.guard_version,
        _continuation_snapshot_json(request),
        request.first_seen_guard_version or request.guard_version,
        request.last_seen_guard_version or request.guard_version,
        request_id,
        oauth_source,
    )


def _insert_request(
    connection: sqlite3.Connection,
    request: GuardApprovalRequest,
    canonical: CanonicalApprovalSurfaces,
    *,
    oauth_source: str,
    identity_key: str,
    action_identity: str,
    queue_group_id: str,
    now: str,
) -> None:
    connection.execute(
        """insert into approval_requests (
             request_id, harness, artifact_id, artifact_name, artifact_type, artifact_hash, publisher, policy_action,
             recommended_scope, changed_fields_json, source_scope, oauth_source, config_path, workspace,
             launch_target, normalized_identity_key, action_identity, queue_group_id, dedupe_count, last_seen_at,
             transport, risk_summary, risk_signals_json, artifact_label, source_label, trigger_summary, why_now,
             launch_summary, risk_headline, action_envelope_json, decision_v2_json, fallback_cli_command,
             scanner_evidence_json, browser_intent_json, review_command, approval_url, status, resolution_action,
             resolution_scope, reason, created_at, resolved_at, raw_command_text, guard_version,
             first_seen_guard_version, last_seen_guard_version, watch_only_observation, continuation_snapshot_json)
           values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                   ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        _insert_values(
            request,
            canonical,
            oauth_source=oauth_source,
            identity_key=identity_key,
            action_identity=action_identity,
            queue_group_id=queue_group_id,
            now=now,
        ),
    )


def _insert_values(
    request: GuardApprovalRequest,
    canonical: CanonicalApprovalSurfaces,
    *,
    oauth_source: str,
    identity_key: str,
    action_identity: str,
    queue_group_id: str,
    now: str,
) -> tuple[object, ...]:
    return (
        request.request_id,
        request.harness,
        request.artifact_id,
        request.artifact_name,
        request.artifact_type,
        request.artifact_hash,
        request.publisher,
        canonical.policy_action,
        request.recommended_scope,
        json.dumps(list(request.changed_fields)),
        request.source_scope,
        oauth_source,
        request.config_path,
        request.workspace,
        request.launch_target,
        identity_key,
        action_identity,
        queue_group_id,
        max(1, int(request.dedupe_count)),
        request.last_seen_at or now,
        request.transport,
        request.risk_summary,
        json.dumps(list(request.risk_signals)),
        request.artifact_label,
        request.source_label,
        request.trigger_summary,
        request.why_now,
        request.launch_summary,
        request.risk_headline,
        _optional_json(canonical.action_envelope_json),
        json.dumps(canonical.decision_v2_json),
        request.fallback_cli_command,
        json.dumps(list(request.scanner_evidence), sort_keys=True),
        _optional_json(request.browser_intent, sort_keys=True),
        request.review_command,
        request.approval_url,
        "pending",
        None,
        None,
        None,
        now,
        None,
        request.raw_command_text,
        request.guard_version,
        request.first_seen_guard_version or request.guard_version,
        request.last_seen_guard_version or request.guard_version,
        int(_scanner_evidence_is_watch_only(request.scanner_evidence)),
        _continuation_snapshot_json(request),
    )


def _continuation_snapshot_json(request: GuardApprovalRequest) -> str:
    snapshot = validated_continuation_snapshot(request.continuation_snapshot)
    if snapshot is None:
        snapshot = non_resumable_continuation_snapshot(request.to_dict())
    return json.dumps(snapshot, sort_keys=True, separators=(",", ":"))


def _scanner_evidence_is_watch_only(scanner_evidence: Sequence[Mapping[str, object]]) -> bool:
    return any(item.get("source") == "observe_mode_inbox" for item in scanner_evidence)


def _rewrite_review_command(command: str, request_id: str) -> str:
    prefix, _, _ = command.rpartition(" ")
    return f"{prefix} {request_id}" if prefix else request_id


def _rewrite_approval_url(url: str, request_id: str) -> str:
    prefix, _, _ = url.replace("/approvals/", "/requests/").rpartition("/")
    return f"{prefix}/{request_id}" if prefix else request_id


def _optional_json(value: object, *, sort_keys: bool = False) -> str | None:
    return json.dumps(value, sort_keys=sort_keys) if value is not None else None
