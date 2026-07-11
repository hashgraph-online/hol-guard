"""GuardStore domain mixin extracted from store.py."""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false

from __future__ import annotations

# ruff: noqa: F403,F405
from .approval_scope_support import package_request_portable_workspace_scope
from .memory_pattern_fingerprint import build_memory_pattern_fingerprint
from .store_base import *


class StorePolicyMixin:
    def upsert_policy(
        self,
        decision: PolicyDecision,
        now: str,
        *,
        approval_gate_grant: ApprovalGateGrant | None = None,
        remote_write_authorized: bool = False,
    ) -> None:
        validate_policy_write_authority(
            decision,
            remote_write_authorized=remote_write_authorized,
        )
        require_policy_write(
            self.guard_home,
            decision=decision,
            approval_gate_grant=approval_gate_grant,
            now=now,
        )
        _validate_scoped_policy_artifact_target(decision.scope, decision.artifact_id)
        artifact_id, artifact_hash, workspace, publisher = self._normalized_policy_keys(decision)
        next_control_state: dict[str, object] | None = None
        with self._connect() as connection:
            secret_material = (None, None)
            if not is_remote_policy_source(decision.source):
                secret_material = self._policy_integrity_secret_material(create=True)
            state = self._refresh_policy_integrity_state(
                connection,
                now=now,
                create_key=not is_remote_policy_source(decision.source),
                secret_material=secret_material,
                allow_cutover_resign=False,
            )
            connection.execute(
                """
                delete from policy_decisions
                where harness = ? and scope = ? and coalesce(artifact_id, '') = coalesce(?, '')
                  and coalesce(artifact_hash, '') = coalesce(?, '')
                  and coalesce(workspace, '') = coalesce(?, '')
                  and coalesce(publisher, '') = coalesce(?, '')
                """,
                (decision.harness, decision.scope, artifact_id, artifact_hash, workspace, publisher),
            )
            cursor = connection.execute(
                """
                insert into policy_decisions (
                  harness, scope, artifact_id, artifact_hash, workspace, publisher, action, reason, owner, source,
                  expires_at, updated_at, integrity_version, integrity_generation, payload_hash, payload_mac,
                  integrity_key_id, signed_at
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision.harness,
                    decision.scope,
                    artifact_id,
                    artifact_hash,
                    workspace,
                    publisher,
                    decision.action,
                    decision.reason,
                    decision.owner,
                    decision.source,
                    decision.expires_at,
                    now,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                ),
            )
            if not is_remote_policy_source(decision.source) and state.get("mode") == "protected":
                key, key_id = secret_material
                if key is not None and key_id is not None:
                    trusted_state = self._load_policy_integrity_control_state(create=True)
                    if trusted_state is not None:
                        lastrowid = cursor.lastrowid
                        if lastrowid is None:
                            raise RuntimeError("Guard policy decision row was not inserted.")
                        next_control_state = self._advance_policy_integrity_generation(
                            connection,
                            now=now,
                            key=key,
                            key_id=key_id,
                            trusted_state=trusted_state,
                            force_sign_decision_ids={lastrowid},
                        )
                        connection.commit()
        if next_control_state is not None:
            self._finalize_policy_integrity_control_state(next_control_state)

    def replace_remote_policies(
        self,
        decisions: list[PolicyDecision],
        now: str,
        *,
        approval_gate_grant: ApprovalGateGrant | None = None,
        remote_write_authorized: bool = False,
    ) -> None:
        for decision in decisions:
            validate_policy_write_authority(
                decision,
                remote_write_authorized=remote_write_authorized,
            )
            require_policy_write(
                self.guard_home,
                decision=decision,
                approval_gate_grant=approval_gate_grant,
                now=now,
            )
        with self._connect() as connection:
            connection.execute(
                f"delete from policy_decisions where source in {_REMOTE_POLICY_SOURCE_PLACEHOLDERS}",
                _REMOTE_POLICY_SOURCE_PARAMS,
            )
            for decision in decisions:
                _validate_scoped_policy_artifact_target(decision.scope, decision.artifact_id)
                artifact_id, artifact_hash, workspace, publisher = self._normalized_policy_keys(decision)
                connection.execute(
                    """
                    insert into policy_decisions (
                      harness, scope, artifact_id, artifact_hash, workspace, publisher, action, reason, owner, source,
                      expires_at, updated_at, integrity_version, integrity_generation, payload_hash, payload_mac,
                      integrity_key_id, signed_at
                    )
                    values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        decision.harness,
                        decision.scope,
                        artifact_id,
                        artifact_hash,
                        workspace,
                        publisher,
                        decision.action,
                        decision.reason,
                        decision.owner,
                        decision.source,
                        decision.expires_at,
                        now,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                    ),
                )

    def resolve_policy(
        self,
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
    ) -> str | None:
        lookup = self.resolve_policy_decision_lookup_with_memory_pattern(
            harness,
            artifact_id,
            artifact_hash=artifact_hash,
            workspace=workspace,
            publisher=publisher,
            now=now,
            memory_command=memory_command,
            memory_artifact_type=memory_artifact_type,
            memory_artifact_name=memory_artifact_name,
        )
        decision = lookup["decision"]
        return str(decision["action"]) if decision is not None else None

    def resolve_policy_decision_lookup_with_memory_pattern(
        self,
        harness: str,
        artifact_id: str | None,
        artifact_hash: str | None = None,
        workspace: str | None = None,
        publisher: str | None = None,
        now: str | None = None,
        runtime_exact_match_context: str | None = None,
        *,
        memory_command: str | None = None,
        memory_artifact_type: str | None = None,
        memory_artifact_name: str | None = None,
    ) -> PolicyDecisionLookupResult:
        direct_lookup = self.resolve_policy_decision_lookup(
            harness,
            artifact_id,
            artifact_hash=artifact_hash,
            workspace=workspace,
            publisher=publisher,
            now=now,
            runtime_exact_match_context=runtime_exact_match_context,
        )
        if direct_lookup["decision"] is not None or direct_lookup.get("ignored_local_integrity") is not None:
            return direct_lookup
        memory_pattern = build_memory_pattern_fingerprint(
            command=memory_command,
            artifact_type=memory_artifact_type,
            artifact_id=artifact_id,
            artifact_name=memory_artifact_name,
            harness=harness,
        )
        if memory_pattern is None:
            return direct_lookup
        memory_artifact_id = f"memory:{harness}:{memory_pattern.kind}:{memory_pattern.fingerprint}"
        if memory_artifact_id == artifact_id:
            return direct_lookup
        memory_lookup = self.resolve_policy_decision_lookup(
            harness,
            memory_artifact_id,
            artifact_hash=artifact_hash,
            workspace=workspace,
            publisher=publisher,
            now=now,
            runtime_exact_match_context=runtime_exact_match_context,
        )
        return (
            memory_lookup
            if (memory_lookup["decision"] is not None or memory_lookup.get("ignored_local_integrity") is not None)
            else direct_lookup
        )

    def resolve_policy_decision_lookup(
        self,
        harness: str,
        artifact_id: str | None,
        artifact_hash: str | None = None,
        workspace: str | None = None,
        publisher: str | None = None,
        now: str | None = None,
        runtime_exact_match_context: str | None = None,
    ) -> PolicyDecisionLookupResult:
        current_time = now or _now()
        workspace_key = _workspace_policy_key(workspace)
        portable_workspace_key = _workspace_policy_key(
            package_request_portable_workspace_scope(
                artifact_id=artifact_id,
                artifact_hash=artifact_hash,
            )
        )
        action_family_key = _artifact_family_key(artifact_id)
        runtime_exact_match_key = (
            _runtime_scoped_exact_match_key(artifact_id, runtime_exact_match_context)
            if artifact_hash is not None
            else None
        )
        events: list[tuple[str, dict[str, object]]] = []
        selected_payload: dict[str, object] | None = None
        ignored_local_integrity: dict[str, object] | None = None
        with self._connect() as connection:
            local_once_decision = None
            local_once_hashes = tuple(
                dict.fromkeys(hash_value for hash_value in (artifact_hash, runtime_exact_match_key) if hash_value)
            )
            for local_once_hash in local_once_hashes:
                local_once_decision = self._claim_local_once_approval_locked(
                    connection,
                    harness=harness,
                    artifact_id=artifact_id,
                    artifact_hash=local_once_hash,
                    workspace=workspace,
                    publisher=publisher,
                    now=current_time,
                )
                if local_once_decision is not None:
                    break
            if local_once_decision is not None:
                selected_payload = local_once_decision
                events.append(
                    (
                        "approval.local_once_applied",
                        {
                            "approval_id": local_once_decision.get("approval_id"),
                            "request_id": local_once_decision.get("request_id"),
                            "harness": harness,
                            "artifact_id": artifact_id,
                        },
                    )
                )
            rows = connection.execute(
                """
                select decision_id, harness, scope, artifact_id, action, artifact_hash, workspace, publisher, source,
                       reason, owner, expires_at, updated_at, integrity_version, integrity_generation,
                       payload_hash, payload_mac,
                       integrity_key_id, signed_at
                from policy_decisions
                where (harness = ? or harness = '*') and (
                  (
                    scope = 'artifact' and artifact_id = ? and (
                      artifact_hash is null or (? is not null and artifact_hash = ?)
                      or (? is not null and artifact_hash = ?)
                    )
                  )
                  or (
                    scope = 'workspace' and (workspace = ? or workspace = ? or workspace = ?) and (
                      artifact_id is null or (
                        artifact_id = ? and (
                          artifact_hash is null or (? is not null and artifact_hash = ?)
                        )
                      )
                    )
                  )
                  or (scope = 'publisher' and publisher = ?)
                  or (
                    scope = 'harness' and (
                      artifact_id is null or artifact_id = ?
                    )
                  )
                    or (
                      scope = 'global' and (
                        artifact_id is null
                        or artifact_id = ?
                        or artifact_id = ?
                      )
                    )
                )
                and (expires_at is null or expires_at > ?)
                order by case scope when 'artifact' then 0 when 'workspace' then 1 when 'publisher' then 2
                         when 'harness' then 3 else 4 end,
                         case
                           when scope in ('workspace', 'harness', 'global') and artifact_id is not null then 0
                           else 1
                         end,
                         updated_at desc
                """,
                (
                    harness,
                    artifact_id,
                    artifact_hash,
                    artifact_hash,
                    runtime_exact_match_key,
                    runtime_exact_match_key,
                    workspace_key,
                    workspace,
                    portable_workspace_key,
                    artifact_id,
                    artifact_hash,
                    artifact_hash,
                    publisher,
                    action_family_key,
                    artifact_id,
                    action_family_key,
                    current_time,
                ),
            ).fetchall()
            cached_state = self._load_policy_integrity_state(connection) or {}
            cached_trust_status = TrustStatus.from_policy_integrity_state(cached_state).to_dict()
            if not rows and selected_payload is None:
                return {
                    "decision": None,
                    "ignored_local_integrity": None,
                    "trust_status": cached_trust_status,
                }
            has_local_rows = any(not is_remote_policy_source(str(candidate["source"])) for candidate in rows)
            if not has_local_rows:
                if selected_payload is None:
                    for candidate in rows:
                        if _scoped_runtime_row_requires_exact_match(
                            scope=str(candidate["scope"]),
                            stored_artifact_id=(
                                str(candidate["artifact_id"]) if isinstance(candidate["artifact_id"], str) else None
                            ),
                            stored_artifact_hash=(
                                str(candidate["artifact_hash"]) if isinstance(candidate["artifact_hash"], str) else None
                            ),
                            source=str(candidate["source"]),
                            requested_artifact_id=artifact_id,
                            requested_runtime_exact_match_key=runtime_exact_match_key,
                        ):
                            continue
                        integrity_result = self._policy_integrity_result_for_row(
                            candidate,
                            mode=str((cached_state or {}).get("mode") or "degraded"),
                            key=None,
                            key_id=None,
                            trusted_generation=_mapping_int(cached_state, "generation"),
                        )
                        if integrity_result.status != "valid":
                            events.append(
                                (
                                    "policy_integrity_violation",
                                    {
                                        "decision_id": int(candidate["decision_id"]),
                                        "harness": str(candidate["harness"]),
                                        "artifact_id": candidate["artifact_id"],
                                        "integrity_status": integrity_result.status,
                                        "message": integrity_result.message,
                                    },
                                )
                            )
                            continue
                        selected_payload = self._policy_row_payload(candidate)
                        if is_remote_policy_source(str(candidate["source"])):
                            events.append(
                                (
                                    "policy.cloud.applied",
                                    {
                                        "decision_id": int(candidate["decision_id"]),
                                        "harness": str(candidate["harness"]),
                                        "artifact_id": candidate["artifact_id"],
                                        "scope": str(candidate["scope"]),
                                        "source": str(candidate["source"]),
                                        "action": str(candidate["action"]),
                                    },
                                )
                            )
                        if _is_approval_gate_one_shot_policy(candidate):
                            connection.execute(
                                "delete from policy_decisions where decision_id = ?",
                                (int(candidate["decision_id"]),),
                            )
                        break
                for event_name, payload in events:
                    connection.execute(
                        """
                        insert into guard_events (event_name, payload_json, occurred_at)
                        values (?, ?, ?)
                        """,
                        (event_name, json.dumps(payload), current_time),
                    )
                return {
                    "decision": selected_payload,
                    "ignored_local_integrity": None,
                    "trust_status": cached_trust_status,
                }
            state = self._refresh_policy_integrity_state(connection, now=current_time, create_key=True)
            trust_status = TrustStatus.from_policy_integrity_state(state).to_dict()
            key, key_id = self._policy_integrity_secret_material(create=True)
            for candidate in rows if selected_payload is None else ():
                if _scoped_runtime_row_requires_exact_match(
                    scope=str(candidate["scope"]),
                    stored_artifact_id=(
                        str(candidate["artifact_id"]) if isinstance(candidate["artifact_id"], str) else None
                    ),
                    stored_artifact_hash=(
                        str(candidate["artifact_hash"]) if isinstance(candidate["artifact_hash"], str) else None
                    ),
                    source=str(candidate["source"]),
                    requested_artifact_id=artifact_id,
                    requested_runtime_exact_match_key=runtime_exact_match_key,
                ):
                    continue
                integrity_result = self._policy_integrity_result_for_row(
                    candidate,
                    mode=str(state.get("mode") or "degraded"),
                    key=key,
                    key_id=key_id,
                    trusted_generation=_mapping_int(state, "generation"),
                )
                if integrity_result.status == "valid" or _warn_only_policy_integrity_status(
                    integrity_result.status,
                    state,
                    source=str(candidate["source"]),
                ):
                    selected_payload = self._policy_row_payload(
                        candidate,
                        integrity_result=integrity_result,
                        state=state,
                    )
                    if is_remote_policy_source(str(candidate["source"])):
                        events.append(
                            (
                                "policy.cloud.applied",
                                {
                                    "decision_id": int(candidate["decision_id"]),
                                    "harness": str(candidate["harness"]),
                                    "artifact_id": candidate["artifact_id"],
                                    "scope": str(candidate["scope"]),
                                    "source": str(candidate["source"]),
                                    "action": str(candidate["action"]),
                                },
                            )
                        )
                    if _is_approval_gate_one_shot_policy(candidate):
                        connection.execute(
                            "delete from policy_decisions where decision_id = ?",
                            (int(candidate["decision_id"]),),
                        )
                    break
                events.append(
                    (
                        "policy_integrity_violation",
                        {
                            "decision_id": int(candidate["decision_id"]),
                            "harness": str(candidate["harness"]),
                            "artifact_id": candidate["artifact_id"],
                            "integrity_status": integrity_result.status,
                            "message": integrity_result.message,
                        },
                    )
                )
                if ignored_local_integrity is None and not is_remote_policy_source(str(candidate["source"])):
                    ignored_local_integrity = {
                        "decision_id": int(candidate["decision_id"]),
                        "harness": str(candidate["harness"]),
                        "artifact_id": candidate["artifact_id"],
                        "scope": str(candidate["scope"]),
                        "source": str(candidate["source"]),
                        "integrity_status": integrity_result.status,
                        "integrity_message": integrity_result.message,
                        "trust_status": trust_status,
                    }
                if not is_remote_policy_source(str(candidate["source"])):
                    events.append(
                        (
                            "rule.ignored.local_integrity",
                            {
                                "decision_id": int(candidate["decision_id"]),
                                "harness": str(candidate["harness"]),
                                "artifact_id": candidate["artifact_id"],
                                "scope": str(candidate["scope"]),
                                "source": str(candidate["source"]),
                                "integrity_status": integrity_result.status,
                                "message": integrity_result.message,
                            },
                        )
                    )
                _store_logger.warning(
                    "Guard ignored local policy decision %s because integrity status was %s.",
                    candidate["decision_id"],
                    integrity_result.status,
                )
            for event_name, payload in events:
                connection.execute(
                    """
                    insert into guard_events (event_name, payload_json, occurred_at)
                    values (?, ?, ?)
                    """,
                    (event_name, json.dumps(payload), current_time),
                )
            return {
                "decision": selected_payload,
                "ignored_local_integrity": ignored_local_integrity,
                "trust_status": trust_status,
            }

    def resolve_policy_decision(
        self,
        harness: str,
        artifact_id: str | None,
        artifact_hash: str | None = None,
        workspace: str | None = None,
        publisher: str | None = None,
        now: str | None = None,
        runtime_exact_match_context: str | None = None,
    ) -> dict[str, object] | None:
        lookup = self.resolve_policy_decision_lookup(
            harness,
            artifact_id,
            artifact_hash=artifact_hash,
            workspace=workspace,
            publisher=publisher,
            now=now,
            runtime_exact_match_context=runtime_exact_match_context,
        )
        return lookup["decision"]

    @staticmethod
    def _normalized_policy_keys(decision: PolicyDecision) -> tuple[str | None, str | None, str | None, str | None]:
        if decision.scope in {"harness", "global"}:
            artifact_id = _artifact_family_key(decision.artifact_id)
        else:
            artifact_id = decision.artifact_id if decision.scope in {"artifact", "workspace"} else None
        artifact_hash = (
            decision.artifact_hash
            if decision.scope in {"artifact", "workspace"} or _is_runtime_scoped_exact_match_key(decision.artifact_hash)
            else None
        )
        workspace = _workspace_policy_key(decision.workspace) if decision.scope == "workspace" else None
        publisher = decision.publisher if decision.scope == "publisher" else None
        return artifact_id, artifact_hash, workspace, publisher

    def policy_fingerprint(
        self,
        *,
        harness: str,
        workspace: Path | str | None,
        now: str | None = None,
    ) -> str:
        """Return a stable hash of all policy decisions affecting a harness/workspace.

        Reads all non-expired rows that can affect global, harness, publisher,
        artifact, or workspace-scoped decisions. Includes policy integrity
        trust status. Any policy change invalidates this fingerprint, ensuring
        source-read cache entries are invalidated when policy changes.
        """
        import hashlib
        import json
        from datetime import datetime, timezone

        current_time = now or datetime.now(timezone.utc).isoformat()
        workspace_key = _workspace_policy_key(str(workspace) if workspace is not None else None)
        with self._connect() as connection:
            rows = connection.execute(
                """
                select decision_id, harness, scope, artifact_id, artifact_hash, workspace, publisher,
                       action, source, expires_at, updated_at, integrity_version, integrity_generation,
                       payload_hash, payload_mac, integrity_key_id, signed_at
                from policy_decisions
                where (harness = ? or harness = '*')
                  and (expires_at is null or expires_at > ?)
                  and (
                    scope in ('global', 'harness', 'publisher', 'artifact')
                    or (scope = 'workspace' and (workspace = ? or workspace is null))
                  )
                order by decision_id asc
                """,
                (harness, current_time, workspace_key),
            ).fetchall()
            integrity_state = self._load_policy_integrity_state(connection) or {}
        material = {
            "harness": harness,
            "workspace": workspace_key,
            "rows": [dict(row) for row in rows],
            "trust_status": TrustStatus.from_policy_integrity_state(integrity_state).to_dict(),
        }
        return hashlib.sha256(
            json.dumps(material, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
