"""Policy decision lookup with unchanged authority and one-shot ordering."""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false

from __future__ import annotations

from .store_base import PolicyDecisionLookupResult


class StorePolicyMixin:
    def resolve_policy_decision_lookup(
        self,
        harness: str,
        artifact_id: str | None,
        artifact_hash: str | None = None,
        workspace: str | None = None,
        publisher: str | None = None,
        now: str | None = None,
        runtime_exact_match_context: str | None = None,
        consume_one_shot: bool = True,
        exact_command_sha256: str | None = None,
    ) -> PolicyDecisionLookupResult:
        from . import store_policy as _policy

        current_time = _policy._canonical_utc_timestamp(now or _policy._now())
        workspace_key = _policy._workspace_policy_key(workspace)
        action_family_key = _policy._artifact_family_key(artifact_id)
        runtime_exact_match_key = (
            _policy._runtime_scoped_exact_match_key(artifact_id, runtime_exact_match_context)
            if artifact_hash is not None
            else None
        )
        portable_runtime_exact_match_key = (
            _policy._runtime_scoped_exact_match_key(
                artifact_id,
                _policy.runtime_tool_action_portable_match_context(runtime_exact_match_context),
            )
            if artifact_hash is not None and runtime_exact_match_context is not None
            else None
        )
        global_runtime_exact_match_key = (
            _policy._global_runtime_scoped_exact_match_key(
                artifact_id,
                _policy.runtime_tool_action_portable_match_context(runtime_exact_match_context),
            )
            if artifact_hash is not None and runtime_exact_match_context is not None
            else None
        )
        events: list[tuple[str, dict[str, object]]] = []
        selected_payload: dict[str, object] | None = None
        ignored_local_integrity: dict[str, object] | None = None
        local_once_integrity_key: bytes | None = None
        local_once_integrity_key_id: str | None = None
        with self._connect() as connection:
            starting_authority_revision = _policy._approval_authority_revision(connection)

            def lookup_result(
                decision: dict[str, object] | None,
                *,
                ignored_integrity: dict[str, object] | None,
                trust_status: dict[str, object],
            ) -> _policy.PolicyDecisionLookupResult:
                ending_authority_revision = _policy._approval_authority_revision(connection)
                stable_revision = (
                    starting_authority_revision if ending_authority_revision == starting_authority_revision else -1
                )
                if decision is not None and not consume_one_shot:
                    decision = {
                        **decision,
                        "_approval_authority_revision": stable_revision,
                    }
                return {
                    "decision": decision,
                    "ignored_local_integrity": ignored_integrity,
                    "trust_status": trust_status,
                    "authority_revision": stable_revision,
                }

            local_once_decision = None
            local_once_hash: str | None = None
            reported_local_once_failures: set[object] = set()
            local_once_hashes = tuple(
                dict.fromkeys(hash_value for hash_value in (artifact_hash, runtime_exact_match_key) if hash_value)
            )
            for local_once_hash in local_once_hashes:
                local_once_decision, local_once_integrity_failure = self._peek_local_once_approval_lookup_locked(
                    connection,
                    harness=harness,
                    artifact_id=artifact_id,
                    artifact_hash=local_once_hash,
                    workspace=workspace,
                    publisher=publisher,
                    now=current_time,
                )
                if (
                    local_once_decision is None
                    and local_once_integrity_failure is not None
                    and local_once_integrity_failure.get("integrity_status") == "unknown_key"
                ):
                    local_once_integrity_key, local_once_integrity_key_id = self._policy_integrity_secret_material(
                        create=False
                    )
                    local_once_decision, local_once_integrity_failure = self._peek_local_once_approval_lookup_locked(
                        connection,
                        harness=harness,
                        artifact_id=artifact_id,
                        artifact_hash=local_once_hash,
                        workspace=workspace,
                        publisher=publisher,
                        now=current_time,
                        integrity_key=local_once_integrity_key,
                        integrity_key_id=local_once_integrity_key_id,
                    )
                if local_once_integrity_failure is not None:
                    if ignored_local_integrity is None:
                        ignored_local_integrity = local_once_integrity_failure
                    failure_id = local_once_integrity_failure.get("approval_id")
                    if failure_id not in reported_local_once_failures:
                        reported_local_once_failures.add(failure_id)
                        events.append(
                            (
                                "rule.ignored.local_integrity",
                                {
                                    **local_once_integrity_failure,
                                    "message": local_once_integrity_failure.get("integrity_message"),
                                },
                            )
                        )
                if local_once_decision is not None:
                    break
            if local_once_decision is not None:
                selected_payload = local_once_decision

            def claim_selected_local_once() -> None:
                """Consume a selected one-shot only after stronger policy wins are known."""

                nonlocal selected_payload
                if (
                    not consume_one_shot
                    or local_once_decision is None
                    or selected_payload is not local_once_decision
                    or local_once_hash is None
                ):
                    return
                claimed = self._claim_local_once_approval_locked(
                    connection,
                    harness=harness,
                    artifact_id=artifact_id,
                    artifact_hash=local_once_hash,
                    workspace=workspace,
                    publisher=publisher,
                    now=current_time,
                    integrity_key=local_once_integrity_key,
                    integrity_key_id=local_once_integrity_key_id,
                )
                if claimed is None:
                    selected_payload = None
                    return
                selected_payload = claimed
                events.append(
                    (
                        "approval.local_once_applied",
                        {
                            "approval_id": claimed.get("approval_id"),
                            "request_id": claimed.get("request_id"),
                            "harness": harness,
                            "artifact_id": artifact_id,
                        },
                    )
                )

            if not consume_one_shot:
                rows = _policy._bounded_non_consuming_policy_rows(
                    connection,
                    harness=harness,
                    artifact_id=artifact_id,
                    artifact_hash=artifact_hash,
                    runtime_exact_match_key=runtime_exact_match_key,
                    global_runtime_exact_match_key=global_runtime_exact_match_key,
                    workspace_key=workspace_key,
                    workspace=workspace,
                    publisher=publisher,
                    action_family_key=action_family_key,
                    current_time=current_time,
                    exact_command_sha256=exact_command_sha256,
                )
            else:
                rows = connection.execute(
                    _policy._POLICY_LOOKUP_CONSUMING_SQL,
                    (
                        harness,
                        artifact_id,
                        artifact_hash,
                        artifact_hash,
                        runtime_exact_match_key,
                        runtime_exact_match_key,
                        workspace_key,
                        workspace,
                        artifact_id,
                        action_family_key,
                        artifact_hash,
                        artifact_hash,
                        publisher,
                        artifact_hash,
                        action_family_key,
                        artifact_hash,
                        runtime_exact_match_key,
                        runtime_exact_match_key,
                        artifact_id,
                        action_family_key,
                        artifact_hash,
                        global_runtime_exact_match_key,
                        global_runtime_exact_match_key,
                        exact_command_sha256,
                        current_time,
                        _policy._NON_CONSUMING_POLICY_MATCH_LIMIT + 1 if not consume_one_shot else -1,
                    ),
                ).fetchall()
            rows.sort(key=_policy.generic_policy_row_precedence, reverse=True)
            policy_match_overflow = not consume_one_shot and len(rows) > _policy._NON_CONSUMING_POLICY_MATCH_LIMIT
            if policy_match_overflow:
                rows = rows[: _policy._NON_CONSUMING_POLICY_MATCH_LIMIT]
                selected_payload = {
                    "action": "block",
                    "artifact_hash": artifact_hash,
                    "artifact_id": artifact_id,
                    "decision_id": None,
                    "expires_at": None,
                    "harness": harness,
                    "owner": None,
                    "publisher": publisher,
                    "reason": "Guard policy match limit exceeded during approval reuse.",
                    "scope": "global",
                    "source": "guard-policy-match-cap",
                    "updated_at": current_time,
                    "workspace": workspace,
                }
                events.append(
                    (
                        "approval.policy_lookup_overflow",
                        {
                            "harness": harness,
                            "artifact_id": artifact_id,
                            "match_limit": _policy._NON_CONSUMING_POLICY_MATCH_LIMIT,
                            "authoritative_action": "block",
                        },
                    )
                )
            cached_state = self._load_policy_integrity_state(connection) or {}
            cached_trust_status = _policy.TrustStatus.from_policy_integrity_state(cached_state).to_dict()
            if not rows and selected_payload is None:
                for event_name, payload in events:
                    connection.execute(
                        """
                        insert into guard_events (event_name, payload_json, occurred_at)
                        values (?, ?, ?)
                        """,
                        (event_name, _policy.json.dumps(payload), current_time),
                    )
                if ignored_local_integrity is not None:
                    ignored_local_integrity["trust_status"] = cached_trust_status
                return lookup_result(
                    None,
                    ignored_integrity=ignored_local_integrity,
                    trust_status=cached_trust_status,
                )
            policy_bundle_row_authorities = (
                self._cached_policy_bundle_row_authorities(
                    now=_policy._parse_utc_timestamp(current_time).timestamp(),
                )
                if any(str(candidate["source"]) in {"policy-bundle", "policy-bundle-canonical"} for candidate in rows)
                else {}
            )
            policy_bundle_decision_identities = frozenset(policy_bundle_row_authorities)
            memory_decision_identities = (
                self._cached_review_memory_decision_identities(now=current_time)
                if any(str(candidate["source"]) == "cloud-signed-memory" for candidate in rows)
                else frozenset()
            )
            has_local_rows = any(not _policy.is_remote_policy_source(str(candidate["source"])) for candidate in rows)
            if not has_local_rows:
                for candidate in rows:
                    if not self._runtime_policy_row_is_eligible(
                        candidate,
                        policy_bundle_decision_identities=policy_bundle_decision_identities,
                        memory_decision_identities=memory_decision_identities,
                        artifact_id=artifact_id,
                        artifact_hash=artifact_hash,
                        runtime_exact_match_key=runtime_exact_match_key,
                        portable_runtime_exact_match_key=portable_runtime_exact_match_key,
                        global_runtime_exact_match_key=global_runtime_exact_match_key,
                    ):
                        continue
                    integrity_result = self._policy_integrity_result_for_row(
                        candidate,
                        mode=str((cached_state or {}).get("mode") or "degraded"),
                        key=None,
                        key_id=None,
                        trusted_generation=_policy._mapping_int(cached_state, "generation"),
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
                    candidate_payload = self._policy_row_payload(candidate)
                    source_identity = policy_bundle_row_authorities.get(
                        (*self._materialized_policy_bundle_row_identity(candidate), candidate["updated_at"])
                    )
                    if source_identity is not None:
                        candidate_payload.update(source_identity.to_selected_row_dict())
                    candidate_outranks_local_once = selected_payload is None or _policy.guard_action_severity(
                        candidate_payload.get("action"),
                        unknown_action="block",
                    ) > _policy.guard_action_severity(selected_payload.get("action"), unknown_action="block")
                    if candidate_outranks_local_once:
                        selected_payload = candidate_payload
                        if consume_one_shot and _policy.is_remote_policy_source(str(candidate["source"])):
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
                        if consume_one_shot and _policy._is_approval_gate_one_shot_policy(candidate):
                            connection.execute(
                                "delete from policy_decisions where decision_id = ?",
                                (int(candidate["decision_id"]),),
                            )
                    # Both paths select the same first authenticated generic
                    # row. A generic shared block is not a managed floor.
                    break
                claim_selected_local_once()
                for event_name, payload in events:
                    connection.execute(
                        """
                        insert into guard_events (event_name, payload_json, occurred_at)
                        values (?, ?, ?)
                        """,
                        (event_name, _policy.json.dumps(payload), current_time),
                    )
                if ignored_local_integrity is not None:
                    ignored_local_integrity["trust_status"] = cached_trust_status
                return lookup_result(
                    selected_payload,
                    ignored_integrity=ignored_local_integrity,
                    trust_status=cached_trust_status,
                )
            state = self._refresh_policy_integrity_state(connection, now=current_time, create_key=True)
            trust_status = _policy.TrustStatus.from_policy_integrity_state(state).to_dict()
            key, key_id = self._policy_integrity_secret_material(create=True)
            for candidate in rows:
                if not self._runtime_policy_row_is_eligible(
                    candidate,
                    policy_bundle_decision_identities=policy_bundle_decision_identities,
                    memory_decision_identities=memory_decision_identities,
                    artifact_id=artifact_id,
                    artifact_hash=artifact_hash,
                    runtime_exact_match_key=runtime_exact_match_key,
                    portable_runtime_exact_match_key=portable_runtime_exact_match_key,
                    global_runtime_exact_match_key=global_runtime_exact_match_key,
                ):
                    continue
                integrity_result = self._policy_integrity_result_for_row(
                    candidate,
                    mode=str(state.get("mode") or "degraded"),
                    key=key,
                    key_id=key_id,
                    trusted_generation=_policy._mapping_int(state, "generation"),
                )
                if integrity_result.status == "valid" or _policy._warn_only_policy_integrity_status(
                    integrity_result.status,
                    state,
                    source=str(candidate["source"]),
                ):
                    candidate_payload = self._policy_row_payload(
                        candidate,
                        integrity_result=integrity_result,
                        state=state,
                    )
                    source_identity = policy_bundle_row_authorities.get(
                        (*self._materialized_policy_bundle_row_identity(candidate), candidate["updated_at"])
                    )
                    if source_identity is not None:
                        candidate_payload.update(source_identity.to_selected_row_dict())
                    candidate_outranks_local_once = selected_payload is None or _policy.guard_action_severity(
                        candidate_payload.get("action"),
                        unknown_action="block",
                    ) > _policy.guard_action_severity(selected_payload.get("action"), unknown_action="block")
                    if candidate_outranks_local_once:
                        selected_payload = candidate_payload
                    if (
                        candidate_outranks_local_once
                        and consume_one_shot
                        and _policy.is_remote_policy_source(str(candidate["source"]))
                    ):
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
                    if (
                        candidate_outranks_local_once
                        and consume_one_shot
                        and _policy._is_approval_gate_one_shot_policy(candidate)
                    ):
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
                if ignored_local_integrity is None and not _policy.is_remote_policy_source(str(candidate["source"])):
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
                if not _policy.is_remote_policy_source(str(candidate["source"])):
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
                _policy._store_logger.warning(
                    "Guard ignored local policy decision %s because integrity status was %s.",
                    candidate["decision_id"],
                    integrity_result.status,
                )
            claim_selected_local_once()
            for event_name, payload in events:
                connection.execute(
                    """
                    insert into guard_events (event_name, payload_json, occurred_at)
                    values (?, ?, ?)
                    """,
                    (event_name, _policy.json.dumps(payload), current_time),
                )
            if ignored_local_integrity is not None:
                ignored_local_integrity.setdefault("trust_status", trust_status)
            return lookup_result(
                selected_payload,
                ignored_integrity=ignored_local_integrity,
                trust_status=trust_status,
            )
