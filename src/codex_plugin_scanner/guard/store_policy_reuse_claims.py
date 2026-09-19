"""Approval reuse validation and atomic one-shot claiming."""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false

from __future__ import annotations

from typing import Literal

from .store_base import Mapping, Sequence, sqlite3


class StorePolicyMixin:
    def claim_approval_reuse_decision(
        self,
        decision: Mapping[str, object],
        *,
        now: str | None = None,
    ) -> bool:
        """Atomically validate and claim an accepted saved ``allow`` decision.

        Returning ``False`` means the decision expired, changed, was consumed
        by another evaluator, or was not an approval ``allow``. Callers must
        then enforce the recomputed current action without saved evidence.
        """

        return self.claim_approval_reuse_decisions((decision,), now=now)

    @staticmethod
    def approval_reuse_claim_disposition(
        decision: Mapping[str, object],
    ) -> Literal["consumed", "retained"] | None:
        """Describe what a successful claim does to this selected allow.

        Package local-once approvals are reusable and remain in their table.
        Expiring ``approval-gate`` policy rows are the only policy decisions
        atomically deleted by the claim transaction. All other valid policy
        allows remain authoritative and therefore must still exist when a
        caller revalidates immediately before launch.
        """
        from . import store_policy as _policy

        if decision.get("action") != "allow":
            return None
        approval_id = decision.get("approval_id")
        if isinstance(approval_id, str) and approval_id:
            artifact_id = decision.get("artifact_id")
            if not isinstance(artifact_id, str) or not artifact_id:
                return None
            return "retained" if _policy._local_once_approval_is_reusable(artifact_id) else "consumed"
        decision_id = decision.get("decision_id")
        if not isinstance(decision_id, int) or isinstance(decision_id, bool):
            return None
        if decision.get("source") == _policy._APPROVAL_GATE_POLICY_SOURCE and decision.get("expires_at") is not None:
            return "consumed"
        return "retained"

    def claim_approval_reuse_decisions(
        self,
        decisions: Sequence[Mapping[str, object]],
        *,
        now: str | None = None,
    ) -> bool:
        """Validate and claim a group of saved allows in one transaction.

        A compound launch (for example, an MCP tool call that also installs a
        package) may depend on more than one one-shot approval.  The launch is
        authorized only when every selected row still matches the authority
        revision observed during evaluation.  Any failed member rolls the
        entire group back so a denied launch cannot consume a sibling grant.
        """
        from . import store_policy as _policy

        current_time = _policy._canonical_utc_timestamp(now or _policy._now())
        unique_decisions: list[_policy.Mapping[str, object]] = []
        seen_keys: set[tuple[str, object]] = set()
        expected_revision: int | None = None
        has_local_once = False
        for decision in decisions:
            if decision.get("action") != "allow":
                return False
            revision = decision.get("_approval_authority_revision")
            if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
                return False
            if expected_revision is None:
                expected_revision = revision
            elif revision != expected_revision:
                return False
            approval_id = decision.get("approval_id")
            decision_id = decision.get("decision_id")
            if isinstance(approval_id, str) and approval_id:
                decision_key: tuple[str, object] = ("approval", approval_id)
                has_local_once = True
            elif isinstance(decision_id, int) and not isinstance(decision_id, bool):
                decision_key = ("policy", decision_id)
            else:
                return False
            if decision_key in seen_keys:
                continue
            seen_keys.add(decision_key)
            unique_decisions.append(decision)
        if not unique_decisions:
            return True
        assert expected_revision is not None
        local_integrity_key: bytes | None = None
        local_integrity_key_id: str | None = None
        if has_local_once:
            local_integrity_key, local_integrity_key_id = self._policy_integrity_secret_material(create=False)
        with self._connect() as connection:
            connection.execute("begin immediate")
            if _policy._approval_authority_revision(connection) != expected_revision:
                connection.rollback()
                return False
            policy_bundle_decision_identities: frozenset[tuple[object, ...]] | None = None
            if any(
                decision.get("source") in {"policy-bundle", "policy-bundle-canonical"} for decision in unique_decisions
            ):
                # Revalidate the signed bundle and its materialized identities
                # after the write lock is held. This closes bundle/key/workspace
                # replacement and key-expiry races between lookup and launch.
                policy_bundle_decision_identities = self._cached_policy_bundle_decision_identities(
                    now=_policy._parse_utc_timestamp(current_time).timestamp(),
                )
            memory_decision_identities = (
                self._cached_review_memory_decision_identities(now=current_time)
                if any(decision.get("source") == "cloud-signed-memory" for decision in unique_decisions)
                else frozenset()
            )
            for decision in unique_decisions:
                if not self._claim_approval_reuse_decision_locked(
                    connection,
                    decision=decision,
                    current_time=current_time,
                    local_integrity_key=local_integrity_key,
                    local_integrity_key_id=local_integrity_key_id,
                    policy_bundle_decision_identities=policy_bundle_decision_identities,
                    memory_decision_identities=memory_decision_identities,
                ):
                    connection.rollback()
                    return False
        return True

    def _claim_approval_reuse_decision_locked(
        self,
        connection: sqlite3.Connection,
        *,
        decision: Mapping[str, object],
        current_time: str,
        local_integrity_key: bytes | None,
        local_integrity_key_id: str | None,
        policy_bundle_decision_identities: frozenset[tuple[object, ...]] | None,
        memory_decision_identities: frozenset[tuple[object, ...]],
    ) -> bool:
        """Claim one prevalidated member of an open batch transaction."""
        from . import store_policy as _policy

        approval_id = decision.get("approval_id")
        decision_id = decision.get("decision_id")
        if isinstance(approval_id, str) and approval_id:
            claim_disposition = self.approval_reuse_claim_disposition(decision)
            if claim_disposition is None:
                return False
            claimed = self._claim_local_once_approval_by_id_locked(
                connection,
                approval_id=approval_id,
                now=current_time,
                expected_decision=decision,
                integrity_key=local_integrity_key,
                integrity_key_id=local_integrity_key_id,
                consume=claim_disposition == "consumed",
            )
            if claimed is None:
                return False
            connection.execute(
                """
                insert into guard_events (event_name, payload_json, occurred_at)
                values (?, ?, ?)
                """,
                (
                    (
                        "approval.local_once_reused"
                        if claim_disposition == "retained"
                        else "approval.local_once_applied"
                    ),
                    _policy.json.dumps(
                        {
                            "approval_id": claimed.get("approval_id"),
                            "request_id": claimed.get("request_id"),
                            "harness": claimed.get("harness"),
                            "artifact_id": claimed.get("artifact_id"),
                        }
                    ),
                    current_time,
                ),
            )
            return True
        if not isinstance(decision_id, int) or isinstance(decision_id, bool):
            return False
        row = connection.execute(
            """
            select decision_id, harness, scope, artifact_id, action, artifact_hash, workspace, publisher,
                   exact_command_sha256,
                   source, reason, owner, expires_at, updated_at, integrity_version, integrity_generation,
                   payload_hash, payload_mac, integrity_key_id, signed_at
            from policy_decisions
            where decision_id = ? and action = 'allow'
              and (expires_at is null or julianday(expires_at) > julianday(?))
            """,
            (decision_id, current_time),
        ).fetchone()
        if row is None:
            return False
        source = str(row["source"])
        if source in {"cloud-sync", "team-policy"}:
            return False
        if source in {"policy-bundle", "policy-bundle-canonical"} and (
            policy_bundle_decision_identities is None
            or (*self._materialized_policy_bundle_row_identity(row), row["updated_at"])
            not in policy_bundle_decision_identities
        ):
            return False
        if (
            source == "cloud-signed-memory"
            and (*self._materialized_policy_bundle_row_identity(row), row["updated_at"])
            not in memory_decision_identities
        ):
            return False
        if _policy.is_remote_policy_source(source):
            integrity_result = self._policy_integrity_result_for_row(
                row,
                mode="protected",
                key=None,
                key_id=None,
                trusted_generation=None,
            )
            integrity_state: dict[str, object] | None = None
        else:
            integrity_state = self._refresh_policy_integrity_state(connection, now=current_time, create_key=True) or {}
            key, key_id = self._policy_integrity_secret_material(create=True)
            generation = integrity_state.get("generation")
            trusted_generation = (
                generation if isinstance(generation, int) and not isinstance(generation, bool) else None
            )
            integrity_result = self._policy_integrity_result_for_row(
                row,
                mode=str(integrity_state.get("mode") or "degraded"),
                key=key,
                key_id=key_id,
                trusted_generation=trusted_generation,
            )
        if integrity_result.status != "valid":
            return False
        current_payload = self._policy_row_payload(
            row,
            integrity_result=integrity_result,
            state=integrity_state,
        )
        identity_keys = (
            "action",
            "artifact_hash",
            "exact_command_sha256",
            "artifact_id",
            "decision_id",
            "expires_at",
            "harness",
            "integrity_enforcement",
            "integrity_generation",
            "integrity_key_id",
            "integrity_mode",
            "integrity_status",
            "integrity_version",
            "owner",
            "publisher",
            "reason",
            "signed_at",
            "scope",
            "source",
            "updated_at",
            "workspace",
        )
        if any(current_payload.get(key) != decision.get(key) for key in identity_keys):
            return False
        claim_disposition = self.approval_reuse_claim_disposition(current_payload)
        if claim_disposition is None:
            return False
        if claim_disposition == "consumed":
            cursor = connection.execute(
                "delete from policy_decisions where decision_id = ? and action = 'allow'",
                (decision_id,),
            )
            if cursor.rowcount != 1:
                return False
        connection.execute(
            """
            insert into guard_events (event_name, payload_json, occurred_at)
            values (?, ?, ?)
            """,
            (
                "approval.policy_reuse_applied",
                _policy.json.dumps(
                    {
                        "decision_id": decision_id,
                        "harness": current_payload.get("harness"),
                        "artifact_id": current_payload.get("artifact_id"),
                        "scope": current_payload.get("scope"),
                    }
                ),
                current_time,
            ),
        )
        return True

    def approval_reuse_validation_reason(
        self,
        harness: str,
        artifact_id: str | None,
        artifact_hash: str | None,
        workspace: str | None,
        publisher: str | None,
        now: str | None = None,
    ) -> str | None:
        """Explain why otherwise relevant saved allow evidence did not match.

        The normal resolver intentionally returns only usable authority.  This
        read-only diagnostic pass is used after a miss so receipts can explain
        stale content/context without treating a near match as permission.
        """
        from . import store_policy as _policy

        if artifact_id is None:
            return None
        current_time = _policy._canonical_utc_timestamp(now or _policy._now())
        workspace_key = _policy._workspace_policy_key(workspace)
        artifact_family = _policy._artifact_family_key(artifact_id)
        policy_integrity_state: dict[str, object] = {}
        policy_integrity_key: bytes | None = None
        policy_integrity_key_id: str | None = None
        with self._connect() as connection:
            local_rows = _policy._bounded_local_approval_reuse_diagnostic_rows(
                connection,
                harness=harness,
                artifact_id=artifact_id,
                artifact_family=artifact_family,
                artifact_hash=artifact_hash,
            )
            policy_rows = _policy._bounded_policy_approval_reuse_diagnostic_rows(
                connection,
                harness=harness,
                artifact_id=artifact_id,
                artifact_family=artifact_family,
                artifact_hash=artifact_hash,
                publisher=publisher,
            )
            if any(not _policy.is_remote_policy_source(str(row["source"])) for row in policy_rows):
                policy_integrity_state = self._refresh_policy_integrity_state(
                    connection,
                    now=current_time,
                    create_key=False,
                )
                policy_integrity_key, policy_integrity_key_id = self._policy_integrity_secret_material(create=False)
        if local_rows:
            local_integrity_key, local_integrity_key_id = self._policy_integrity_secret_material(create=False)
            for row in local_rows:
                integrity_result = _policy._verify_local_once_approval(
                    dict(row),
                    key=local_integrity_key,
                    key_id=local_integrity_key_id,
                )
                if integrity_result.status != "valid":
                    return "approval_reuse_integrity_failure"
        for row in (*local_rows, *policy_rows):
            row_keys = set(row.keys())
            if "claimed_at" in row_keys and row["claimed_at"] is not None:
                continue
            stored_artifact_id = str(row["artifact_id"]) if row["artifact_id"] is not None else None
            stored_artifact_hash = str(row["artifact_hash"]) if row["artifact_hash"] is not None else None
            same_identity = stored_artifact_id in {artifact_id, artifact_family}
            same_content = artifact_hash is not None and stored_artifact_hash == artifact_hash
            broad_scope = "scope" in row_keys and str(row["scope"]) in {"harness", "global"}
            publisher_scope = (
                "scope" in row_keys
                and str(row["scope"]) == "publisher"
                and row["publisher"] is not None
                and str(row["publisher"]) == publisher
            )
            if not (same_identity or same_content or publisher_scope or (broad_scope and stored_artifact_id is None)):
                continue
            if "decision_id" in row_keys and not _policy.is_remote_policy_source(str(row["source"])):
                integrity_result = self._policy_integrity_result_for_row(
                    row,
                    mode=str(policy_integrity_state.get("mode") or "degraded"),
                    key=policy_integrity_key,
                    key_id=policy_integrity_key_id,
                    trusted_generation=_policy._mapping_int(policy_integrity_state, "generation"),
                )
                if integrity_result.status != "valid" and not _policy._warn_only_policy_integrity_status(
                    integrity_result.status,
                    policy_integrity_state,
                    source=str(row["source"]),
                ):
                    return "approval_reuse_integrity_failure"
            expires_at = str(row["expires_at"]) if row["expires_at"] is not None else None
            if expires_at is not None and _policy._timestamp_has_expired(expires_at, now=current_time):
                return "approval_reuse_expired"
            if _policy._is_approval_context_token(stored_artifact_hash) or _policy._is_approval_context_token(
                artifact_hash
            ):
                context_reason = _policy.approval_context_tokens_validation_reason(stored_artifact_hash, artifact_hash)
                if context_reason is not None:
                    return context_reason
            if stored_artifact_hash is not None and artifact_hash is not None and stored_artifact_hash != artifact_hash:
                return "approval_reuse_content_changed"
            stored_workspace = str(row["workspace"]) if row["workspace"] is not None else None
            stored_publisher = str(row["publisher"]) if row["publisher"] is not None else None
            if stored_workspace is not None and stored_workspace not in {workspace, workspace_key}:
                return "approval_reuse_identity_changed"
            if stored_publisher is not None and stored_publisher != publisher:
                return "approval_reuse_identity_changed"
            if not same_identity:
                return "approval_reuse_identity_changed"
        return None
