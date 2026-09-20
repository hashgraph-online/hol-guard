"""Policy row writes and managed keyring reconciliation."""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false

from __future__ import annotations

from typing import TYPE_CHECKING

from .store_base import ApprovalGateGrant, Mapping, Path, PolicyDecision, Sequence, sqlite3

if TYPE_CHECKING:
    from .policy_rule_identity import PolicyRuleIdentity


class StorePolicyMixin:
    def reconcile_managed_policy_bundle_keyring_state(
        self,
        *,
        managed_keyring: Mapping[str, object] | None,
        quarantined_local_keyring: Mapping[str, object] | None,
        provenance: Mapping[str, object] | None,
        now: str,
        force_clear: bool = False,
    ) -> bool:
        """Atomically reconcile the user-side mirror of machine key authority.

        A configured managed domain writes its diagnostic mirror, empty local
        anchor slot, and provenance marker in one transaction. Cleanup may be
        forced by an authorized managed repair/deactivation so deleting the
        user-writable marker cannot preserve a replacement local anchor.
        """
        from . import store_policy as _policy

        state_keys = (
            "managed_policy_bundle_keyring_provenance",
            "managed_policy_bundle_keyring_mirror",
            "policy_bundle_keyring",
        )
        normalized_now = _policy._canonical_utc_timestamp(now)
        configured = managed_keyring is not None and quarantined_local_keyring is not None and provenance is not None
        if (
            any(item is not None for item in (managed_keyring, quarantined_local_keyring, provenance))
            and not configured
        ):
            raise ValueError("managed_policy_bundle_keyring_reconcile_incomplete")
        with self._connect() as connection:
            connection.execute("begin immediate")
            if not configured:
                marker = connection.execute(
                    "select 1 from sync_state where state_key = ?",
                    (state_keys[0],),
                ).fetchone()
                if marker is None and not force_clear:
                    connection.rollback()
                    return False
                placeholders = ",".join("?" for _ in state_keys)
                connection.execute(
                    f"delete from sync_state where state_key in ({placeholders})",
                    state_keys,
                )
                return True
            assert managed_keyring is not None
            assert quarantined_local_keyring is not None
            assert provenance is not None
            payloads = {
                state_keys[0]: dict(provenance),
                state_keys[1]: dict(managed_keyring),
                state_keys[2]: dict(quarantined_local_keyring),
            }
            encoded = {
                state_key: _policy.json.dumps(payload, allow_nan=False) for state_key, payload in payloads.items()
            }
            for state_key, payload_json in encoded.items():
                connection.execute(
                    """
                    insert into sync_state (state_key, payload_json, updated_at)
                    values (?, ?, ?)
                    on conflict(state_key) do update set
                      payload_json = excluded.payload_json,
                      updated_at = excluded.updated_at
                    """,
                    (state_key, payload_json, normalized_now),
                )
        return True

    def _cached_policy_bundle_decision_identities(
        self,
        *,
        now: float | None = None,
    ) -> frozenset[tuple[object, ...]]:
        """Return only rows derivable from the currently authorized signed bundle."""

        return frozenset(self._cached_policy_bundle_row_authorities(now=now))

    def _cached_policy_bundle_row_authorities(
        self, *, now: float | None = None
    ) -> dict[tuple[object, ...], PolicyRuleIdentity | None]:
        from . import store_policy as _policy
        from .policy_bundle_row_authority import PolicyBundleRowStore, current_policy_bundle_row_authorities

        return current_policy_bundle_row_authorities(
            _policy.cast(PolicyBundleRowStore, _policy.cast(object, self)), now=now
        )

    def upsert_policy(
        self,
        decision: PolicyDecision,
        now: str,
        *,
        approval_gate_grant: ApprovalGateGrant | None = None,
        remote_write_authorized: bool = False,
    ) -> None:
        from . import store_policy as _policy

        now = _policy._canonical_utc_timestamp(now)
        _policy.validate_policy_write_authority(
            decision,
            remote_write_authorized=remote_write_authorized,
        )
        _policy.require_policy_write(
            self.guard_home,
            decision=decision,
            approval_gate_grant=approval_gate_grant,
            now=now,
        )
        _policy._validate_scoped_policy_artifact_target(decision.scope, decision.artifact_id)
        next_control_state: dict[str, object] | None = None
        with self._connect() as connection:
            secret_material = (None, None)
            if not _policy.is_remote_policy_source(decision.source):
                secret_material = self._policy_integrity_secret_material(create=True)
            next_control_state = self._upsert_policy_locked(
                connection,
                decision=decision,
                now=now,
                secret_material=secret_material,
            )
        if next_control_state is not None:
            self._finalize_policy_integrity_control_state(next_control_state)

    def _upsert_policy_locked(
        self,
        connection: sqlite3.Connection,
        *,
        decision: PolicyDecision,
        now: str,
        secret_material: tuple[bytes | None, str | None],
    ) -> dict[str, object] | None:
        from . import store_policy as _policy

        expires_at = _policy._canonical_utc_timestamp(decision.expires_at) if decision.expires_at is not None else None
        artifact_id, artifact_hash, workspace, publisher = self._normalized_policy_keys(decision)
        state = self._refresh_policy_integrity_state(
            connection,
            now=now,
            create_key=not _policy.is_remote_policy_source(decision.source),
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
              and exact_command_sha256 is ?
            """,
            (
                decision.harness,
                decision.scope,
                artifact_id,
                artifact_hash,
                workspace,
                publisher,
                decision.exact_command_sha256,
            ),
        )
        cursor = connection.execute(
            """
            insert into policy_decisions (
              harness, scope, artifact_id, artifact_hash, workspace, publisher,
                   exact_command_sha256,
              action, reason, owner, source,
              expires_at, updated_at, integrity_version, integrity_generation, payload_hash, payload_mac,
              integrity_key_id, signed_at
            )
            values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                decision.harness,
                decision.scope,
                artifact_id,
                artifact_hash,
                workspace,
                publisher,
                decision.exact_command_sha256,
                decision.action,
                decision.reason,
                decision.owner,
                decision.source,
                expires_at,
                now,
                None,
                None,
                None,
                None,
                None,
                None,
            ),
        )
        if _policy.is_remote_policy_source(decision.source) or state.get("mode") != "protected":
            return None
        key, key_id = secret_material
        if key is None or key_id is None:
            return None
        trusted_state = self._load_policy_integrity_control_state(create=True)
        if trusted_state is None:
            return None
        lastrowid = cursor.lastrowid
        if lastrowid is None:
            raise RuntimeError("Guard policy decision row was not inserted.")
        return self._advance_policy_integrity_generation(
            connection,
            now=now,
            key=key,
            key_id=key_id,
            trusted_state=trusted_state,
            force_sign_decision_ids={lastrowid},
        )

    def replace_remote_policies(
        self,
        decisions: list[PolicyDecision],
        now: str,
        *,
        approval_gate_grant: ApprovalGateGrant | None = None,
        remote_write_authorized: bool = False,
    ) -> None:
        now, rows = self._prepared_remote_policy_rows(
            decisions,
            now,
            approval_gate_grant=approval_gate_grant,
            remote_write_authorized=remote_write_authorized,
        )
        with self._connect() as connection:
            self._replace_remote_policy_rows_locked(connection, rows)

    def _prepared_remote_policy_rows(
        self,
        decisions: Sequence[PolicyDecision],
        now: str,
        *,
        approval_gate_grant: ApprovalGateGrant | None,
        remote_write_authorized: bool,
    ) -> tuple[str, list[tuple[object, ...]]]:
        from . import store_policy as _policy

        normalized_now = _policy._canonical_utc_timestamp(now)
        rows: list[tuple[object, ...]] = []
        for decision in decisions:
            _policy.validate_policy_write_authority(
                decision,
                remote_write_authorized=remote_write_authorized,
            )
            _policy.require_policy_write(
                self.guard_home,
                decision=decision,
                approval_gate_grant=approval_gate_grant,
                now=normalized_now,
            )
            expires_at = (
                _policy._canonical_utc_timestamp(decision.expires_at) if decision.expires_at is not None else None
            )
            _policy._validate_scoped_policy_artifact_target(decision.scope, decision.artifact_id)
            artifact_id, artifact_hash, workspace, publisher = self._normalized_policy_keys(decision)
            rows.append(
                (
                    decision.harness,
                    decision.scope,
                    artifact_id,
                    artifact_hash,
                    workspace,
                    publisher,
                    decision.exact_command_sha256,
                    decision.action,
                    decision.reason,
                    decision.owner,
                    decision.source,
                    expires_at,
                    normalized_now,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
            )
        return normalized_now, rows

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

        from . import store_policy as _policy

        current_time = _policy._canonical_utc_timestamp(now or datetime.now(timezone.utc).isoformat())
        workspace_key = _policy._workspace_policy_key(str(workspace) if workspace is not None else None)
        with self._connect() as connection:
            rows = connection.execute(
                """
                select decision_id, harness, scope, artifact_id, artifact_hash, workspace, publisher,
                       exact_command_sha256, action, source, expires_at, updated_at,
                       integrity_version, integrity_generation,
                       payload_hash, payload_mac, integrity_key_id, signed_at
                from policy_decisions
                where (harness = ? or harness = '*')
                  and (expires_at is null or julianday(expires_at) > julianday(?))
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
            "trust_status": _policy.TrustStatus.from_policy_integrity_state(integrity_state).to_dict(),
        }
        return hashlib.sha256(
            json.dumps(material, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
