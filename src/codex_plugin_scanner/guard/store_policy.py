"""GuardStore domain mixin extracted from store.py."""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false

from __future__ import annotations

from typing import Literal

# ruff: noqa: F403,F405
from .action_lattice import guard_action_severity
from .memory_pattern_fingerprint import (
    build_exact_command_memory_artifact_id,
    build_memory_pattern_fingerprint,
)
from .models import GUARD_ACTION_VALUES
from .runtime.approval_context import approval_context_tokens_validation_reason
from .store_base import *
from .store_event_receipts import _local_once_approval_is_reusable, _verify_local_once_approval

_NON_CONSUMING_POLICY_MATCH_LIMIT = 256
_APPROVAL_REUSE_DIAGNOSTIC_LIMIT = 32
_APPROVAL_CONTEXT_SQL_PATTERN = "guard-approval-context:v1:%"
_POLICY_LOOKUP_COLUMNS = """
    decision_id, harness, scope, artifact_id, action, artifact_hash, workspace, publisher, source,
    reason, owner, expires_at, updated_at, integrity_version, integrity_generation,
    payload_hash, payload_mac, integrity_key_id, signed_at
"""
_LOCAL_REUSE_DIAGNOSTIC_COLUMNS = """
    approval_id, request_id, harness, artifact_id, artifact_hash, workspace, publisher,
    action, created_at, expires_at, claimed_at, integrity_version, payload_hash, payload_mac,
    integrity_key_id, signed_at
"""
_POLICY_REUSE_DIAGNOSTIC_COLUMNS = _POLICY_LOOKUP_COLUMNS

_SqlProbe = tuple[str, tuple[object, ...], str]


def _distinct_non_null(values: Sequence[str | None]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value for value in values if value is not None))


def _execute_unordered_bounded_probes(
    connection: sqlite3.Connection,
    *,
    table: str,
    columns: str,
    probes: Sequence[_SqlProbe],
    limit: int,
    current_time: str,
    explain: bool,
) -> list[sqlite3.Row]:
    """Execute exact probes while bounding each branch by the remaining cap."""

    rows: list[sqlite3.Row] = []
    for predicate, parameters, index_name in probes:
        remaining = limit - len(rows)
        query = f"""
            select {columns}
            from {table} indexed by {index_name}
            where {predicate}
              and (expires_at is null or julianday(expires_at) > julianday(?))
            limit ?
        """
        if explain:
            rows.extend(
                connection.execute(
                    f"explain query plan {query}",
                    (*parameters, current_time, limit),
                ).fetchall()
            )
            continue
        if remaining <= 0:
            break
        rows.extend(connection.execute(query, (*parameters, current_time, remaining)).fetchall())
        if len(rows) >= limit:
            break
    return rows


def _execute_ordered_probe_groups(
    connection: sqlite3.Connection,
    *,
    table: str,
    columns: str,
    probe_groups: Sequence[Sequence[_SqlProbe]],
    order_column: str,
    id_column: str,
    limit: int,
    explain: bool,
) -> list[sqlite3.Row]:
    """Merge indexed priority groups without a SQL CASE sort.

    Probes within a group are disjoint (for example, the requested harness and
    the wildcard harness).  Each can therefore read at most ``limit`` rows in
    index order before the small in-memory merge.  Groups are concatenated in
    the same precedence order previously expressed by ``ORDER BY CASE``.
    """

    rows: list[sqlite3.Row] = []
    for probes in probe_groups:
        group_rows: list[sqlite3.Row] = []
        for predicate, parameters, index_name in probes:
            query = f"""
                select {columns}
                from {table} indexed by {index_name}
                where {predicate}
                order by {order_column} desc, {id_column} desc
                limit ?
            """
            if explain:
                rows.extend(
                    connection.execute(
                        f"explain query plan {query}",
                        (*parameters, limit),
                    ).fetchall()
                )
                continue
            group_rows.extend(connection.execute(query, (*parameters, limit)).fetchall())
        if explain:
            continue
        group_rows.sort(
            key=lambda row: (str(row[order_column]), row[id_column]),
            reverse=True,
        )
        remaining = limit - len(rows)
        if remaining <= 0:
            break
        rows.extend(group_rows[:remaining])
        if len(rows) >= limit:
            break
    return rows


def _hash_partition_probes(
    *,
    base_predicate: str,
    base_parameters: tuple[object, ...],
    exact_hashes: Sequence[str | None],
    exact_index: str,
    legacy_index: str | None,
    exact_first: bool = False,
) -> list[_SqlProbe]:
    """Partition nullable, exact, and legacy hashes into disjoint probes.

    ``exact_first`` is used for scopes whose equal-action precedence is exact
    context, then family-bound context. Artifact and publisher probes retain
    their established nullable-first ordering.
    """

    nullable_probe: _SqlProbe = (
        f"{base_predicate} and artifact_hash is null",
        base_parameters,
        exact_index,
    )
    distinct_hashes = _distinct_non_null(exact_hashes)
    exact_probes: list[_SqlProbe] = [
        (
            f"{base_predicate} and artifact_hash = ?",
            (*base_parameters, exact_hash),
            exact_index,
        )
        for exact_hash in distinct_hashes
    ]
    probes = [*exact_probes, nullable_probe] if exact_first else [nullable_probe, *exact_probes]
    if legacy_index is not None:
        legacy_predicate = (
            f"{base_predicate} and artifact_hash is not null "
            f"and artifact_hash not like '{_APPROVAL_CONTEXT_SQL_PATTERN}'"
        )
        legacy_parameters = list(base_parameters)
        for exact_hash in distinct_hashes:
            legacy_predicate += " and artifact_hash <> ?"
            legacy_parameters.append(exact_hash)
        probes.append((legacy_predicate, tuple(legacy_parameters), legacy_index))
    return probes


def _bounded_non_consuming_policy_rows(
    connection: sqlite3.Connection,
    *,
    harness: str,
    artifact_id: str | None,
    artifact_hash: str | None,
    runtime_exact_match_key: str | None,
    workspace_key: str | None,
    workspace: str | None,
    publisher: str | None,
    action_family_key: str | None,
    current_time: str,
    _explain: bool = False,
) -> list[sqlite3.Row]:
    """Read at most one-over-limit matches through disjoint exact probes.

    Every branch fixes the scope, harness selector, scope selector, and hash
    partition.  This prevents a miss for one artifact from walking all rows for
    the same harness.  Within workspace, harness, and global scopes, exact
    artifact selectors precede family selectors, exact hashes precede nullable
    or legacy family matches, and broad selectors run last.  Legacy non-context
    hashes use dedicated partial indexes, while nullable and exact hashes use
    the regular scope indexes.
    """

    probes: list[_SqlProbe] = []
    harness_selectors = _distinct_non_null((harness, "*"))
    if artifact_id is not None:
        for harness_selector in harness_selectors:
            probes.extend(
                _hash_partition_probes(
                    base_predicate="scope = 'artifact' and artifact_id = ? and harness = ?",
                    base_parameters=(artifact_id, harness_selector),
                    exact_hashes=(artifact_hash, runtime_exact_match_key),
                    exact_index="idx_policy_decisions_lookup_artifact",
                    legacy_index=None,
                )
            )

    workspace_selectors = _distinct_non_null((workspace_key, workspace))
    for workspace_selector in workspace_selectors:
        for harness_selector in harness_selectors:
            for artifact_selector in _distinct_non_null((artifact_id, action_family_key)):
                probes.extend(
                    _hash_partition_probes(
                        base_predicate=("scope = 'workspace' and workspace = ? and harness = ? and artifact_id = ?"),
                        base_parameters=(workspace_selector, harness_selector, artifact_selector),
                        exact_hashes=(artifact_hash,),
                        exact_index="idx_policy_decisions_lookup_workspace",
                        legacy_index=None,
                        exact_first=True,
                    )
                )
            probes.append(
                (
                    "scope = 'workspace' and workspace = ? and harness = ? and artifact_id is null",
                    (workspace_selector, harness_selector),
                    "idx_policy_decisions_lookup_workspace",
                )
            )

    if publisher is not None:
        for harness_selector in harness_selectors:
            probes.extend(
                _hash_partition_probes(
                    base_predicate="scope = 'publisher' and publisher = ? and harness = ?",
                    base_parameters=(publisher, harness_selector),
                    exact_hashes=(artifact_hash,),
                    exact_index="idx_policy_decisions_lookup_publisher",
                    legacy_index="idx_policy_decisions_lookup_publisher_legacy",
                )
            )

    for harness_selector in harness_selectors:
        for artifact_selector in _distinct_non_null((artifact_id, action_family_key)):
            probes.extend(
                _hash_partition_probes(
                    base_predicate="scope = 'harness' and harness = ? and artifact_id = ?",
                    base_parameters=(harness_selector, artifact_selector),
                    exact_hashes=(artifact_hash, runtime_exact_match_key),
                    exact_index="idx_policy_decisions_lookup_harness",
                    legacy_index="idx_policy_decisions_lookup_harness_legacy",
                    exact_first=True,
                )
            )
        probes.extend(
            _hash_partition_probes(
                base_predicate="scope = 'harness' and harness = ? and artifact_id is null",
                base_parameters=(harness_selector,),
                exact_hashes=(artifact_hash, runtime_exact_match_key),
                exact_index="idx_policy_decisions_lookup_harness",
                legacy_index="idx_policy_decisions_lookup_harness_legacy",
                exact_first=True,
            )
        )

    for harness_selector in harness_selectors:
        for artifact_selector in _distinct_non_null((artifact_id, action_family_key)):
            probes.extend(
                _hash_partition_probes(
                    base_predicate="scope = 'global' and harness = ? and artifact_id = ?",
                    base_parameters=(harness_selector, artifact_selector),
                    exact_hashes=(artifact_hash, runtime_exact_match_key),
                    exact_index="idx_policy_decisions_lookup_global",
                    legacy_index="idx_policy_decisions_lookup_global_legacy",
                    exact_first=True,
                )
            )
        probes.extend(
            _hash_partition_probes(
                base_predicate="scope = 'global' and harness = ? and artifact_id is null",
                base_parameters=(harness_selector,),
                exact_hashes=(artifact_hash, runtime_exact_match_key),
                exact_index="idx_policy_decisions_lookup_global",
                legacy_index="idx_policy_decisions_lookup_global_legacy",
                exact_first=True,
            )
        )

    return _execute_unordered_bounded_probes(
        connection,
        table="policy_decisions",
        columns=_POLICY_LOOKUP_COLUMNS,
        probes=probes,
        limit=_NON_CONSUMING_POLICY_MATCH_LIMIT + 1,
        current_time=current_time,
        explain=_explain,
    )


def _append_exclusions(
    predicate: str,
    parameters: tuple[object, ...],
    *,
    column: str,
    values: Sequence[str | None],
) -> tuple[str, tuple[object, ...]]:
    """Exclude nullable values without introducing an OR predicate."""

    next_parameters = list(parameters)
    for value in _distinct_non_null(values):
        predicate += f" and {column} is not ?"
        next_parameters.append(value)
    return predicate, tuple(next_parameters)


def _bounded_local_approval_reuse_diagnostic_rows(
    connection: sqlite3.Connection,
    *,
    harness: str,
    artifact_id: str,
    artifact_family: str | None,
    artifact_hash: str | None,
    _explain: bool = False,
) -> list[sqlite3.Row]:
    """Return local near matches in legacy diagnostic precedence order."""

    identity_selectors = _distinct_non_null((artifact_id, artifact_family))
    probe_groups: list[list[_SqlProbe]] = [
        [
            (
                "claimed_at is null and action = 'allow' and harness = ? and artifact_id = ?",
                (harness, identity_selector),
                "idx_guard_local_once_diagnostic_artifact",
            )
        ]
        for identity_selector in identity_selectors
    ]
    if artifact_hash is not None:
        hash_predicate, hash_parameters = _append_exclusions(
            "claimed_at is null and action = 'allow' and harness = ? and artifact_hash = ?",
            (harness, artifact_hash),
            column="artifact_id",
            values=identity_selectors,
        )
        probe_groups.append(
            [
                (
                    hash_predicate,
                    hash_parameters,
                    "idx_guard_local_once_diagnostic_hash",
                )
            ]
        )
    return _execute_ordered_probe_groups(
        connection,
        table="guard_local_once_approvals",
        columns=_LOCAL_REUSE_DIAGNOSTIC_COLUMNS,
        probe_groups=probe_groups,
        order_column="created_at",
        id_column="approval_id",
        limit=_APPROVAL_REUSE_DIAGNOSTIC_LIMIT,
        explain=_explain,
    )


def _bounded_policy_approval_reuse_diagnostic_rows(
    connection: sqlite3.Connection,
    *,
    harness: str,
    artifact_id: str,
    artifact_family: str | None,
    artifact_hash: str | None,
    publisher: str | None,
    _explain: bool = False,
) -> list[sqlite3.Row]:
    """Return saved-policy near matches through ordered exact probes."""

    harness_selectors = _distinct_non_null((harness, "*"))
    identity_selectors = _distinct_non_null((artifact_id, artifact_family))
    probe_groups: list[list[_SqlProbe]] = []
    for identity_selector in identity_selectors:
        probe_groups.append(
            [
                (
                    "action = ? and harness = ? and artifact_id = ?",
                    (action, harness_selector, identity_selector),
                    "idx_policy_decisions_reuse_artifact",
                )
                for harness_selector in harness_selectors
                for action in GUARD_ACTION_VALUES
            ]
        )

    if artifact_hash is not None:
        hash_probes: list[_SqlProbe] = []
        for harness_selector in harness_selectors:
            for action in GUARD_ACTION_VALUES:
                hash_predicate, hash_parameters = _append_exclusions(
                    "action = ? and harness = ? and artifact_hash = ?",
                    (action, harness_selector, artifact_hash),
                    column="artifact_id",
                    values=identity_selectors,
                )
                hash_probes.append(
                    (
                        hash_predicate,
                        hash_parameters,
                        "idx_policy_decisions_reuse_hash",
                    )
                )
        probe_groups.append(hash_probes)

    broad_probes: list[_SqlProbe] = []
    for harness_selector in harness_selectors:
        for scope, index_name in (
            ("harness", "idx_policy_decisions_diagnostic_harness_broad"),
            ("global", "idx_policy_decisions_diagnostic_global_broad"),
        ):
            broad_predicate, broad_parameters = _append_exclusions(
                f"scope = '{scope}' and action = 'allow' and artifact_id is null and harness = ?",
                (harness_selector,),
                column="artifact_hash",
                values=(artifact_hash,),
            )
            broad_probes.append((broad_predicate, broad_parameters, index_name))
            for action in GUARD_ACTION_VALUES:
                if action == "allow":
                    continue
                non_allow_predicate, non_allow_parameters = _append_exclusions(
                    f"scope = '{scope}' and action = ? and harness = ? and artifact_id is null",
                    (action, harness_selector),
                    column="artifact_hash",
                    values=(artifact_hash,),
                )
                broad_probes.append(
                    (
                        non_allow_predicate,
                        non_allow_parameters,
                        "idx_policy_decisions_reuse_artifact",
                    )
                )
        if publisher is not None:
            publisher_predicate, publisher_parameters = _append_exclusions(
                "scope = 'publisher' and action = 'allow' and harness = ? and publisher = ?",
                (harness_selector, publisher),
                column="artifact_id",
                values=identity_selectors,
            )
            publisher_predicate, publisher_parameters = _append_exclusions(
                publisher_predicate,
                publisher_parameters,
                column="artifact_hash",
                values=(artifact_hash,),
            )
            broad_probes.append(
                (
                    publisher_predicate,
                    publisher_parameters,
                    "idx_policy_decisions_diagnostic_publisher",
                )
            )
            for action in GUARD_ACTION_VALUES:
                if action == "allow":
                    continue
                non_allow_publisher_predicate, non_allow_publisher_parameters = _append_exclusions(
                    "scope = 'publisher' and action = ? and harness = ? and publisher = ?",
                    (action, harness_selector, publisher),
                    column="artifact_id",
                    values=identity_selectors,
                )
                non_allow_publisher_predicate, non_allow_publisher_parameters = _append_exclusions(
                    non_allow_publisher_predicate,
                    non_allow_publisher_parameters,
                    column="artifact_hash",
                    values=(artifact_hash,),
                )
                broad_probes.append(
                    (
                        non_allow_publisher_predicate,
                        non_allow_publisher_parameters,
                        "idx_policy_decisions_reuse_publisher",
                    )
                )
    probe_groups.append(broad_probes)

    return _execute_ordered_probe_groups(
        connection,
        table="policy_decisions",
        columns=_POLICY_REUSE_DIAGNOSTIC_COLUMNS,
        probe_groups=probe_groups,
        order_column="updated_at",
        id_column="decision_id",
        limit=_APPROVAL_REUSE_DIAGNOSTIC_LIMIT,
        explain=_explain,
    )


def _most_restrictive_policy_lookup(
    lookups: Sequence[PolicyDecisionLookupResult],
) -> PolicyDecisionLookupResult:
    """Compose non-consuming direct, exact-command, and memory matches."""

    if not lookups:
        raise ValueError("at least one policy lookup is required")
    selected_lookup = lookups[0]
    selected_decision = selected_lookup["decision"]
    ignored_integrity = selected_lookup.get("ignored_local_integrity")
    revisions = {lookup["authority_revision"] for lookup in lookups}
    authority_revision = next(iter(revisions)) if len(revisions) == 1 else -1
    for lookup in lookups[1:]:
        decision = lookup["decision"]
        if ignored_integrity is None and lookup.get("ignored_local_integrity") is not None:
            ignored_integrity = lookup["ignored_local_integrity"]
        if decision is None:
            continue
        if selected_decision is None or guard_action_severity(
            decision.get("action"),
            unknown_action="block",
        ) > guard_action_severity(selected_decision.get("action"), unknown_action="block"):
            selected_lookup = lookup
            selected_decision = decision
    if selected_decision is not None:
        selected_decision = {
            **selected_decision,
            "_approval_authority_revision": authority_revision,
        }
    return {
        "decision": selected_decision,
        "ignored_local_integrity": ignored_integrity,
        "trust_status": selected_lookup["trust_status"],
        "authority_revision": authority_revision,
    }


def _approval_authority_revision(connection: sqlite3.Connection) -> int:
    row = connection.execute("select revision from guard_approval_authority_revision where singleton = 1").fetchone()
    if row is None:
        return -1
    revision = row["revision"]
    return revision if isinstance(revision, int) and not isinstance(revision, bool) else -1


class StorePolicyMixin:
    def upsert_policy(
        self,
        decision: PolicyDecision,
        now: str,
        *,
        approval_gate_grant: ApprovalGateGrant | None = None,
        remote_write_authorized: bool = False,
    ) -> None:
        now = _canonical_utc_timestamp(now)
        expires_at = _canonical_utc_timestamp(decision.expires_at) if decision.expires_at is not None else None
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
        now = _canonical_utc_timestamp(now)
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
                expires_at = _canonical_utc_timestamp(decision.expires_at) if decision.expires_at is not None else None
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
        consume_one_shot: bool = True,
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
            consume_one_shot=consume_one_shot,
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
        consume_one_shot: bool = True,
    ) -> PolicyDecisionLookupResult:
        direct_lookup = self.resolve_policy_decision_lookup(
            harness,
            artifact_id,
            artifact_hash=artifact_hash,
            workspace=workspace,
            publisher=publisher,
            now=now,
            runtime_exact_match_context=runtime_exact_match_context,
            consume_one_shot=consume_one_shot,
        )
        candidate_lookups = [direct_lookup]
        if consume_one_shot and (
            direct_lookup["decision"] is not None or direct_lookup.get("ignored_local_integrity") is not None
        ):
            return direct_lookup
        exact_command_artifact_id = build_exact_command_memory_artifact_id(memory_command)
        if exact_command_artifact_id is not None and exact_command_artifact_id != artifact_id:
            exact_command_lookup = self.resolve_policy_decision_lookup(
                harness,
                exact_command_artifact_id,
                artifact_hash=artifact_hash,
                workspace=workspace,
                publisher=publisher,
                now=now,
                runtime_exact_match_context=runtime_exact_match_context,
                consume_one_shot=consume_one_shot,
            )
            candidate_lookups.append(exact_command_lookup)
            if consume_one_shot and (
                exact_command_lookup["decision"] is not None
                or exact_command_lookup.get("ignored_local_integrity") is not None
            ):
                return exact_command_lookup
        memory_pattern = build_memory_pattern_fingerprint(
            command=memory_command,
            artifact_type=memory_artifact_type,
            artifact_id=artifact_id,
            artifact_name=memory_artifact_name,
            harness=harness,
        )
        if memory_pattern is None:
            return _most_restrictive_policy_lookup(candidate_lookups)
        memory_artifact_id = f"memory:{harness}:{memory_pattern.kind}:{memory_pattern.fingerprint}"
        if memory_artifact_id == artifact_id:
            return _most_restrictive_policy_lookup(candidate_lookups)
        memory_lookup = self.resolve_policy_decision_lookup(
            harness,
            memory_artifact_id,
            artifact_hash=artifact_hash,
            workspace=workspace,
            publisher=publisher,
            now=now,
            runtime_exact_match_context=runtime_exact_match_context,
            consume_one_shot=consume_one_shot,
        )
        candidate_lookups.append(memory_lookup)
        if consume_one_shot:
            return (
                memory_lookup
                if (memory_lookup["decision"] is not None or memory_lookup.get("ignored_local_integrity") is not None)
                else direct_lookup
            )
        return _most_restrictive_policy_lookup(candidate_lookups)

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
    ) -> PolicyDecisionLookupResult:
        current_time = _canonical_utc_timestamp(now or _now())
        workspace_key = _workspace_policy_key(workspace)
        action_family_key = _artifact_family_key(artifact_id)
        runtime_exact_match_key = (
            _runtime_scoped_exact_match_key(artifact_id, runtime_exact_match_context)
            if artifact_hash is not None
            else None
        )
        events: list[tuple[str, dict[str, object]]] = []
        selected_payload: dict[str, object] | None = None
        ignored_local_integrity: dict[str, object] | None = None
        local_once_integrity_key: bytes | None = None
        local_once_integrity_key_id: str | None = None
        with self._connect() as connection:
            starting_authority_revision = _approval_authority_revision(connection)

            def lookup_result(
                decision: dict[str, object] | None,
                *,
                ignored_integrity: dict[str, object] | None,
                trust_status: dict[str, object],
            ) -> PolicyDecisionLookupResult:
                ending_authority_revision = _approval_authority_revision(connection)
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
                rows = _bounded_non_consuming_policy_rows(
                    connection,
                    harness=harness,
                    artifact_id=artifact_id,
                    artifact_hash=artifact_hash,
                    runtime_exact_match_key=runtime_exact_match_key,
                    workspace_key=workspace_key,
                    workspace=workspace,
                    publisher=publisher,
                    action_family_key=action_family_key,
                    current_time=current_time,
                )
            else:
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
                    scope = 'workspace' and (workspace = ? or workspace = ?) and (
                      artifact_id is null or (
                        artifact_id = ? and (
                          artifact_hash is null or (? is not null and artifact_hash = ?)
                        )
                      )
                    )
                  )
                  or (
                    scope = 'publisher' and publisher = ? and (
                      artifact_hash is null or artifact_hash = ?
                      or artifact_hash not like 'guard-approval-context:v1:%'
                    )
                  )
                  or (
                    scope = 'harness' and (
                      artifact_id is null or artifact_id = ?
                    ) and (
                      artifact_hash is null or artifact_hash = ?
                      or (? is not null and artifact_hash = ?)
                      or artifact_hash not like 'guard-approval-context:v1:%'
                    )
                  )
                    or (
                      scope = 'global' and (
                        artifact_id is null
                        or artifact_id = ?
                        or artifact_id = ?
                      ) and (
                        artifact_hash is null or artifact_hash = ?
                        or (? is not null and artifact_hash = ?)
                        or artifact_hash not like 'guard-approval-context:v1:%'
                      )
                    )
                )
                and (expires_at is null or julianday(expires_at) > julianday(?))
                order by case scope when 'artifact' then 0 when 'workspace' then 1 when 'publisher' then 2
                         when 'harness' then 3 else 4 end,
                         case
                           when scope in ('workspace', 'harness', 'global') and artifact_id is not null then 0
                           else 1
                         end,
                         updated_at desc
                limit ?
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
                        artifact_id,
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
                        runtime_exact_match_key,
                        runtime_exact_match_key,
                        current_time,
                        _NON_CONSUMING_POLICY_MATCH_LIMIT + 1 if not consume_one_shot else -1,
                    ),
                ).fetchall()
            policy_match_overflow = not consume_one_shot and len(rows) > _NON_CONSUMING_POLICY_MATCH_LIMIT
            if policy_match_overflow:
                rows = rows[:_NON_CONSUMING_POLICY_MATCH_LIMIT]
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
                            "match_limit": _NON_CONSUMING_POLICY_MATCH_LIMIT,
                            "authoritative_action": "block",
                        },
                    )
                )
            cached_state = self._load_policy_integrity_state(connection) or {}
            cached_trust_status = TrustStatus.from_policy_integrity_state(cached_state).to_dict()
            if not rows and selected_payload is None:
                for event_name, payload in events:
                    connection.execute(
                        """
                        insert into guard_events (event_name, payload_json, occurred_at)
                        values (?, ?, ?)
                        """,
                        (event_name, json.dumps(payload), current_time),
                    )
                if ignored_local_integrity is not None:
                    ignored_local_integrity["trust_status"] = cached_trust_status
                return lookup_result(
                    None,
                    ignored_integrity=ignored_local_integrity,
                    trust_status=cached_trust_status,
                )
            has_local_rows = any(not is_remote_policy_source(str(candidate["source"])) for candidate in rows)
            if not has_local_rows:
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
                        requested_artifact_hash=artifact_hash,
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
                    candidate_payload = self._policy_row_payload(candidate)
                    candidate_outranks_local_once = selected_payload is None or guard_action_severity(
                        candidate_payload.get("action"),
                        unknown_action="block",
                    ) > guard_action_severity(selected_payload.get("action"), unknown_action="block")
                    if candidate_outranks_local_once:
                        selected_payload = candidate_payload
                        if consume_one_shot and is_remote_policy_source(str(candidate["source"])):
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
                        if consume_one_shot and _is_approval_gate_one_shot_policy(candidate):
                            connection.execute(
                                "delete from policy_decisions where decision_id = ?",
                                (int(candidate["decision_id"]),),
                            )
                    # The first valid policy row retains the established scope
                    # precedence for legacy consuming callers. Current-policy-
                    # first callers inspect every valid match so a saved,
                    # specific allow cannot hide a broader managed block.
                    if consume_one_shot:
                        break
                claim_selected_local_once()
                for event_name, payload in events:
                    connection.execute(
                        """
                        insert into guard_events (event_name, payload_json, occurred_at)
                        values (?, ?, ?)
                        """,
                        (event_name, json.dumps(payload), current_time),
                    )
                if ignored_local_integrity is not None:
                    ignored_local_integrity["trust_status"] = cached_trust_status
                return lookup_result(
                    selected_payload,
                    ignored_integrity=ignored_local_integrity,
                    trust_status=cached_trust_status,
                )
            state = self._refresh_policy_integrity_state(connection, now=current_time, create_key=True)
            trust_status = TrustStatus.from_policy_integrity_state(state).to_dict()
            key, key_id = self._policy_integrity_secret_material(create=True)
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
                    requested_artifact_hash=artifact_hash,
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
                    candidate_payload = self._policy_row_payload(
                        candidate,
                        integrity_result=integrity_result,
                        state=state,
                    )
                    candidate_outranks_local_once = selected_payload is None or guard_action_severity(
                        candidate_payload.get("action"),
                        unknown_action="block",
                    ) > guard_action_severity(selected_payload.get("action"), unknown_action="block")
                    if candidate_outranks_local_once:
                        selected_payload = candidate_payload
                    if (
                        candidate_outranks_local_once
                        and consume_one_shot
                        and is_remote_policy_source(str(candidate["source"]))
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
                        and _is_approval_gate_one_shot_policy(candidate)
                    ):
                        connection.execute(
                            "delete from policy_decisions where decision_id = ?",
                            (int(candidate["decision_id"]),),
                        )
                    if consume_one_shot:
                        break
                    continue
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
            claim_selected_local_once()
            for event_name, payload in events:
                connection.execute(
                    """
                    insert into guard_events (event_name, payload_json, occurred_at)
                    values (?, ?, ?)
                    """,
                    (event_name, json.dumps(payload), current_time),
                )
            if ignored_local_integrity is not None:
                ignored_local_integrity.setdefault("trust_status", trust_status)
            return lookup_result(
                selected_payload,
                ignored_integrity=ignored_local_integrity,
                trust_status=trust_status,
            )

    def resolve_policy_decision(
        self,
        harness: str,
        artifact_id: str | None,
        artifact_hash: str | None = None,
        workspace: str | None = None,
        publisher: str | None = None,
        now: str | None = None,
        runtime_exact_match_context: str | None = None,
        consume_one_shot: bool = True,
    ) -> dict[str, object] | None:
        lookup = self.resolve_policy_decision_lookup(
            harness,
            artifact_id,
            artifact_hash=artifact_hash,
            workspace=workspace,
            publisher=publisher,
            now=now,
            runtime_exact_match_context=runtime_exact_match_context,
            consume_one_shot=consume_one_shot,
        )
        return lookup["decision"]

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

        if decision.get("action") != "allow":
            return None
        approval_id = decision.get("approval_id")
        if isinstance(approval_id, str) and approval_id:
            artifact_id = decision.get("artifact_id")
            if not isinstance(artifact_id, str) or not artifact_id:
                return None
            return "retained" if _local_once_approval_is_reusable(artifact_id) else "consumed"
        decision_id = decision.get("decision_id")
        if not isinstance(decision_id, int) or isinstance(decision_id, bool):
            return None
        if decision.get("source") == _APPROVAL_GATE_POLICY_SOURCE and decision.get("expires_at") is not None:
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

        current_time = _canonical_utc_timestamp(now or _now())
        unique_decisions: list[Mapping[str, object]] = []
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
            if _approval_authority_revision(connection) != expected_revision:
                connection.rollback()
                return False
            for decision in unique_decisions:
                if not self._claim_approval_reuse_decision_locked(
                    connection,
                    decision=decision,
                    current_time=current_time,
                    local_integrity_key=local_integrity_key,
                    local_integrity_key_id=local_integrity_key_id,
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
    ) -> bool:
        """Claim one prevalidated member of an open batch transaction."""

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
                    json.dumps(
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
        if is_remote_policy_source(source):
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
                json.dumps(
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

        if artifact_id is None:
            return None
        current_time = _canonical_utc_timestamp(now or _now())
        workspace_key = _workspace_policy_key(workspace)
        artifact_family = _artifact_family_key(artifact_id)
        policy_integrity_state: dict[str, object] = {}
        policy_integrity_key: bytes | None = None
        policy_integrity_key_id: str | None = None
        with self._connect() as connection:
            local_rows = _bounded_local_approval_reuse_diagnostic_rows(
                connection,
                harness=harness,
                artifact_id=artifact_id,
                artifact_family=artifact_family,
                artifact_hash=artifact_hash,
            )
            policy_rows = _bounded_policy_approval_reuse_diagnostic_rows(
                connection,
                harness=harness,
                artifact_id=artifact_id,
                artifact_family=artifact_family,
                artifact_hash=artifact_hash,
                publisher=publisher,
            )
            if any(not is_remote_policy_source(str(row["source"])) for row in policy_rows):
                policy_integrity_state = self._refresh_policy_integrity_state(
                    connection,
                    now=current_time,
                    create_key=False,
                )
                policy_integrity_key, policy_integrity_key_id = self._policy_integrity_secret_material(create=False)
        if local_rows:
            local_integrity_key, local_integrity_key_id = self._policy_integrity_secret_material(create=False)
            for row in local_rows:
                integrity_result = _verify_local_once_approval(
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
            if "decision_id" in row_keys and not is_remote_policy_source(str(row["source"])):
                integrity_result = self._policy_integrity_result_for_row(
                    row,
                    mode=str(policy_integrity_state.get("mode") or "degraded"),
                    key=policy_integrity_key,
                    key_id=policy_integrity_key_id,
                    trusted_generation=_mapping_int(policy_integrity_state, "generation"),
                )
                if integrity_result.status != "valid" and not _warn_only_policy_integrity_status(
                    integrity_result.status,
                    policy_integrity_state,
                    source=str(row["source"]),
                ):
                    return "approval_reuse_integrity_failure"
            expires_at = str(row["expires_at"]) if row["expires_at"] is not None else None
            if expires_at is not None and _timestamp_has_expired(expires_at, now=current_time):
                return "approval_reuse_expired"
            if _is_approval_context_token(stored_artifact_hash) or _is_approval_context_token(artifact_hash):
                context_reason = approval_context_tokens_validation_reason(stored_artifact_hash, artifact_hash)
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

    @staticmethod
    def _normalized_policy_keys(decision: PolicyDecision) -> tuple[str | None, str | None, str | None, str | None]:
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

        current_time = _canonical_utc_timestamp(now or datetime.now(timezone.utc).isoformat())
        workspace_key = _workspace_policy_key(str(workspace) if workspace is not None else None)
        with self._connect() as connection:
            rows = connection.execute(
                """
                select decision_id, harness, scope, artifact_id, artifact_hash, workspace, publisher,
                       action, source, expires_at, updated_at, integrity_version, integrity_generation,
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
            "trust_status": TrustStatus.from_policy_integrity_state(integrity_state).to_dict(),
        }
        return hashlib.sha256(
            json.dumps(material, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
