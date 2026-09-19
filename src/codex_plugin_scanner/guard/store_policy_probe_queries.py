"""Bounded selector probes and the consuming policy query."""

from __future__ import annotations

from .store_base import Sequence, sqlite3

_SqlProbe = tuple[str, tuple[object, ...], str]

_POLICY_LOOKUP_CONSUMING_SQL = """
                select decision_id, harness, scope, artifact_id, action, artifact_hash, workspace, publisher,
                   exact_command_sha256,
                       source,
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
                      artifact_id is null or artifact_id = ? or artifact_id = ?
                    ) and (
                      artifact_hash is null or (? is not null and artifact_hash = ?)
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
                and (exact_command_sha256 is null or exact_command_sha256 = ?)
                and (expires_at is null or julianday(expires_at) > julianday(?))
                limit ?
                """


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
    from . import store_policy as _policy

    rows: list[_policy.sqlite3.Row] = []
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
    from . import store_policy as _policy

    rows: list[_policy.sqlite3.Row] = []
    for probes in probe_groups:
        group_rows: list[_policy.sqlite3.Row] = []
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

    ``exact_first`` controls probe traversal, not generic authority precedence.
    Winner selection orders the complete bounded candidate set after reading
    these disjoint partitions.
    """
    from . import store_policy as _policy

    nullable_probe: _policy._SqlProbe = (
        f"{base_predicate} and artifact_hash is null",
        base_parameters,
        exact_index,
    )
    distinct_hashes = _policy._distinct_non_null(exact_hashes)
    exact_probes: list[_policy._SqlProbe] = [
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
            f"and artifact_hash not like '{_policy._APPROVAL_CONTEXT_SQL_PATTERN}'"
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
    global_runtime_exact_match_key: str | None,
    workspace_key: str | None,
    workspace: str | None,
    publisher: str | None,
    action_family_key: str | None,
    current_time: str,
    exact_command_sha256: str | None = None,
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
    from . import store_policy as _policy

    probes: list[_policy._SqlProbe] = []
    harness_selectors = _policy._distinct_non_null((harness, "*"))
    if artifact_id is not None:
        for harness_selector in harness_selectors:
            probes.extend(
                _policy._hash_partition_probes(
                    base_predicate="scope = 'artifact' and artifact_id = ? and harness = ?",
                    base_parameters=(artifact_id, harness_selector),
                    exact_hashes=(artifact_hash, runtime_exact_match_key),
                    exact_index="idx_policy_decisions_lookup_artifact",
                    legacy_index=None,
                )
            )

    workspace_selectors = _policy._distinct_non_null((workspace_key, workspace))
    for workspace_selector in workspace_selectors:
        for harness_selector in harness_selectors:
            for artifact_selector in _policy._distinct_non_null((artifact_id, action_family_key)):
                probes.extend(
                    _policy._hash_partition_probes(
                        base_predicate=("scope = 'workspace' and workspace = ? and harness = ? and artifact_id = ?"),
                        base_parameters=(workspace_selector, harness_selector, artifact_selector),
                        exact_hashes=(artifact_hash,),
                        exact_index="idx_policy_decisions_lookup_workspace",
                        legacy_index=None,
                        exact_first=True,
                    )
                )
            probes.extend(
                _policy._hash_partition_probes(
                    base_predicate="scope = 'workspace' and workspace = ? and harness = ? and artifact_id is null",
                    base_parameters=(workspace_selector, harness_selector),
                    exact_hashes=(artifact_hash,),
                    exact_index="idx_policy_decisions_lookup_workspace",
                    legacy_index=None,
                )
            )

    if publisher is not None:
        for harness_selector in harness_selectors:
            probes.extend(
                _policy._hash_partition_probes(
                    base_predicate="scope = 'publisher' and publisher = ? and harness = ?",
                    base_parameters=(publisher, harness_selector),
                    exact_hashes=(artifact_hash,),
                    exact_index="idx_policy_decisions_lookup_publisher",
                    legacy_index="idx_policy_decisions_lookup_publisher_legacy",
                )
            )

    for harness_selector in harness_selectors:
        for artifact_selector in _policy._distinct_non_null((artifact_id, action_family_key)):
            probes.extend(
                _policy._hash_partition_probes(
                    base_predicate="scope = 'harness' and harness = ? and artifact_id = ?",
                    base_parameters=(harness_selector, artifact_selector),
                    exact_hashes=(artifact_hash, runtime_exact_match_key),
                    exact_index="idx_policy_decisions_lookup_harness",
                    legacy_index="idx_policy_decisions_lookup_harness_legacy",
                    exact_first=True,
                )
            )
        probes.extend(
            _policy._hash_partition_probes(
                base_predicate="scope = 'harness' and harness = ? and artifact_id is null",
                base_parameters=(harness_selector,),
                exact_hashes=(artifact_hash, runtime_exact_match_key),
                exact_index="idx_policy_decisions_lookup_harness",
                legacy_index="idx_policy_decisions_lookup_harness_legacy",
                exact_first=True,
            )
        )

    for harness_selector in harness_selectors:
        for artifact_selector in _policy._distinct_non_null((artifact_id, action_family_key)):
            probes.extend(
                _policy._hash_partition_probes(
                    base_predicate="scope = 'global' and harness = ? and artifact_id = ?",
                    base_parameters=(harness_selector, artifact_selector),
                    exact_hashes=(artifact_hash, global_runtime_exact_match_key),
                    exact_index="idx_policy_decisions_lookup_global",
                    legacy_index="idx_policy_decisions_lookup_global_legacy",
                    exact_first=True,
                )
            )
        probes.extend(
            _policy._hash_partition_probes(
                base_predicate="scope = 'global' and harness = ? and artifact_id is null",
                base_parameters=(harness_selector,),
                exact_hashes=(artifact_hash, global_runtime_exact_match_key),
                exact_index="idx_policy_decisions_lookup_global",
                legacy_index="idx_policy_decisions_lookup_global_legacy",
                exact_first=True,
            )
        )

    return _policy._execute_unordered_bounded_probes(
        connection,
        table="policy_decisions",
        columns=_policy._POLICY_LOOKUP_COLUMNS,
        probes=[
            (
                f"({predicate}) and (exact_command_sha256 is null or exact_command_sha256 = ?)",
                (*params, exact_command_sha256),
                index,
            )
            for predicate, params, index in probes
        ],
        limit=_policy._NON_CONSUMING_POLICY_MATCH_LIMIT + 1,
        current_time=current_time,
        explain=_explain,
    )
