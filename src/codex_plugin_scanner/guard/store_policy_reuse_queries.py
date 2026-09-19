"""Bounded approval-reuse queries and authority revision reads."""

from __future__ import annotations

from .store_base import PolicyDecisionLookupResult, Sequence, sqlite3


def _append_exclusions(
    predicate: str,
    parameters: tuple[object, ...],
    *,
    column: str,
    values: Sequence[str | None],
) -> tuple[str, tuple[object, ...]]:
    """Exclude nullable values without introducing an OR predicate."""
    from . import store_policy as _policy

    next_parameters = list(parameters)
    for value in _policy._distinct_non_null(values):
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
    from . import store_policy as _policy

    identity_selectors = _policy._distinct_non_null((artifact_id, artifact_family))
    probe_groups: list[list[_policy._SqlProbe]] = [
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
        hash_predicate, hash_parameters = _policy._append_exclusions(
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
    return _policy._execute_ordered_probe_groups(
        connection,
        table="guard_local_once_approvals",
        columns=_policy._LOCAL_REUSE_DIAGNOSTIC_COLUMNS,
        probe_groups=probe_groups,
        order_column="created_at",
        id_column="approval_id",
        limit=_policy._APPROVAL_REUSE_DIAGNOSTIC_LIMIT,
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
    from . import store_policy as _policy

    harness_selectors = _policy._distinct_non_null((harness, "*"))
    identity_selectors = _policy._distinct_non_null((artifact_id, artifact_family))
    probe_groups: list[list[_policy._SqlProbe]] = []
    for identity_selector in identity_selectors:
        probe_groups.append(
            [
                (
                    "action = ? and harness = ? and artifact_id = ?",
                    (action, harness_selector, identity_selector),
                    "idx_policy_decisions_reuse_artifact",
                )
                for harness_selector in harness_selectors
                for action in _policy.GUARD_ACTION_VALUES
            ]
        )

    if artifact_hash is not None:
        hash_probes: list[_policy._SqlProbe] = []
        for harness_selector in harness_selectors:
            for action in _policy.GUARD_ACTION_VALUES:
                hash_predicate, hash_parameters = _policy._append_exclusions(
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

    broad_probes: list[_policy._SqlProbe] = []
    for harness_selector in harness_selectors:
        for scope, index_name in (
            ("harness", "idx_policy_decisions_diagnostic_harness_broad"),
            ("global", "idx_policy_decisions_diagnostic_global_broad"),
        ):
            broad_predicate, broad_parameters = _policy._append_exclusions(
                f"scope = '{scope}' and action = 'allow' and artifact_id is null and harness = ?",
                (harness_selector,),
                column="artifact_hash",
                values=(artifact_hash,),
            )
            broad_probes.append((broad_predicate, broad_parameters, index_name))
            for action in _policy.GUARD_ACTION_VALUES:
                if action == "allow":
                    continue
                non_allow_predicate, non_allow_parameters = _policy._append_exclusions(
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
            publisher_predicate, publisher_parameters = _policy._append_exclusions(
                "scope = 'publisher' and action = 'allow' and harness = ? and publisher = ?",
                (harness_selector, publisher),
                column="artifact_id",
                values=identity_selectors,
            )
            publisher_predicate, publisher_parameters = _policy._append_exclusions(
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
            for action in _policy.GUARD_ACTION_VALUES:
                if action == "allow":
                    continue
                non_allow_publisher_predicate, non_allow_publisher_parameters = _policy._append_exclusions(
                    "scope = 'publisher' and action = ? and harness = ? and publisher = ?",
                    (action, harness_selector, publisher),
                    column="artifact_id",
                    values=identity_selectors,
                )
                non_allow_publisher_predicate, non_allow_publisher_parameters = _policy._append_exclusions(
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

    return _policy._execute_ordered_probe_groups(
        connection,
        table="policy_decisions",
        columns=_policy._POLICY_REUSE_DIAGNOSTIC_COLUMNS,
        probe_groups=probe_groups,
        order_column="updated_at",
        id_column="decision_id",
        limit=_policy._APPROVAL_REUSE_DIAGNOSTIC_LIMIT,
        explain=_explain,
    )


def _most_restrictive_policy_lookup(
    lookups: Sequence[PolicyDecisionLookupResult],
) -> PolicyDecisionLookupResult:
    """Compose non-consuming direct, exact-command, and memory matches."""
    from . import store_policy as _policy

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
        if selected_decision is None or _policy.guard_action_severity(
            decision.get("action"),
            unknown_action="block",
        ) > _policy.guard_action_severity(selected_decision.get("action"), unknown_action="block"):
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
