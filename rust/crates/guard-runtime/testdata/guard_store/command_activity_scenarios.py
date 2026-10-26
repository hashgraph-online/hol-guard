"""Scenarios replayed through the original Python command-activity store."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from command_activity_factories import (
    at,
    evidence_a,
    evidence_b,
    evidence_c,
    evidence_d,
    evidence_e,
    handle,
    replace,
    shadow_for,
)

from codex_plugin_scanner.guard.runtime.command_activity_contract import (
    ActivityLatencyBucket,
    CommandActivityEvidence,
    CommandExecutionStatus,
    CommandHookPhase,
    CommandProofLevel,
    CorrelationKind,
)
from codex_plugin_scanner.guard.runtime.command_shadow_evaluation import CommandShadowCohort
from codex_plugin_scanner.guard.runtime.effect_contract import EffectKind

REQUEST = CorrelationKind.REQUEST
NOW = at(2026, 7, 20, 12)
ACTIVITY_INSERT = (
    "insert into command_activity (activity_id, occurred_at, harness, hook_phase, execution_status, "
    "proof_level, policy_action, decision_reason_code, controlling_rule_id, parse_confidence, "
    "uncertainty_class, match_count, prompted, approval_reuse_status, receipt_link_status, receipt_id, "
    "evaluation_latency_bucket, persistence_latency_bucket, schema_version) "
    "values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)
MATCH_INSERT = (
    "insert into command_activity_matches (activity_id, ordinal, extension_id, extension_version, rule_id, "
    "rule_version, match_class, severity, default_floor, safe_variant_id, schema_version) "
    "values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)
EFFECT_INSERT = "insert into command_activity_match_effects (activity_id, ordinal, effect_class) values (?, ?, ?)"


def call(method: str, *args: object, label: str = "", python_side: bool = False, **kwargs: object) -> dict:
    return {"method": method, "args": args, "kwargs": kwargs, "label": label, "python_side": python_side}


def record(evidence, label: str = "", **kwargs: object) -> dict:
    return call("record_command_activity", evidence, label=label, **kwargs)


def sql_for(evidence: CommandActivityEvidence) -> dict:
    """Raw legacy rows with no rollup membership: only the pending trigger runs."""

    activity = evidence.activity
    statements = [
        (
            ACTIVITY_INSERT,
            [
                activity.activity_id,
                activity.occurred_at.isoformat(),
                activity.harness,
                activity.hook_phase.value,
                activity.execution_status.value,
                activity.proof_level.value,
                activity.policy_action,
                activity.decision_reason_code.value if activity.decision_reason_code else None,
                activity.controlling_rule_id,
                activity.parse_confidence.value if activity.parse_confidence else None,
                activity.uncertainty_class.value if activity.uncertainty_class else None,
                activity.match_count,
                int(activity.prompted),
                activity.approval_reuse_status.value,
                activity.receipt_link_status.value,
                activity.receipt_id,
                activity.evaluation_latency_bucket.value,
                activity.persistence_latency_bucket.value,
                activity.schema_version,
            ],
        )
    ]
    for match in evidence.matches:
        statements.append(
            (
                MATCH_INSERT,
                [
                    match.activity_id,
                    match.ordinal,
                    match.identity.extension_id,
                    match.identity.extension_version,
                    match.identity.rule_id,
                    match.identity.rule_version,
                    match.match_class.value,
                    match.severity.value,
                    match.default_floor,
                    match.safe_variant_id,
                    match.schema_version,
                ],
            )
        )
        for effect in sorted(match.effect_claims, key=lambda item: item.value):
            statements.append((EFFECT_INSERT, [match.activity_id, match.ordinal, effect.value]))
    return {"sql": statements, "label": f"legacy {activity.activity_id}"}


def raw(statement: str, *params: object, label: str = "") -> dict:
    return {"sql": [(statement, list(params))], "label": label}


def failure(code: str, label: str = "", **kwargs: object) -> dict:
    return call(
        "record_command_activity_persistence_failure",
        error_code=code,
        occurred_at=kwargs.get("occurred_at", NOW),
        label=label,
        python_side=bool(kwargs.get("python_side")),
    )


def maintain(
    now: datetime = NOW, retain: int = 30, batch: int = 1000, label: str = "", python_side: bool = False
) -> dict:
    return call(
        "maintain_command_activity",
        now=now,
        detail_retain_days=retain,
        batch_size=batch,
        label=label or f"maintain batch={batch}",
        python_side=python_side,
    )


def confirmed(activity, *, success: bool = True, **overrides: object):
    return replace(
        activity,
        hook_phase=CommandHookPhase.POST_SUCCESS if success else CommandHookPhase.POST_FAILURE,
        execution_status=(
            CommandExecutionStatus.CONFIRMED_SUCCESS if success else CommandExecutionStatus.CONFIRMED_FAILURE
        ),
        proof_level=CommandProofLevel.POST_HOOK,
        persistence_latency_bucket=ActivityLatencyBucket.LE_10_MS,
        **overrides,
    )


def _record_basic() -> list[dict]:
    a, b, c, d = evidence_a(), evidence_b(), evidence_c(), evidence_d()
    e = evidence_e()
    changed_match = CommandActivityEvidence(
        a.activity, (a.matches[0], replace(a.matches[1], severity=a.matches[0].severity))
    )
    return [
        record(a, "new two-match"),
        record(a, "exact replay"),
        record(changed_match, "conflicting match"),
        record(
            CommandActivityEvidence(
                replace(a.activity, persistence_latency_bucket=ActivityLatencyBucket.LE_100_MS), a.matches
            ),
            "conflicting activity",
        ),
        record(b, "new no match with preview", invocation_preview="  git status  "),
        record(b, "replay with preview"),
        record(evidence_b("activity:b2", request="8"), "empty preview", invocation_preview="   ", python_side=True),
        record(evidence_b("activity:b3", request="9"), "nul preview", invocation_preview="a\x00b", python_side=True),
        record(c, "safe variant"),
        record(d, "unpaired post"),
        record(e, "uncertainty with shadow", shadow=shadow_for(e, cohorts=(CommandShadowCohort.BASELINE,))),
        call("get_command_activity_by_request_correlation", handle(REQUEST, "a"), label="lookup a"),
        call("get_command_activity_by_request_correlation", handle(REQUEST, "f"), label="lookup unknown"),
        call("get_command_activity_by_request_correlation", handle(REQUEST, "e"), label="lookup e"),
        call("is_exact_command_activity_pre_replay", a, label="pre replay true"),
        call("is_exact_command_activity_pre_replay", c, label="pre replay no correlation"),
        call(
            "is_exact_command_activity_pre_replay", evidence_b("activity:b9", request="9"), label="pre replay unknown"
        ),
        call(
            "is_exact_command_activity_pre_replay",
            CommandActivityEvidence(replace(b.activity, evaluation_latency_bucket=ActivityLatencyBucket.LE_100_MS), ()),
            label="pre replay conflict",
        ),
        call(
            "is_exact_command_activity_pre_replay",
            CommandActivityEvidence(
                a.activity,
                (replace(a.matches[0], effect_claims=frozenset({EffectKind.SENSITIVE_READ})), a.matches[1]),
            ),
            label="pre replay effects",
        ),
        record(evidence_a("activity:a2", at(2026, 7, 21, 1)), "duplicate request handle"),
    ]


def _record_shadow() -> list[dict]:
    a, b, c = evidence_a(), evidence_b(), evidence_c()
    two = (CommandShadowCohort.BASELINE, CommandShadowCohort.REMOTE_MUTATION_FLOORS)
    return [
        failure("storage_failed", "command failure"),
        failure("shadow_evaluation_failed", "shadow failure"),
        record(a, "new with shadow", shadow=shadow_for(a, cohorts=two)),
        record(a, "replay with shadow", shadow=shadow_for(a, cohorts=two)),
        record(a, "shadow proposal conflict", shadow=shadow_for(a, cohorts=two, proposal_version="proposal.other.v2")),
        record(a, "shadow cohort conflict", shadow=shadow_for(a, cohorts=(CommandShadowCohort.BASELINE,))),
        record(b, "no shadow"),
        record(b, "shadow missing on replay", shadow=shadow_for(b)),
        failure("shadow_evaluation_failed", "shadow failure again"),
        record(c, "shadow succeeded without row", shadow_evaluation_succeeded=True),
        call("record_command_activity_observation_conflict", occurred_at=at(2026, 7, 20, 13), label="conflict"),
    ]


def _lifecycle() -> list[dict]:
    a, b, e = evidence_a(), evidence_b(), evidence_e()
    attempted = evidence_a(
        "activity:t1",
        at(2026, 7, 18, 21),
        request="1",
        session="2",
        execution_status=CommandExecutionStatus.ATTEMPTED,
    )
    ok = confirmed(a.activity)
    return [
        record(a, "pre"),
        call("transition_command_activity", ok, label="to confirmed success"),
        call("transition_command_activity", ok, label="exact replay"),
        call("transition_command_activity", a.activity, label="back to pre"),
        call("transition_command_activity", confirmed(a.activity, success=False), label="success to failure"),
        call("transition_command_activity", replace(ok, policy_action="warn"), label="immutable decision"),
        call(
            "transition_command_activity",
            replace(ok, persistence_latency_bucket=ActivityLatencyBucket.LE_100_MS),
            label="idempotent change",
        ),
        call(
            "transition_command_activity",
            replace(ok, request_correlation=handle(REQUEST, "7")),
            label="unknown correlation",
        ),
        call("transition_command_activity", replace(ok, activity_id="activity:zz"), label="identity conflict"),
        call("transition_command_activity", evidence_d().activity, label="no request", python_side=True),
        call("get_command_activity_by_request_correlation", handle(REQUEST, "a"), label="lookup transitioned"),
        record(b, "pre without session"),
        call("transition_command_activity", confirmed(b.activity, success=False), label="b to failure"),
        record(e, "prevented"),
        call("transition_command_activity", confirmed(e.activity), label="prevented to success"),
        record(attempted, "attempted"),
        call(
            "transition_command_activity",
            replace(attempted.activity, execution_status=CommandExecutionStatus.PREVENTED),
            label="attempted to prevented",
        ),
        call("is_exact_command_activity_pre_replay", a, label="pre replay after transition"),
    ]


def _health() -> list[dict]:
    a = evidence_a()
    far = 9_223_372_036_854_775_806
    return [
        failure("storage_failed", "command"),
        failure("shadow_evaluation_failed", "shadow"),
        failure("maintenance_failed", "maintenance"),
        call("record_command_activity_observation_conflict", occurred_at=at(2026, 7, 20, 13), label="conflict"),
        raw(
            "update command_activity_health set dropped_event_count = ?, persistence_error_count = ? "
            "where singleton = 1",
            far,
            far,
            label="near overflow",
        ),
        failure("storage_failed", "overflow one"),
        failure("storage_failed", "overflow two"),
        call("record_command_activity_observation_conflict", occurred_at=at(2026, 7, 20, 14), label="conflict cap"),
        failure("Bad Code", "invalid code", python_side=True),
        failure("storage_failed", "naive time", occurred_at=datetime(2026, 7, 20, 12), python_side=True),
        failure(
            "storage_failed",
            "non-utc offset",
            occurred_at=datetime(2026, 7, 20, 12, tzinfo=timezone(timedelta(hours=1))),
            python_side=True,
        ),
        call("probe_command_activity_persistence", a, label="probe clears command and shadow"),
        maintain(label="clears maintenance"),
    ]


def _probe() -> list[dict]:
    a, b = evidence_a(), evidence_b()
    return [
        failure("storage_failed", "command"),
        failure("shadow_evaluation_failed", "shadow"),
        call("probe_command_activity_persistence", b, shadow_evaluation_succeeded=False, label="probe no shadow"),
        call("probe_command_activity_persistence", a, shadow=shadow_for(a), label="probe with shadow"),
        record(a, "record"),
        call("probe_command_activity_persistence", a, label="probe duplicate"),
        call(
            "probe_command_activity_persistence", evidence_a("activity:p2", request="a"), label="probe duplicate handle"
        ),
        record(b, "record b"),
    ]


def _maintain_backfill() -> list[dict]:
    legacy = [
        evidence_a("activity:l1", at(2026, 7, 15, 10), request="1", session="2"),
        evidence_b("activity:l2", at(2026, 7, 15, 11), request="3"),
        evidence_c("activity:l3", at(2026, 7, 16, 8)),
        evidence_d("activity:l4", at(2026, 7, 16, 9)),
        evidence_e("activity:l5", at(2026, 7, 17, 10), request="4", session="5"),
    ]
    steps: list[dict] = [call("command_activity_rollups_are_reconciled", label="empty")]
    steps.extend(sql_for(item) for item in legacy)
    steps.append(call("command_activity_rollups_are_reconciled", label="legacy unreconciled"))
    steps.append(record(evidence_b("activity:l2", at(2026, 7, 15, 11), request="3"), label="pending replay"))
    steps.extend(maintain(batch=2) for _ in range(7))
    steps.append(maintain(batch=2, label="idle"))
    steps.append(call("command_activity_rollups_are_reconciled", label="after backfill"))
    steps.append(maintain(retain=0, python_side=True))
    steps.append(maintain(batch=0, python_side=True))
    steps.append(maintain(now=datetime(2026, 7, 20, 12), python_side=True))
    return steps


def _retention() -> list[dict]:
    old_one = evidence_a("activity:old1", at(2024, 3, 1), request="1", session="2")
    old_two = evidence_a("activity:old2", at(2025, 12, 1), request="3", session="4")
    recent = evidence_a("activity:new1", at(2026, 7, 18), request="5", session="6")
    old_b = evidence_b("activity:old3", at(2025, 12, 2), request="7")
    steps = [
        record(old_one, "old one", shadow=shadow_for(old_one), invocation_preview="git push"),
        record(old_two, "old two", shadow=shadow_for(old_two)),
        record(old_b, "old three"),
        record(recent, "recent"),
        call("command_activity_rollups_are_reconciled", label="before"),
    ]
    steps.extend(maintain(batch=1) for _ in range(7))
    steps.extend(
        [
            call("command_activity_rollups_are_reconciled", label="after"),
            record(old_two, "re-record deleted detail"),
            call("get_command_activity_by_request_correlation", handle(REQUEST, "3"), label="lookup deleted"),
            maintain(now=at(2026, 7, 21), batch=5),
            maintain(now=at(2026, 7, 21), batch=5, label="same day idle"),
            call("rebuild_command_activity_rollups", now=at(2026, 7, 21, 13), label="rebuild"),
            call("command_activity_rollups_are_reconciled", label="rebuilt"),
        ]
    )
    return steps


def _rebuild() -> list[dict]:
    items = [evidence_a(), evidence_b(), evidence_c(), evidence_d(), evidence_e()]
    steps = [record(item) for item in items]
    steps.extend(
        [
            call("command_activity_rollups_are_reconciled", label="reconciled"),
            raw("delete from command_activity_daily_rollups where dimension = 'harness'", label="drop cells"),
            call("command_activity_rollups_are_reconciled", label="missing cells"),
            call("rebuild_command_activity_rollups", now=at(2026, 7, 20, 14), label="rebuild one"),
            call("command_activity_rollups_are_reconciled", label="rebuilt one"),
            raw("update command_activity_daily_totals set total = total + 5", label="skew totals"),
            call("command_activity_rollups_are_reconciled", label="skewed"),
            call("rebuild_command_activity_rollups", now=at(2026, 7, 20, 15), label="rebuild two"),
            call("command_activity_rollups_are_reconciled", label="rebuilt two"),
            call("rebuild_command_activity_rollups", now=datetime(2026, 7, 20, 15), label="naive", python_side=True),
        ]
    )
    return steps


def _check_maintenance(steps: list[dict]) -> None:
    results = [step["result"] for step in steps if step["method"] == "maintain_command_activity" and step["result"]]
    assert any(result[1] for result in results), "maintenance never completed"
    assert any(result[3] for result in results), "retention never deleted detail"


SCENARIOS = [
    {"name": "record_basic", "steps": _record_basic()},
    {"name": "record_shadow", "steps": _record_shadow()},
    {"name": "lifecycle", "steps": _lifecycle()},
    {"name": "health", "steps": _health()},
    {"name": "probe", "steps": _probe()},
    {"name": "maintain_backfill", "steps": _maintain_backfill()},
    {"name": "retention", "steps": _retention(), "final_check": _check_maintenance},
    {"name": "rebuild", "steps": _rebuild()},
]
