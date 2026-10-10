"""Read and privacy scenarios replayed through the original Python store."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

from codex_plugin_scanner.guard.runtime.command_activity_api_contract import (
    CommandActivityAnalyticsQuery,
    CommandActivityFeedbackLabel,
    CommandActivityListQuery,
)

UTC = timezone.utc
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
SCHEMA = "guard.command-activity.v1"


def _activity(
    activity_id: str,
    occurred_at: str,
    harness: str,
    status: str,
    proof: str,
    *,
    prompted: int = 0,
    reuse: str = "not-applicable",
    action: str | None = "allow",
    rule: str | None = None,
    receipt: str | None = None,
) -> tuple[str, tuple[object, ...]]:
    return (
        ACTIVITY_INSERT,
        (
            activity_id,
            occurred_at,
            harness,
            "pre",
            status,
            proof,
            action,
            "no_match" if rule is None else "extension_match",
            rule,
            "exact",
            None,
            0 if rule is None else 1,
            prompted,
            reuse,
            "linked" if receipt else "not_applicable",
            receipt,
            "le_5_ms",
            "le_2_ms",
            SCHEMA,
        ),
    )


ACTIVITIES = [
    ("act:01", "2026-07-10T08:00:00+00:00", "codex", "confirmed_success", "post_hook", {}),
    (
        "act:02",
        "2026-07-12T09:30:00+00:00",
        "codex",
        "prevented",
        "pre_hook",
        {"prompted": 1, "reuse": "rejected", "action": "block", "rule": "command.git.push", "receipt": "r:2"},
    ),
    ("act:03", "2026-07-12T09:30:00+00:00", "claude-code", "allowed_unconfirmed", "pre_hook", {}),
    (
        "act:04",
        "2026-07-12T09:30:00+00:00",
        "claude-code",
        "confirmed_failure",
        "post_hook",
        {"prompted": 1, "reuse": "accepted", "action": "review", "rule": "command.safe.read"},
    ),
    ("act:05", "2026-07-15T23:59:59.999999+00:00", "cursor", "attempted", "pre_hook", {"action": "warn"}),
    ("act:06", "2026-07-16T00:00:00+00:00", "cursor", "unpaired_post", "unpaired_post", {"action": None}),
    (
        "act:07",
        "2026-07-18T20:00:00+00:00",
        "codex",
        "prevented",
        "pre_hook",
        {"action": "block", "rule": "command.package.install", "receipt": "r:7"},
    ),
    ("act:08", "2026-07-19T08:00:00+00:00", "pi", "allowed_unconfirmed", "pre_hook", {"prompted": 1}),
    ("act:09", "2026-07-20T10:00:00+00:00", "codex", "confirmed_success", "post_hook", {}),
    ("act:10", "9999-12-31T23:59:59.999999+00:00", "codex", "attempted", "pre_hook", {}),
]
MATCHES = [
    ("act:02", 0, "command.git", "command.git.push", "unsafe", "high", "review", None, ["remote_state_mutation"]),
    (
        "act:02",
        1,
        "command.package",
        "command.package.install",
        "unsafe",
        "critical",
        "block",
        None,
        ["network_read", "package_or_source_installation"],
    ),
    ("act:04", 0, "command.safe", "command.safe.read", "safe_variant", "low", "warn", "variant.one", []),
    (
        "act:07",
        0,
        "command.package",
        "command.package.install",
        "unsafe",
        "critical",
        "block",
        None,
        ["package_or_source_installation"],
    ),
]
FEEDBACK = [
    ("act:02", "expected_guard_to_stop_this", "2026-07-12T10:00:00+00:00", "2026-07-12T10:05:00+00:00"),
    ("act:04", "should_not_have_interrupted", "2026-07-12T11:00:00+00:00", "2026-07-12T11:00:00+00:00"),
    ("act:07", "expected_guard_to_stop_this", "2026-07-18T21:00:00+00:00", "2026-07-18T21:00:00+00:00"),
]
INVOCATIONS = [("act:02", "git push origin main"), ("act:07", "npm install left-pad")]
DAY_TOTALS = [
    ("2026-07-10", 1),
    ("2026-07-12", 3),
    ("2026-07-15", 1),
    ("2026-07-16", 1),
    ("2026-07-18", 1),
    ("2026-07-19", 1),
    ("2026-07-20", 1),
]
ROLLUPS = [
    ("2026-07-10", "harness", "codex", 1),
    ("2026-07-12", "harness", "codex", 1),
    ("2026-07-12", "harness", "claude-code", 2),
    ("2026-07-15", "harness", "cursor", 1),
    ("2026-07-16", "harness", "cursor", 1),
    ("2026-07-18", "harness", "codex", 1),
    ("2026-07-19", "harness", "pi", 1),
    ("2026-07-20", "harness", "codex", 1),
    ("2026-07-12", "extension", "command.git", 1),
    ("2026-07-12", "extension", "command.package", 1),
    ("2026-07-18", "extension", "command.package", 1),
    ("2026-07-12", "rule", "command.git.push", 1),
    ("2026-07-18", "rule", "command.package.install", 1),
    ("2026-07-12", "rule", "command.package.install", 1),
    ("2026-07-12", "disposition", "block", 1),
    ("2026-07-18", "disposition", "block", 1),
    ("2026-07-10", "disposition", "allow", 1),
    ("2026-07-12", "execution_status", "prevented", 1),
    ("2026-07-18", "execution_status", "prevented", 1),
    ("2026-07-10", "execution_status", "confirmed_success", 1),
    ("2026-07-12", "prompt_status", "prompted", 2),
    ("2026-07-10", "prompt_status", "not_prompted", 1),
    ("2026-07-10", "proof_level", "post_hook", 1),
    ("2026-07-12", "proof_level", "pre_hook", 2),
    ("2026-07-12", "latency", "le_5_ms", 3),
]
SHADOWS = [
    ("act:02", "2026-07-12T09:30:00+00:00", ["baseline", "cdx-064-remote-mutation-floors"]),
    ("act:07", "2026-07-18T20:00:00+00:00", ["cdx-065-package-provenance-floors"]),
    ("act:01", "2026-07-10T08:00:00+00:00", ["baseline"]),
]


def seed_statements() -> list[tuple[str, tuple[object, ...]]]:
    statements: list[tuple[str, tuple[object, ...]]] = []
    for activity_id, occurred_at, harness, status, proof, options in ACTIVITIES:
        statements.append(_activity(activity_id, occurred_at, harness, status, proof, **options))
    for activity_id, ordinal, extension, rule, klass, severity, floor, variant, effects in MATCHES:
        statements.append(
            (
                MATCH_INSERT,
                (activity_id, ordinal, extension, "2.2.0", rule, "1.0.0", klass, severity, floor, variant, SCHEMA),
            )
        )
        statements.extend((EFFECT_INSERT, (activity_id, ordinal, effect)) for effect in effects)
    statements.extend(
        ("insert into command_activity_feedback values (?, ?, ?, ?, 'guard.command-activity-api.v1')", row)
        for row in FEEDBACK
    )
    statements.extend(("insert into command_activity_invocation values (?, ?)", row) for row in INVOCATIONS)
    statements.extend(("insert into command_activity_daily_totals values (?, ?)", row) for row in DAY_TOTALS)
    statements.extend(("insert into command_activity_daily_rollups values (?, ?, ?, ?)", row) for row in ROLLUPS)
    for activity_id, occurred_at, cohorts in SHADOWS:
        statements.append(
            (
                "insert into command_activity_shadow_evaluations values "
                "(?, ?, 'allow', 'allow', 'silent-verified', 'review', 'review', 'strengthened', "
                "'proposal.multi.v1', '1.0.0', 1, 10000, 'guard.command-shadow.v1')",
                (activity_id, occurred_at),
            )
        )
        statements.extend(
            ("insert into command_activity_shadow_cohorts values (?, ?, ?)", (activity_id, index, cohort))
            for index, cohort in enumerate(cohorts)
        )
    statements.append(
        (
            "update command_activity_maintenance set last_completed_day = '2026-07-19', last_run_at = "
            "'2026-07-19T01:00:00+00:00', rollup_backfill_complete = 1, last_backfilled_rows = 4, "
            "last_detail_rows_deleted = 2 where singleton = 1",
            (),
        )
    )
    return statements


def call(method: str, *args: object, label: str = "", python_side: bool = False, **kwargs: object) -> dict:
    return {"method": method, "args": args, "kwargs": kwargs, "label": label, "python_side": python_side}


def sql(*statements: tuple[str, tuple[object, ...]], label: str = "") -> dict:
    return {"sql": list(statements), "label": label}


def page(label: str, cursor: tuple[str, str] | None = None, **query: object) -> dict:
    return call("list_command_activity_page", CommandActivityListQuery(**query), cursor=cursor, label=label)


def analytics(label: str, as_of: date = date(2026, 7, 20), **query: object) -> dict:
    return call("command_activity_analytics", CommandActivityAnalyticsQuery(**query), as_of=as_of, label=label)


SHOULD_NOT = CommandActivityFeedbackLabel.SHOULD_NOT_HAVE_INTERRUPTED
EXPECTED = CommandActivityFeedbackLabel.EXPECTED_GUARD_TO_STOP_THIS


def _feedback(label: str, activity_id: str, kind: CommandActivityFeedbackLabel, at: datetime, **flags: object) -> dict:
    return {
        "method": "record_command_activity_feedback",
        "args": (),
        "kwargs": {"activity_id": activity_id, "label": kind, "recorded_at": at},
        "label": label,
        "python_side": bool(flags.get("python_side")),
    }


def _invalidations(label: str, cursor: int, **kwargs: object) -> dict:
    return call("list_command_activity_invalidations", cursor, label=label, **kwargs)


def _shadow(label: str, **kwargs: object) -> dict:
    return call("list_command_shadow_observations", label=label, **kwargs)


def _shadow_count(label: str) -> dict:
    return call("count_command_shadow_observations", label=label)


def _diagnostics(label: str) -> dict:
    return call("command_activity_diagnostics", label=label)


READ_STEPS = [
    page("default page"),
    page("small page", limit=3),
    page("second page", cursor=("2026-07-12T09:30:00+00:00", "act:03"), limit=3),
    page("cursor mid tie", cursor=("2026-07-12T09:30:00+00:00", "act:04"), limit=50),
    page("harness codex", harness="codex"),
    page("status prevented", execution_status="prevented"),
    page("proof post", proof_level="post_hook"),
    page("prompted true", prompted=True),
    page("prompted false", prompted=False),
    page("reuse rejected", approval_reuse_status="rejected"),
    page("extension filter", extension_id="command.package"),
    page("rule filter", rule_id="command.safe.read"),
    page("from date", occurred_from=date(2026, 7, 15)),
    page("through date", occurred_through=date(2026, 7, 12)),
    page("through max", occurred_through=date.max),
    page("window", occurred_from=date(2026, 7, 12), occurred_through=date(2026, 7, 16)),
    page("combined", harness="codex", prompted=True, execution_status="prevented", rule_id="command.git.push"),
    page("no matches", harness="devin"),
    analytics("analytics default"),
    analytics("analytics 7 days", days=7),
    analytics("analytics top 2", top_limit=2),
    analytics("analytics harness scope", dimension="harness", dimension_value="codex"),
    analytics("analytics extension scope", dimension="extension", dimension_value="command.package"),
    analytics("analytics rule scope", dimension="rule", dimension_value="command.git.push"),
    analytics("analytics later window", as_of=date(2026, 8, 30), days=60),
    analytics("analytics empty window", as_of=date(2025, 1, 1), days=5),
    _invalidations("invalidations from zero", 0),
    _invalidations("invalidations limit", 0, limit=4),
    _invalidations("invalidations mid", 12),
    _invalidations("invalidations at max", 21),
    _invalidations("invalidations beyond max", 400),
    _invalidations("invalidations bad cursor", -1),
    _invalidations("invalidations bad limit", 0, limit=101),
    _diagnostics("diagnostics seeded"),
    _shadow("shadow all"),
    _shadow_count("shadow count seeded"),
    _shadow("shadow limit one", limit=1),
    _shadow("shadow bad limit", limit=0),
]
for step in READ_STEPS[-1:]:
    step["python_side"] = True
for step in READ_STEPS:
    if step["method"] == "list_command_activity_invalidations" and (
        step["args"][0] < 0 or step["kwargs"].get("limit", 1) > 100
    ):
        step["python_side"] = True

T0 = datetime(2026, 7, 21, 9, 0, 0, tzinfo=UTC)
FEEDBACK_STEPS = [
    _feedback("new label", "act:03", SHOULD_NOT, T0),
    _feedback("same label is a no-op", "act:03", SHOULD_NOT, T0 + timedelta(minutes=5)),
    _feedback("changed label keeps created_at", "act:03", EXPECTED, T0 + timedelta(minutes=10)),
    _feedback("existing seeded label replaced", "act:02", SHOULD_NOT, T0 + timedelta(minutes=15)),
    _feedback("unknown activity", "act:missing", SHOULD_NOT, T0),
    _feedback("empty activity id", "", SHOULD_NOT, T0, python_side=True),
    _feedback("naive timestamp", "act:03", SHOULD_NOT, datetime(2026, 7, 21, 9, 0, 0), python_side=True),
    _feedback(
        "offset timestamp",
        "act:03",
        SHOULD_NOT,
        datetime(2026, 7, 21, 9, 0, 0, tzinfo=timezone(timedelta(hours=2))),
        python_side=True,
    ),
    page("page shows labels", limit=4),
    _invalidations("invalidations after feedback", 13),
]
CLEAR_STEPS = [
    _diagnostics("diagnostics before clear"),
    call("clear_command_activity_evidence", label="clear"),
    _diagnostics("diagnostics after clear"),
    page("page after clear"),
    analytics("analytics after clear"),
    _invalidations("invalidations after clear", 0),
    _invalidations("stale cursor after clear", 15),
    _shadow("shadow after clear"),
    _shadow_count("shadow count after clear"),
    call("clear_command_activity_evidence", label="clear twice"),
]
HEALTH_STEPS = [
    analytics("healthy analytics"),
    sql(
        (
            "update command_activity_health set dropped_event_count = 3, persistence_error_count = 5, "
            "last_error_code = 'pre_record_failed', last_error_at = '2026-07-20T11:00:00+00:00' where singleton = 1",
            (),
        ),
        ("update command_activity_health_active set command_error_active = 1 where singleton = 1", ()),
        label="active command error",
    ),
    analytics("degraded analytics"),
    _diagnostics("diagnostics allowed error class"),
    sql(
        ("update command_activity_health set last_error_code = 'free_form_secret_code' where singleton = 1", ()),
        label="unlisted error code",
    ),
    _diagnostics("diagnostics unlisted error class"),
    sql(
        (
            "update command_activity_health set last_error_code = 'maintenance_failed', persistence_error_count = 0 "
            "where singleton = 1",
            (),
        ),
        (
            "update command_activity_health_active set command_error_active = 0, maintenance_error_active = 1 "
            "where singleton = 1",
            (),
        ),
        label="zero persistence errors",
    ),
    _diagnostics("diagnostics zero errors"),
    analytics("maintenance degraded analytics"),
    sql(("delete from command_activity_health_active", ()), label="active row missing"),
    analytics("missing active row"),
    sql(("delete from command_activity_health", ()), label="health row missing"),
    analytics("missing health row"),
    _diagnostics("diagnostics missing health"),
    _invalidations("invalidations cursor 0 on seeded", 0),
]

SCENARIOS = [
    {"name": "seeded_reads", "seed": True, "steps": READ_STEPS},
    {"name": "feedback_flow", "seed": True, "steps": FEEDBACK_STEPS},
    {"name": "clear_flow", "seed": True, "steps": CLEAR_STEPS},
    {"name": "health_states", "seed": True, "steps": HEALTH_STEPS},
    {
        "name": "empty_store",
        "seed": False,
        "steps": [
            page("empty page"),
            analytics("empty analytics"),
            _invalidations("empty invalidations", 0),
            _invalidations("empty invalidations stale cursor", 5),
            _diagnostics("empty diagnostics"),
            _shadow("empty shadow"),
            _feedback("empty feedback target", "act:01", SHOULD_NOT, T0),
            call("clear_command_activity_evidence", label="clear empty"),
        ],
    },
]
