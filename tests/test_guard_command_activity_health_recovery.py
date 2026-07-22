"""Recovery semantics for current command-activity persistence health."""

# pyright: reportAny=false, reportIndexIssue=false, reportPrivateUsage=false, reportUnusedCallResult=false

from __future__ import annotations

from datetime import date, datetime, timezone
from pathlib import Path
from typing import cast

from codex_plugin_scanner.guard.runtime.command_activity_api_contract import CommandActivityAnalyticsQuery
from codex_plugin_scanner.guard.runtime.command_activity_contract import (
    ActivityApprovalReuseStatus,
    ActivityDecisionReason,
)
from codex_plugin_scanner.guard.runtime.command_activity_lifecycle import (
    CommandActivityDecisionFacts,
    build_pre_hook_evidence,
)
from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_shadow_evaluation import (
    CommandShadowCohort,
    CommandShadowControl,
    CommandShadowProposal,
    build_command_shadow_observation,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_command_activity_api_support import evidence, seed

_NOW = datetime(2026, 7, 18, 20, 4, tzinfo=timezone.utc)


def _health(store: GuardStore) -> dict[str, object]:
    payload = store.command_activity_analytics(
        CommandActivityAnalyticsQuery(days=7),
        as_of=date(2026, 7, 18),
    )
    return cast(dict[str, object], payload["health"])


def _shadow_evidence(activity_id: str):
    evaluation = evaluate_command("git push origin release/2.1 --force")
    activity_evidence = build_pre_hook_evidence(
        evaluation,
        CommandActivityDecisionFacts(
            policy_action="allow",
            decision_reason_code=ActivityDecisionReason.EXTENSION_MATCH,
            prompted=False,
            approval_reuse_status=ActivityApprovalReuseStatus.NOT_APPLICABLE,
            receipt_id=None,
        ),
        activity_id=activity_id,
        occurred_at=_NOW,
        harness="codex",
        request_correlation=None,
    )
    cohorts = frozenset({CommandShadowCohort.BASELINE})
    shadow = build_command_shadow_observation(
        evaluation,
        authoritative_action="allow",
        proposal=CommandShadowProposal(evaluation.decision_plane, cohorts, "proposal.recovery.v1"),
        activity_id=activity_id,
        occurred_at=_NOW,
        control=CommandShadowControl(True, False, cohorts, frozenset(), 10_000),
    )
    assert shadow is not None
    return activity_evidence, shadow


def test_command_health_recovers_by_write_order_without_resetting_counters(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    seed(store)
    store.record_command_activity(evidence("activity:future-event", minute=10))
    store.record_command_activity_persistence_failure(error_code="post_record_failed", occurred_at=_NOW)
    assert _health(store)["status"] == "degraded"

    store.record_command_activity(evidence("activity:delayed-event", minute=3))
    recovered = _health(store)
    assert recovered["status"] == "healthy"
    assert recovered["dropped_events"] == recovered["persistence_errors"] == 1
    assert recovered["last_error_class"] == "post_record_failed"


def test_interleaved_failure_domains_recover_independently(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    store.record_command_activity_persistence_failure(error_code="maintenance_failed", occurred_at=_NOW)
    store.record_command_activity_persistence_failure(error_code="post_record_failed", occurred_at=_NOW)
    store.record_command_activity(evidence("activity:command-recovered", minute=5))
    assert _health(store)["status"] == "degraded"

    store.maintain_command_activity(now=_NOW, detail_retain_days=30)
    recovered = _health(store)
    assert recovered["status"] == "healthy"
    assert recovered["dropped_events"] == recovered["persistence_errors"] == 2


def test_command_write_does_not_mask_maintenance_failure(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    store.record_command_activity_persistence_failure(error_code="maintenance_failed", occurred_at=_NOW)
    store.record_command_activity(evidence("activity:command-success", minute=5))
    assert _health(store)["status"] == "degraded"


def test_shadow_failure_requires_successful_shadow_persistence_to_recover(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    store.record_command_activity_persistence_failure(error_code="shadow_evaluation_failed", occurred_at=_NOW)
    activity_evidence, _shadow = _shadow_evidence("activity:shadow-not-run")
    store.record_command_activity(activity_evidence)
    assert _health(store)["status"] == "degraded"

    recovered_evidence, recovered_shadow = _shadow_evidence("activity:shadow-recovered")
    store.record_command_activity(recovered_evidence, shadow=recovered_shadow)
    assert _health(store)["status"] == "healthy"


def test_successful_disabled_shadow_evaluation_recovers_shadow_health(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    store.record_command_activity_persistence_failure(error_code="shadow_evaluation_failed", occurred_at=_NOW)
    activity_evidence, _shadow = _shadow_evidence("activity:shadow-disabled")

    store.record_command_activity(activity_evidence, shadow_evaluation_succeeded=True)

    assert _health(store)["status"] == "healthy"
