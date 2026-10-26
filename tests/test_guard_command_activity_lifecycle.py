from __future__ import annotations

from datetime import datetime, timezone

from codex_plugin_scanner.guard.runtime.command_activity_contract import (
    CommandExecutionStatus,
    CommandHookPhase,
    CommandProofLevel,
    CorrelationHandle,
    CorrelationKind,
)
from codex_plugin_scanner.guard.runtime.command_activity_lifecycle import (
    build_unpaired_post_evidence,
)

NOW = datetime(2026, 7, 18, 20, 0, tzinfo=timezone.utc)


def _correlation(kind: CorrelationKind = CorrelationKind.REQUEST, *, digest: str = "a" * 64) -> CorrelationHandle:
    return CorrelationHandle(kind=kind, harness="codex", key_id="key.v1", digest=digest)


def test_unpaired_post_claims_no_decision_match_receipt_or_request_proof() -> None:
    session = _correlation(CorrelationKind.SESSION)
    evidence = build_unpaired_post_evidence(
        activity_id="activity:unpaired",
        occurred_at=NOW,
        harness="codex",
        succeeded=False,
        session_correlation=session,
    )

    activity = evidence.activity
    assert activity.execution_status is CommandExecutionStatus.UNPAIRED_POST
    assert activity.hook_phase is CommandHookPhase.POST_FAILURE
    assert activity.proof_level is CommandProofLevel.UNPAIRED_POST
    assert activity.policy_action is None
    assert activity.request_correlation is None
    assert activity.session_correlation == session
    assert activity.receipt_id is None
    assert activity.match_count == 0
    assert evidence.matches == ()
