"""Consent lifecycle hooks for the existing isolated OMP session runner.

No operator home, credentials or live approval endpoint is used here. The
runner supplies its newly created fixture and that fixture's daemon worker.
The ordinary core catalog never activates these hooks.
"""

from __future__ import annotations

from typing import Any

from .approval_retry import ReviewApprover, pinned_retry_outcome, retry_assessment, write_review_config
from .approval_retry_bash import BASH_LIFECYCLE_ORACLE, stage
from .approval_retry_bash import assessment as bash_assessment
from .approval_retry_bash import evidence as bash_evidence
from .approval_rows import approval_rows
from .catalog import Scenario
from .input_evidence import redact_value


def enabled(scenario: Scenario) -> bool:
    return scenario.profiles == ("approval-retry",) and scenario.oracle in {
        "approved-retry",
        BASH_LIFECYCLE_ORACLE,
    }


class OmpReview:
    """One case's fixture-only policy and existing authenticated grant path."""

    def __init__(self, scenario: Scenario, fixture: Any, case: dict[str, Any]) -> None:
        if not enabled(scenario):
            raise ValueError("consent hooks require an approval-retry catalog scenario")
        self.scenario = scenario
        self.fixture = fixture
        self.guard_home = fixture.root / "guard-home"
        self.known_ids: set[str] = set()
        stage(fixture.workspace, scenario.id)
        case["review_policy"] = write_review_config(self.guard_home)

    def approver(self, worker: Any) -> ReviewApprover:
        self.known_ids = {
            str(row["request_id"])
            for row in worker.store.list_approval_requests(status=None, limit=200)
            if isinstance(row, dict) and row.get("request_id")
        }
        return ReviewApprover(
            worker.store,
            known_ids=self.known_ids,
            workspace=self.fixture.workspace,
            scenario_id=self.scenario.id,
            guard_home=self.guard_home,
            worker=worker,
            initial_result_log=self.fixture.root / "private-evidence" / "omp.jsonl",
        )

    def collect(
        self,
        case: dict[str, Any],
        worker: Any,
        approver: ReviewApprover,
        replacements: dict[str, str],
    ) -> None:
        case["approval_grants"] = redact_value(approver.report(), replacements)
        case["approval_rows"] = approval_rows(worker.store, self.known_ids)
        if self.scenario.oracle == BASH_LIFECYCLE_ORACLE:
            case["bash_lifecycle"] = bash_evidence(
                self.fixture.home, self.fixture.workspace, self.scenario.id, worker.store
            )


def assess(
    scenario: Scenario,
    case: dict[str, Any],
    calls: list[dict[str, Any]],
    bound: dict[str, dict[str, Any]],
) -> tuple[str, str]:
    """Called only after the core runner's host, relay and native-inventory proofs."""
    if not enabled(scenario):
        return "harness-error", "consent oracle used outside its dedicated catalog profile"
    by_id = {call["id"]: call for call in calls}
    decisions = []
    for row in case["guard_observations"]:
        if row["event"] != "PreToolUse":
            continue
        decision = {
            "event": row["event"],
            "tool": row["tool"],
            "command": row["input"].get("command"),
            "decision": row["decision"],
            "reason_code": row["reason_code"],
            "tool_call_id": row["tool_call_id"],
        }
        if row["reason_code"] == "native_bash_owner_required":
            call = by_id.get(row["tool_call_id"])
            if row["tool_call_id"] not in bound or call is None:
                return "not-exercised", "native Bash owner delivery was not bound to actual execution"
            # The admission hook requires an owner even on an authorized retry.
            # Judge that owner's real result, retaining the outer hook reason.
            decision["decision"] = "allow" if call["is_error"] is False else "deny"
            result = call.get("result")
            content = result.get("content") if isinstance(result, dict) else None
            lines = (
                {
                    line
                    for part in content
                    if isinstance(part, dict) and part.get("type") == "text"
                    for line in str(part.get("text", "")).splitlines()
                }
                if isinstance(content, list)
                else set()
            )
            codes = lines & {"native_bash_consent_required", "native_policy_block", "native_bash_operation_active"}
            if call["is_error"] is True and len(codes) == 1:
                decision["execution_reason_code"] = codes.pop()
        decisions.append(decision)
    if scenario.oracle == BASH_LIFECYCLE_ORACLE:
        return bash_assessment(scenario.id, case, decisions)
    outcome = retry_assessment(case, decisions)
    if outcome[0] == "pass" and (pinned := pinned_retry_outcome(scenario.commands, decisions)):
        return pinned
    return outcome
