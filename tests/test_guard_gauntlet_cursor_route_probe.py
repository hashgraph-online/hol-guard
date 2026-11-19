"""Cursor's route probe is not a Guard decision for the harness judge."""

from ci.gauntlet.harness_judge import assess_harness_case, guard_decisions
from tests.test_guard_gauntlet_harnesses import BASH_CALL, COPY, SCENARIOS, case, deny, row


def test_cursor_route_probe_is_not_a_decision():
    # Cursor sends a shell call to preToolUse and then beforeShellExecution. Guard answers
    # the first as a route probe with no receipt; the second is the reviewed check.
    scenario = SCENARIOS["secret-copy"]
    probe = row("PreToolUse", {"policy_action": "allow"}, decision=None, harness="cursor", command=COPY)
    probe["payload"]["cursor_route_probe"] = True
    stop = row(
        "PreToolUse",
        deny("native_secret_exfiltration"),
        decision="deny",
        reason="native_secret_exfiltration",
        harness="cursor",
        command=COPY,
    )
    cursor_case = case(scenario.id, [probe, stop], [BASH_CALL], harness="cursor")
    assert [d["receipt_decision"] for d in guard_decisions([probe, stop])] == ["deny"]
    assert assess_harness_case(scenario, cursor_case)["outcome"] == "pass"


def test_unmarked_or_foreign_probe_rows_still_need_a_receipt():
    scenario = SCENARIOS["secret-copy"]
    stop = row(
        "PreToolUse",
        deny("native_secret_exfiltration"),
        decision="deny",
        reason="native_secret_exfiltration",
        harness="cursor",
        command=COPY,
    )
    unmarked = row("PreToolUse", {"policy_action": "allow"}, decision=None, harness="cursor", command=COPY)
    result = assess_harness_case(scenario, case(scenario.id, [unmarked, stop], [BASH_CALL], harness="cursor"))
    assert result["reason"] == "a hook decision lacks a validated native receipt"
    foreign = row("PreToolUse", {"policy_action": "allow"}, decision=None, harness="codex", command=COPY)
    foreign["payload"]["cursor_route_probe"] = True
    result = assess_harness_case(scenario, case(scenario.id, [foreign, stop], [BASH_CALL], harness="cursor"))
    assert result["outcome"] == "harness-error"
