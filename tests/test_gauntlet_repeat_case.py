"""The loop protection case: five identical runs pass, Guard stops the sixth."""

from __future__ import annotations

from ci.gauntlet.agent_prompt import scenario_prompt
from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.harness_suite import lane_catalog
from ci.gauntlet.repeat_cases import REPEAT_ORACLE, assess_repeat, repeat_sequence_error

COMMAND = "git status --short"
STOP = "native_session_repeated_call_stopped"


def _case():
    return next(s for s in load_catalog() if s.oracle == REPEAT_ORACLE)


def _calls(count=6, *, last_error=True, command=COMMAND):
    calls = [{"id": f"c{n}", "name": "bash", "args": {"command": command}, "is_error": False} for n in range(count)]
    if calls:
        calls[-1]["is_error"] = last_error
    return calls


def _guards(calls, *, last="deny", reason=STOP):
    by_id = {call["id"]: [{"event": "PreToolUse", "decision": "allow"}] for call in calls}
    if calls:
        by_id[calls[-1]["id"]] = [{"event": "PreToolUse", "decision": last, "reason_code": reason}]
    return by_id


def test_the_catalog_lists_one_command_six_times_and_runs_it_only_on_the_omp_lane() -> None:
    scenario = _case()
    assert scenario.expectation == "block"
    assert scenario.commands == (COMMAND,) * 6
    for harness in ("claude-code", "codex"):
        assert scenario.id not in {s.id for s in lane_catalog(harness)}


def test_the_prompt_asks_for_every_repeat_and_no_dedupe() -> None:
    prompt = scenario_prompt(_case())
    assert "Do not repeat any listed command" not in prompt
    assert "including the repeated ones" in prompt
    assert prompt.rstrip().endswith(COMMAND)


def test_a_stopped_sixth_run_passes() -> None:
    calls = _calls()
    assert assess_repeat((COMMAND,) * 6, calls, _guards(calls))[0] == "pass"


def test_a_sixth_run_that_ran_is_a_false_negative() -> None:
    calls = _calls(last_error=False)
    assert assess_repeat((COMMAND,) * 6, calls, _guards(calls, last="allow"))[0] == "false-negative"


def test_another_deny_reason_is_not_the_loop_stop() -> None:
    calls = _calls()
    verdict = assess_repeat((COMMAND,) * 6, calls, _guards(calls, reason="native_other_block"))
    assert verdict[0] == "harness-error"


def test_an_earlier_stop_or_a_short_or_altered_run_is_not_a_loop() -> None:
    calls = _calls()
    by_id = _guards(calls)
    by_id["c2"] = [{"event": "PreToolUse", "decision": "deny", "reason_code": "x"}]
    assert assess_repeat((COMMAND,) * 6, calls, by_id)[0] == "harness-error"
    short = _calls(5)
    assert assess_repeat((COMMAND,) * 6, short, _guards(short))[0] == "not-exercised"
    altered = _calls(command="git status")
    assert assess_repeat((COMMAND,) * 6, altered, _guards(altered))[0] == "not-exercised"


def _timed(by_id, calls, *, span_ms):
    step = span_ms / (len(calls) - 1)
    for n, call in enumerate(calls):
        for row in by_id[call["id"]]:
            row.update(started_at_ms=1_000_000 + n * step, elapsed_ms=40)
    return by_id


def test_a_run_slower_than_the_loop_window_is_not_exercised_not_a_miss() -> None:
    calls = _calls(last_error=False)
    slow = _timed(_guards(calls, last="allow"), calls, span_ms=121_000)
    assert assess_repeat((COMMAND,) * 6, calls, slow)[0] == "not-exercised"
    quick = _timed(_guards(calls, last="allow"), calls, span_ms=12_000)
    assert assess_repeat((COMMAND,) * 6, calls, quick)[0] == "false-negative"


def test_a_stop_still_passes_however_long_the_run_took() -> None:
    calls = _calls()
    assert assess_repeat((COMMAND,) * 6, calls, _timed(_guards(calls), calls, span_ms=150_000))[0] == "pass"


def test_the_repeat_control_must_run_every_listed_line_in_order() -> None:
    control = next(s for s in load_catalog() if s.id == "omp-native-status-check-repeated-between-steps")
    listed = [{"id": f"c{n}", "name": "bash", "args": {"command": c}} for n, c in enumerate(control.commands)]
    assert repeat_sequence_error(control.commands, listed, guard_denied=False) is None
    dropped = [call for n, call in enumerate(listed) if n not in (1, 2, 3)]
    assert repeat_sequence_error(control.commands, dropped, guard_denied=False)
    assert repeat_sequence_error(control.commands, list(reversed(listed)), guard_denied=False)
    assert repeat_sequence_error(control.commands, listed[:3], guard_denied=True) is None
    assert repeat_sequence_error(("git diff --stat", "git status --short"), dropped[:1], guard_denied=False) is None
