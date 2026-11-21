"""Installed-lane replay of Claude Code's permission dialog and of flagged prompts.

Split from ``test_gauntlet_installed_lane.py``; the stub harness and lane runner live there.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from ci.gauntlet import installed_lane
from ci.gauntlet.installed_registration import load_contract
from ci.gauntlet.installed_replay import replay_case
from ci.gauntlet.installed_runtime import InstalledRuntimeError
from tests.test_gauntlet_installed_lane import _counter, _run, _stub

__all__ = ["_counter"]


def test_claude_codes_prompt_and_permission_hooks_are_replayed(tmp_path: Path) -> None:
    """Claude Code registers UserPromptSubmit and PermissionRequest, so both are replayed, not skipped."""

    runtime = _stub(tmp_path / "hol-guard", register=True, verdicts=["allow", "allow"])
    evidence = _run(tmp_path, runtime)
    replay = evidence["harnesses"]["claude-code"]["replay"]
    replayed = {case["id"]: case for case in replay["cases"]}
    assert replayed["flagged-prompt-asks-for-private-key"]["failures"] == []
    assert replayed["permission-dialog-for-key-exfiltration-stays-claudes"]["failures"] == []
    assert replayed["permission-dialog-for-key-exfiltration-stays-claudes"]["runs"][0]["decision"] == "defer"
    assert all("prompt" not in failure and "permission dialog" not in failure for failure in evidence["failures"])


def test_a_permission_answer_reads_its_behaviour_and_a_bare_event_defers() -> None:
    """A dict ``decision.behavior`` used to fall through to a quiet allow, even a deny."""

    from ci.gauntlet.installed_replay import _decision_from

    def answer(decision: object | None) -> dict:
        output: dict = {"hookEventName": "PermissionRequest"}
        if decision is not None:
            output["decision"] = decision
        return {"hookSpecificOutput": output}

    assert _decision_from(answer({"behavior": "deny", "message": "no"}))[0] == "deny"
    assert _decision_from(answer({"behavior": "allow"}))[0] == "allow"
    assert _decision_from(answer(None))[0] == "defer"
    assert _decision_from(answer({"behavior": 3}))[0] == "unknown"


def test_a_permission_dialog_settled_by_the_hook_fails_a_defer_case(tmp_path: Path) -> None:
    case = {"id": "defer", "event": "PermissionRequest", "expect": "defer", "payload": {}}
    hook = tmp_path / "hook.py"
    hook.write_text(
        "import json\nprint(json.dumps({'hookSpecificOutput': {'hookEventName': 'PermissionRequest', "
        "'decision': {'behavior': 'allow'}}}))\n",
        encoding="utf-8",
    )
    result = replay_case(
        [sys.executable, str(hook)], case, home=tmp_path, guard_home=tmp_path, workspace=tmp_path, repeat=1
    )
    assert any("permission dialog was not left to the harness" in failure for failure in result["failures"])


def test_a_flagged_prompt_sent_silently_fails_a_notice_case(tmp_path: Path) -> None:
    case = {"id": "notice", "event": "UserPromptSubmit", "expect": "notice", "payload": {}}
    hook = tmp_path / "hook.py"
    hook.write_text(
        "import json\nprint(json.dumps({'hookSpecificOutput': {'hookEventName': 'UserPromptSubmit'}}))\n",
        encoding="utf-8",
    )
    result = replay_case(
        [sys.executable, str(hook)], case, home=tmp_path, guard_home=tmp_path, workspace=tmp_path, repeat=1
    )
    assert any("not let through with a notice" in failure for failure in result["failures"])


def test_a_case_with_an_unknown_expectation_refuses_to_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    contract = load_contract()
    contract["replay_cases"].append({"id": "maybe", "expect": "maybe", "payload": {}})
    monkeypatch.setattr(installed_lane, "load_contract", lambda: contract)
    runtime = _stub(tmp_path / "hol-guard", register=True, verdicts=["allow"])
    with pytest.raises(InstalledRuntimeError, match="maybe expect an outcome"):
        _run(tmp_path, runtime)


def test_a_case_no_harness_replays_refuses_to_run() -> None:
    """A case every harness skips is coverage the lane does not have."""

    from ci.gauntlet.installed_lane import undeclared_case_events

    assert undeclared_case_events(load_contract()) == []
    assert undeclared_case_events(
        {
            "harnesses": {"zcode": {"replay": True, "replay_events": ["UserPromptSubmit"]}},
            "replay_cases": [{"id": "stop", "event": "Stop"}],
        }
    ) == ["Stop"]


def test_the_contract_declares_the_prompt_hook_for_the_harnesses_that_have_one() -> None:
    """zcode, Codex and Claude Code register UserPromptSubmit.

    Ordinary prompts go through quietly. A prompt asking for credentials goes through with a
    notice: Guard screens prompts and stops the tool call that would read the secret.
    """

    contract = load_contract()
    for harness in ("zcode", "codex", "claude-code"):
        assert "UserPromptSubmit" in contract["harnesses"][harness]["replay_events"], harness
    prompt_cases = [case for case in contract["replay_cases"] if case.get("event") == "UserPromptSubmit"]
    assert {case["expect"] for case in prompt_cases} == {"allow", "notice"}


def test_every_contract_case_is_replayed_by_some_harness() -> None:
    from ci.gauntlet.installed_lane import unreplayed_cases

    assert unreplayed_cases(load_contract()) == []


def test_a_case_limited_to_harnesses_that_never_replay_it_is_refused() -> None:
    from ci.gauntlet.installed_lane import unreplayed_cases

    contract = load_contract()
    contract["replay_cases"] = [
        {"id": "omp-only", "expect": "allow", "harnesses": ["omp"], "payload": {}},
        {
            "id": "prompt-on-claude-tool-only",
            "event": "Stop",
            "expect": "allow",
            "harnesses": ["claude-code"],
            "payload": {},
        },
        {"id": "everywhere", "expect": "allow", "payload": {}},
    ]
    assert unreplayed_cases(contract) == ["omp-only", "prompt-on-claude-tool-only"]


def test_claude_code_replays_every_tool_family_it_claims() -> None:
    """An allow and a block for each tool family, and the dialog and prompt outcomes Guard gives.

    An MCP tool nobody has reviewed is reviewed on first use under the default policy, so its
    read is not a quiet allow; a permission dialog with no Guard review pending stays Claude's.
    """

    contract = load_contract()
    claude = [case for case in contract["replay_cases"] if "claude-code" in case.get("harnesses", ["claude-code"])]
    by_tool: dict[str, set[str]] = {}
    for case in claude:
        payload = case["payload"]
        key = payload.get("tool_name") or payload["hook_event_name"]
        if case.get("event") == "PermissionRequest":
            key = "PermissionRequest"
        by_tool.setdefault(key.split("__")[0], set()).add(case["expect"])
    for family in ("Bash", "Read", "Grep", "Write", "Edit", "MultiEdit"):
        assert by_tool.get(family) == {"allow", "not-allow"}, family
    assert by_tool["mcp"] == {"not-allow"}
    assert by_tool["PermissionRequest"] == {"defer"}
    assert by_tool["UserPromptSubmit"] == {"allow", "notice"}
    assert by_tool["WebFetch"] == {"allow"} and by_tool["WebSearch"] == {"allow"}


def test_the_flagged_prompt_case_runs_on_every_harness_that_claims_prompt_screening() -> None:
    """A harness whose generated claim says it screens prompts must show the notice it promises."""

    contract = load_contract()
    claims_path = Path(__file__).resolve().parents[1] / "docs/guard/generated/harness-claims.v1.json"
    claims = json.loads(claims_path.read_text())
    # omp's guard is an in-process extension with no registered command to replay; every
    # other harness the lane replays must honour its claim.
    replayed = {name for name, harness in contract["harnesses"].items() if harness.get("replay")}
    screening = {
        claim["harness"]
        for claim in claims["claims"]
        if claim["event"] == "UserPromptSubmit" and claim["mode"] == "screening" and claim["harness"] in replayed
    }
    assert screening
    for harness in screening:
        assert "UserPromptSubmit" in contract["harnesses"][harness].get("replay_events", []), harness
    flagged = [case for case in contract["replay_cases"] if case["expect"] == "notice"]
    assert flagged and all(set(case["harnesses"]) == screening for case in flagged)


def test_a_permission_hook_that_names_its_event_then_fails_is_no_defer(tmp_path: Path) -> None:
    """The harness reads the failing exit before the event-only answer, so the dialog was not left to it."""

    case = {"id": "defer", "event": "PermissionRequest", "expect": "defer", "payload": {}}
    hook = tmp_path / "hook.py"
    hook.write_text(
        "import json, sys\nprint(json.dumps({'hookSpecificOutput': {'hookEventName': 'PermissionRequest'}}))\n"
        "sys.exit(1)\n",
        encoding="utf-8",
    )
    result = replay_case(
        [sys.executable, str(hook)], case, home=tmp_path, guard_home=tmp_path, workspace=tmp_path, repeat=1
    )
    assert result["runs"][0]["decision"] == "unknown"
    assert any("permission dialog was not left to the harness" in failure for failure in result["failures"])


def test_a_permission_hook_that_stops_and_fails_is_no_defer(tmp_path: Path) -> None:
    """A failing exit is no defer even when the answer also carries ``continue: false``."""

    case = {"id": "defer", "event": "PermissionRequest", "expect": "defer", "payload": {}}
    hook = tmp_path / "hook.py"
    hook.write_text(
        "import json, sys\nprint(json.dumps({'continue': False, "
        "'hookSpecificOutput': {'hookEventName': 'PermissionRequest'}}))\nsys.exit(2)\n",
        encoding="utf-8",
    )
    result = replay_case(
        [sys.executable, str(hook)], case, home=tmp_path, guard_home=tmp_path, workspace=tmp_path, repeat=1
    )
    assert result["runs"][0]["decision"] == "unknown"
    assert any("permission dialog was not left to the harness" in failure for failure in result["failures"])
