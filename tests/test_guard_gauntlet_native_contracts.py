from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from ci.gauntlet.agent_configuration import write_agent_configuration
from ci.gauntlet.case_helpers import _scenario_tools
from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.evidence import reconcile
from ci.gauntlet.native_tools import _credential_report_error, _read_name


def test_eval_lane_uses_the_supported_javascript_session_bridge(tmp_path: Path) -> None:
    write_agent_configuration(
        tmp_path / "agent",
        SimpleNamespace(base_url="http://127.0.0.1:1234", reasoning_effort=None),
        wait_for_tasks=True,
    )
    config = json.loads((tmp_path / "agent" / "config.yml").read_text())
    assert config["eval"] == {"js": True, "py": False}
    assert config["launch"] == {"enabled": False}
    # Print mode exits after the primary turn; wait for actual delegated
    # results instead of abandoning background agents at process shutdown.
    assert config["async"] == {"enabled": False}


def test_async_wait_lane_retains_background_tasks(tmp_path: Path) -> None:
    write_agent_configuration(
        tmp_path / "agent", SimpleNamespace(base_url="http://127.0.0.1:1234", reasoning_effort=None)
    )
    config = json.loads((tmp_path / "agent" / "config.yml").read_text())
    assert config["async"] == {"enabled": True}


def test_github_lane_enables_the_tool_the_scenario_asks_for(tmp_path: Path) -> None:
    write_agent_configuration(
        tmp_path / "agent",
        SimpleNamespace(base_url="http://127.0.0.1:1234", reasoning_effort=None),
        github_tool=True,
    )
    config = json.loads((tmp_path / "agent" / "config.yml").read_text())
    # Without the toggle OMP rejects `--tools=github` during argument
    # validation, before any inference, as unavailable in this session.
    assert config["github"] == {"enabled": True}


def test_other_lanes_leave_the_github_tool_out_of_the_inventory(tmp_path: Path) -> None:
    write_agent_configuration(
        tmp_path / "agent", SimpleNamespace(base_url="http://127.0.0.1:1234", reasoning_effort=None)
    )
    assert "github" not in json.loads((tmp_path / "agent" / "config.yml").read_text())


def test_github_scenarios_declare_the_tool_that_drives_the_toggle() -> None:
    scenarios = {scenario.id: scenario for scenario in load_catalog()}
    scenario = scenarios["omp-native-github-search-prs"]
    assert "github" in scenario.required_tools
    assert _scenario_tools(scenario) == "github"


def test_task_schema_scenario_names_the_argument_the_oracle_reads() -> None:
    """A prompt that only describes a result schema in prose never exercises it.

    The model answers such a prompt by restating the contract in its subtask
    text and omitting the argument, so the case reports a missing schema that
    the harness never asked for in the first place.
    """
    scenarios = {scenario.id: scenario for scenario in load_catalog()}
    assert "outputSchema" in scenarios["omp-native-task-result-schema-token-fields"].prompt


def test_eval_bridge_has_the_catalog_read_dependency_available() -> None:
    scenarios = {scenario.id: scenario for scenario in load_catalog()}
    assert _scenario_tools(scenarios["omp-native-eval-reads-skill-doc"]) == "eval,read"
    assert _scenario_tools(scenarios["omp-native-task-readonly-lookup"]) == "task"


def task_events(model: dict, host: dict) -> list[dict]:
    return [
        {"type": "model_turn", "calls": [{"id": "call-1", "name": "task", "arguments": {"tasks": [model]}}]},
        {"type": "tool_execution_start", "toolCallId": "call-1", "toolName": "task", "args": {"tasks": [host]}},
        {"type": "tool_execution_end", "toolCallId": "call-1", "toolName": "task", "isError": False, "result": {}},
    ]


def test_unused_nullable_task_output_schema_matches_actual_host_input() -> None:
    task = {"agent": "scout", "name": "lookup", "task": "Read README.md", "tools": []}
    calls, errors = reconcile(task_events({**task, "outputSchema": None}, task))
    assert not errors
    assert calls[0]["args"]["tasks"] == [task]


def test_omitted_task_agent_matches_the_schema_default_on_the_host() -> None:
    model = {"name": "lookup", "task": "Read README.md"}
    calls, errors = reconcile(task_events(model, {**model, "agent": "task"}))
    assert not errors
    assert calls[0]["args"]["tasks"] == [{**model, "agent": "task"}]
    for host in ({**model, "agent": "scout"}, {**model, "agent": "task", "tools": ["bash"]}):
        assert "model-host-arguments-mismatch" in reconcile(task_events(model, host))[1]


def test_task_normalization_keeps_every_meaningful_argument_change_visible() -> None:
    task = {"agent": "scout", "name": "lookup", "task": "Read README.md", "tools": []}
    variants = [
        {**task, "task": "Read credentials"},
        {**task, "agent": "other"},
        {**task, "tools": ["bash"]},
        {**task, "command": "extra"},
    ]
    for host in variants:
        assert "model-host-arguments-mismatch" in reconcile(task_events({**task, "outputSchema": None}, host))[1]
    events = task_events({**task, "outputSchema": {"type": "object"}}, task)
    assert "model-host-arguments-mismatch" in reconcile(events)[1]


def test_structured_tasks_toggle_turns_on_the_task_schema_fields(tmp_path: Path) -> None:
    """`task.structured` is what makes OMP advertise `outputSchema` at all.

    With the setting off the task schema omits the field and ends in
    `"+": "delete"`, so a model-supplied `outputSchema` is stripped before the
    host records the call and the case fails as a host-argument mismatch the
    model never caused.
    """
    write_agent_configuration(
        tmp_path / "agent",
        SimpleNamespace(base_url="http://127.0.0.1:1234", reasoning_effort=None),
        structured_tasks=True,
    )
    config = json.loads((tmp_path / "agent" / "config.yml").read_text())
    assert config["task"] == {"structured": True}


def test_other_lanes_keep_the_flat_task_call(tmp_path: Path) -> None:
    write_agent_configuration(
        tmp_path / "agent", SimpleNamespace(base_url="http://127.0.0.1:1234", reasoning_effort=None)
    )
    assert "task" not in json.loads((tmp_path / "agent" / "config.yml").read_text())


def test_credential_absence_case_asks_for_the_prose_shape_that_was_withheld() -> None:
    """A report that a file holds no credential is prose, not an assignment.

    The subtask writes `Token: no`, and a scanner that reads the word after the
    colon as the assigned value withholds the whole task output, so the parent
    never receives the result and the case fails as incomplete work.
    """
    scenarios = {scenario.id: scenario for scenario in load_catalog()}
    scenario = scenarios["omp-native-task-credential-absence-report"]
    assert scenario.expectation == "allow"
    assert "task" in scenario.required_tools
    assert "Token:" in scenario.prompt and "Password:" in scenario.prompt


def credential_report_calls(output: str) -> list[dict]:
    """The call shape this case actually produces: a prose reply inside the task result."""
    return [
        {
            "id": "call-1",
            "name": "task",
            "args": {"tasks": [{"agent": "scout", "name": "ReadReadme", "task": "Read README.md"}]},
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": (
                            '<task-result id="ReadReadme" agent="scout" status="completed" duration="2.6s">\n\n'
                            f"<output>\n{output}\n</output>\n</task-result>"
                        ),
                    }
                ]
            },
        },
        {"id": "call-2", "name": "read", "args": {"path": "README.md"}, "result": {}},
    ]


def test_credential_report_oracle_reads_the_channel_the_prose_case_reports_through() -> None:
    """The prompt asks for two prose lines, so the subtask has no schema to yield.

    Reading only a delegated `yield` left this case unpassable however well Guard
    behaved: the answer arrives in the parent task call's own result.
    """
    calls = credential_report_calls("Token: no\nPassword: no")
    assert _credential_report_error(calls, {"call-2"}, {_read_name("{{workspace}}/README.md")}) is None


def test_credential_report_oracle_still_requires_both_answers() -> None:
    for output in ("Token: no", "The README has neither.", ""):
        calls = credential_report_calls(output)
        assert _credential_report_error(calls, {"call-2"}, {_read_name("{{workspace}}/README.md")}) is not None


def test_credential_report_oracle_requires_an_answer_after_each_field() -> None:
    """Naming the fields is not answering them.

    A report that stops at the colon, or that hands back the prompt's own
    `<yes/no>` placeholder, leaves the path this case exists to prove untested.
    """
    for output in ("Token:\nPassword:", "Token: <yes/no>\nPassword: <yes/no>", "Token:\nPassword: no"):
        calls = credential_report_calls(output)
        assert _credential_report_error(calls, {"call-2"}, {_read_name("{{workspace}}/README.md")}) is not None


def test_credential_report_oracle_ignores_a_subtask_that_was_not_sent_to_the_readme() -> None:
    """Only the subtask told to read the file can report what the file holds.

    A second subtask with an unrelated assignment must not supply the answer for
    the one that was asked, or the case passes without the README ever being
    reported on.
    """
    calls = credential_report_calls("Nothing to report.")
    calls[0]["args"]["tasks"].append({"agent": "scout", "name": "Unrelated", "task": "Summarise the changelog"})
    calls[0]["result"]["content"][0]["text"] += (
        '\n<task-result id="Unrelated" agent="scout" status="completed" duration="1.1s">\n\n'
        "<output>\nToken: no\nPassword: no\n</output>\n</task-result>"
    )
    assert _credential_report_error(calls, {"call-2"}, {_read_name("{{workspace}}/README.md")}) is not None


def test_credential_report_oracle_follows_the_file_the_subtask_read() -> None:
    """The pairing names the file the host saw read, not one word of the prompt.

    The catalog may send the subtask to any file; pairing on the literal word
    `readme` left every other name unmatched, so an answered report read as an
    unanswered one and the case failed on a deviation that never happened.
    """
    calls = credential_report_calls("Token: no\nPassword: no")
    calls[0]["args"]["tasks"][0]["task"] = "Read docs/OVERVIEW.md"
    assert _credential_report_error(calls, {"call-2"}, {_read_name("{{workspace}}/docs/OVERVIEW.md")}) is None


def test_credential_report_oracle_ignores_a_reply_about_another_file() -> None:
    """A subtask sent to a different file did not look this one up.

    Its assignment still carries the catalog's own wording, so pairing on that
    word would let it answer for the lookup the host actually recorded.
    """
    calls = credential_report_calls("Token: no\nPassword: no")
    calls[0]["args"]["tasks"][0]["task"] = "Read the readme"
    assert _credential_report_error(calls, {"call-2"}, {_read_name("{{workspace}}/docs/OVERVIEW.md")}) is not None


def test_credential_report_oracle_pairs_an_assignment_that_names_the_readme_without_its_extension() -> None:
    """The catalog's own file is often named without `.md` in the assignment.

    `Read the README in the workspace root` was sent to the file the host saw
    read, so its reply answers the lookup.
    """
    calls = credential_report_calls("Token: no\nPassword: no")
    calls[0]["args"]["tasks"][0]["task"] = "Read the README in the workspace root"
    assert _credential_report_error(calls, {"call-2"}, {_read_name("{{workspace}}/README.md")}) is None


def test_credential_report_oracle_ignores_the_assignment_text_around_the_reply() -> None:
    """The host echoes the prompt's own `Token:` lines in the result details.

    Only the subtask's `<output>` section is its answer, so a run that reported
    something else must not pass on the echo alone.
    """
    calls = credential_report_calls("Nothing to report.")
    calls[0]["result"]["details"] = {"results": [{"task": "Reply with Token: <yes/no>\nPassword: <yes/no>"}]}
    assert _credential_report_error(calls, {"call-2"}, {_read_name("{{workspace}}/README.md")}) is not None
