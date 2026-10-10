from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from ci.gauntlet.agent_configuration import write_agent_configuration
from ci.gauntlet.case_helpers import _scenario_tools
from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.evidence import reconcile


def test_eval_lane_uses_the_supported_javascript_session_bridge(tmp_path: Path) -> None:
    write_agent_configuration(
        tmp_path / "agent", SimpleNamespace(base_url="http://127.0.0.1:1234", reasoning_effort=None)
    )
    config = json.loads((tmp_path / "agent" / "config.yml").read_text())
    assert config["eval"] == {"js": True, "py": False}
    assert config["launch"] == {"enabled": False}
    # Print mode exits after the primary turn; wait for actual delegated
    # results instead of abandoning background agents at process shutdown.
    assert config["async"] == {"enabled": False}


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
