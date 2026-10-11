from __future__ import annotations

import json
from pathlib import Path

import pytest

from ci.gauntlet.case_helpers import read_case_logs
from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.evidence import reconcile
from ci.gauntlet.host_evidence import complete_host_events
from ci.gauntlet.native_tools import native_tools_scope_error


def lifecycle(key: str, name: str, args: dict) -> list[dict]:
    return [
        {
            "type": "message_end",
            "message": {
                "role": "assistant",
                "content": [{"type": "toolCall", "id": key, "name": name, "arguments": args}],
            },
        },
        {"type": "tool_execution_start", "toolCallId": key, "toolName": name, "args": args},
        {"type": "tool_execution_end", "toolCallId": key, "toolName": name, "isError": False, "result": {}},
    ]


def write(path: Path, events: list[dict]) -> None:
    path.write_text("".join(json.dumps(event) + "\n" for event in events))


def test_eval_bridge_requires_complete_hooks_inside_actual_model_eval() -> None:
    from copy import deepcopy

    parent = lifecycle("eval", "eval", {"language": "js", "code": 'await tool.read({path:"README.md"})'})
    start = {
        "type": "eval_bridge_start",
        "parentToolCallId": "eval",
        "parentToolCallIds": ["eval"],
        "event": {
            "type": "tool_call",
            "toolCallId": "js-read-123",
            "toolName": "read",
            "input": {"path": "README.md"},
        },
    }
    end = {
        "type": "eval_bridge_end",
        "parentToolCallId": "eval",
        "parentToolCallIds": ["eval"],
        "event": {
            "type": "tool_result",
            "toolCallId": "js-read-123",
            "toolName": "read",
            "input": {"path": "README.md"},
            "content": [{"type": "text", "text": "inert fixture"}],
            "isError": False,
        },
    }
    from ci.gauntlet.evidence import public_events

    events = public_events([*parent[:2], start, end, *parent[2:]], {})
    calls, errors = reconcile(events)
    assert not errors and len(calls) == 2
    assert calls[1]["bridge_parent_id"] == "eval"
    for broken in [
        events[:-1],
        events[:2] + events[3:],
        [*events[:2], events[2], events[2], *events[3:]],
        [*events, events[-1]],
    ]:
        assert reconcile(broken)[1]
    altered = deepcopy(events)
    altered[3]["event"]["input"]["path"] = ".env"
    assert reconcile(altered)[1]
    ambiguous = deepcopy(events)
    ambiguous[2]["parentToolCallIds"] = ["eval", "other"]
    assert reconcile(ambiguous)[1]


def test_child_calls_keep_model_start_completion_and_parent_agreement(tmp_path: Path) -> None:
    task = lifecycle("parent", "task", {"tasks": [{"agent": "scout", "task": "Read README.md"}]})
    child = lifecycle("child", "read", {"path": "README.md"})
    parent, observer = tmp_path / "parent.jsonl", tmp_path / "observer.jsonl"
    write(parent, [*task, {"type": "agent_end", "isTerminal": True}])
    write(observer, task[:2] + child + task[2:])
    events, delegated = complete_host_events(parent, observer, {})
    calls, errors = reconcile(events)
    assert not errors
    assert {call["id"] for call in calls} == {"parent", "child"}
    assert delegated == ["child"]
    assert events[-1] == {"type": "agent_end", "terminal": True}
    for malformed in [task[:2] + child, task + task[:1], child]:
        write(observer, malformed)
        with pytest.raises(ValueError):
            complete_host_events(parent, observer, {})


def test_delegation_scope_keeps_exact_read_and_result_report(tmp_path: Path) -> None:
    scenario = next(s for s in load_catalog() if s.id == "omp-native-task-readonly-lookup")
    calls = [
        {"id": "parent", "name": "task", "args": {}},
        {"id": "child", "name": "read", "args": {"path": "README.md"}},
    ]
    case = {"delegated_call_ids": ["child"]}
    assert native_tools_scope_error(scenario, calls, case) is None
    for name, args in [
        ("read", {"path": ".env"}),
        ("bash", {"command": "cat README.md"}),
        ("yield", {"data": {"command": "extra"}}),
    ]:
        bad = [calls[0], {"id": "child", "name": name, "args": args}]
        assert native_tools_scope_error(scenario, bad, case)
    assert native_tools_scope_error(scenario, calls, {"delegated_call_ids": ["absent"]})
    assert native_tools_scope_error(scenario, calls, {"delegated_call_ids": ["child", "child"]})


def test_wait_scenario_observes_its_own_delegated_file() -> None:
    scenario = next(s for s in load_catalog() if s.id == "omp-native-wait-on-task")
    calls = [
        {"id": "task", "name": "task", "args": {}},
        {"id": "wait", "name": "wait", "args": {}},
        {"id": "child", "name": "read", "args": {"path": "src/one.ts"}},
    ]
    case = {"delegated_call_ids": ["child"]}
    assert native_tools_scope_error(scenario, calls, case) is None
    calls[-1]["args"]["path"] = "README.md"
    assert native_tools_scope_error(scenario, calls, case)


def test_parent_evidence_survives_lifecycle_failure_for_cleanup(tmp_path: Path) -> None:
    parent, observer = tmp_path / "parent.jsonl", tmp_path / "observer.jsonl"
    events = lifecycle("call", "bash", {"command": "mktemp -d"})
    write(parent, events)
    write(observer, [])
    case = {"events": []}
    with pytest.raises(ValueError):
        read_case_logs(case, parent, tmp_path / "absent-guard.jsonl", {}, observer)
    assert any(event.get("args", {}).get("command") == "mktemp -d" for event in case["events"])
