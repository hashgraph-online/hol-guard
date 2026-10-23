"""Freeze the pinned Python OMP host/bridge event reconciliation without runtime imports."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
SOURCES = {
    "ci/gauntlet/evidence.py": ("b76344cf9700c73abebd5d65a81d34aa28c960b591fc2bc485423afa038efe2f", "reconcile"),
    "ci/gauntlet/bridge_evidence.py": ("b1422592828f36e489fc7fdb4217324270c79fdc3d1bf8545006bea7c11a96b7", "bridge_calls"),
    "ci/gauntlet/task_arguments.py": ("b80adbc07e9462b3ac623237ca51de4c00e121251b1fb3eaf275e93ec569a1af", "task_arguments_match"),
}


def pinned_reconcile():
    namespace = {"Any": Any, "DEFAULT_TASK_AGENT": "task"}
    for path, (sha256, function_name) in SOURCES.items():
        source = ROOT / path
        raw = source.read_bytes()
        if hashlib.sha256(raw).hexdigest() != sha256:
            raise ValueError(f"pinned source changed: {path}")
        tree = ast.parse(raw, filename=str(source))
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                     and node.name == function_name]
        if len(functions) != 1:
            raise ValueError(f"pinned function is missing or ambiguous: {path}:{function_name}")
        module = ast.fix_missing_locations(ast.Module(body=functions, type_ignores=[]))
        exec(compile(module, str(source), "exec"), namespace)
    return namespace["reconcile"]


def base():
    return [
        {"type": "model_turn", "calls": [{"id": "a", "name": "bash", "arguments": {"command": "echo ok"}}]},
        {"type": "tool_execution_start", "toolCallId": "a", "toolName": "bash", "args": {"command": "echo ok"}},
        {"type": "tool_execution_end", "toolCallId": "a", "toolName": "bash", "isError": False,
         "result": {"content": "ok"}},
    ]


def bridge():
    return [
        {"type": "model_turn", "calls": [{"id": "p", "name": "eval", "arguments": {"code": "tool()"}}]},
        {"type": "tool_execution_start", "toolCallId": "p", "toolName": "eval", "args": {"code": "tool()"}},
        {"type": "eval_bridge_start", "parentToolCallId": "p", "parentToolCallIds": ["p"],
         "event": {"type": "tool_call", "toolCallId": "js-bash-1", "toolName": "bash",
                   "input": {"command": "echo ok"}}},
        {"type": "eval_bridge_end", "parentToolCallId": "p", "parentToolCallIds": ["p"],
         "event": {"type": "tool_result", "toolCallId": "js-bash-1", "toolName": "bash",
                   "input": {"command": "echo ok"}, "isError": False, "content": [{"text": "ok"}]}},
        {"type": "tool_execution_end", "toolCallId": "p", "toolName": "eval", "isError": False,
         "result": {"content": "done"}},
    ]


def cases():
    rows = [("one-complete", base()), ("empty", []), ("one-bridge", bridge())]

    def changed(name, template, edit):
        value = copy.deepcopy(template)
        edit(value)
        rows.append((name, value))

    changed("duplicate-model", base(), lambda e: e[0]["calls"].append(copy.deepcopy(e[0]["calls"][0])))
    changed("missing-model", base(), lambda e: e.pop(0))
    changed("duplicate-start", base(), lambda e: e.insert(2, copy.deepcopy(e[1])))
    changed("duplicate-end", base(), lambda e: e.append(copy.deepcopy(e[2])))
    changed("start-before-request", base(), lambda e: e.insert(1, e.pop(0)))
    changed("end-before-start", base(), lambda e: e.insert(1, e.pop(2)))
    changed("missing-end", base(), lambda e: e.pop())
    changed("missing-model-args", base(), lambda e: e[0]["calls"][0].pop("arguments"))
    changed("missing-host-args", base(), lambda e: e[1].pop("args"))
    changed("wrong-host-name", base(), lambda e: e[1].update(toolName="eval"))
    changed("wrong-end-name", base(), lambda e: e[2].update(toolName="eval"))
    changed("changed-arguments", base(), lambda e: e[1]["args"].update(command="echo changed"))
    changed("ignored-intent", base(), lambda e: e[0]["calls"][0]["arguments"].update(intent="ignored"))
    changed("missing-completion-status", base(), lambda e: e[2].pop("isError"))
    changed("numeric-completion-status", base(), lambda e: e[2].update(isError=0))
    changed("empty-model-id", base(), lambda e: e[0]["calls"][0].update(id=""))
    changed("empty-host-id", base(), lambda e: e[1].update(toolCallId=""))
    changed("task-default-agent", base(), lambda e: (
        e[0]["calls"][0].update(name="task", arguments={"tasks": [{"description": "x", "outputSchema": None}]}),
        e[1].update(toolName="task", args={"tasks": [{"description": "x", "agent": "task"}]}),
        e[2].update(toolName="task")))
    changed("task-changed-description", rows[-1][1], lambda e: e[1]["args"]["tasks"][0].update(description="y"))
    changed("bridge-parent-list", bridge(), lambda e: e[2].update(parentToolCallIds=["p", "q"]))
    changed("bridge-parent-id", bridge(), lambda e: e[2].update(parentToolCallId="q", parentToolCallIds=["q"]))
    changed("bridge-outside-active", bridge(), lambda e: e.insert(2, e.pop(4)))
    changed("bridge-wrong-id-prefix", bridge(), lambda e: e[2]["event"].update(toolCallId="bash-1"))
    changed("bridge-duplicate-start", bridge(), lambda e: e.insert(3, copy.deepcopy(e[2])))
    changed("bridge-changed-input", bridge(), lambda e: e[3]["event"]["input"].update(command="echo changed"))
    changed("bridge-missing-status", bridge(), lambda e: e[3]["event"].pop("isError"))
    changed("bridge-unfinished", bridge(), lambda e: e.pop(3))
    changed("bridge-end-before-child", bridge(), lambda e: e.insert(3, e.pop(4)))
    return rows


def main() -> None:
    reconcile = pinned_reconcile()
    frozen = []
    for name, events in cases():
        calls, errors = reconcile(events)
        frozen.append({"name": name, "events": events, "calls": calls, "errors": errors})
    print(json.dumps({"schema": "gauntlet-host-call-fixtures.v1",
                      "sources": [{"path": path, "sha256": sha}
                                  for path, (sha, _) in SOURCES.items()],
                      "cases": frozen}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
