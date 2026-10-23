"""Freeze the exact pure terminal/retry branch of Python run_pilot."""

from __future__ import annotations

import ast
import hashlib
import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "ci/gauntlet/benchmark/pilot.py"
OUTPUT = ROOT / "ci/gauntlet-rs/crates/gauntlet-evidence/tests/fixtures/pilot_terminal_v1.json"


def extracted():
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "run_pilot")

    def assigns(node, name):
        return isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name for target in node.targets
        )

    starts = [index for index, node in enumerate(function.body) if assigns(node, "execution_valid")]
    ends = [index for index, node in enumerate(function.body) if assigns(node, "episode_end")]
    if len(starts) != 1 or len(ends) != 1 or ends[0] <= starts[0]:
        raise ValueError("Python terminal branch shape changed")
    body = deepcopy(function.body[starts[0] : ends[0] + 1])
    source = ast.unparse(ast.Module(body=body, type_ignores=[]))
    compiled = compile(ast.fix_missing_locations(ast.Module(body=body, type_ignores=[])), str(SOURCE), "exec")
    return compiled, hashlib.sha256(source.encode()).hexdigest()


BRANCH, BRANCH_SHA = extracted()


def classify(case):
    scope = {
        "completed": (None if case["exit_code"] is None else SimpleNamespace(returncode=case["exit_code"])),
        "controller_error": case["controller_error"],
        "events": case["events"],
        "isolated": case["isolated"],
        "isolation": case["isolation"],
        "supervisor": SimpleNamespace(**case["active"]),
    }
    exec(BRANCH, scope)
    return {key: scope[key] for key in ("execution_valid", "controller_error", "retryable_startup", "episode_end")}


BASE = {
    "exit_code": 0,
    "controller_error": None,
    "events": [{"type": "episode_start"}, {"type": "episode_end", "status": "finished"}],
    "isolated": False,
    "isolation": None,
    "active": {"active_sessions": 0, "active_children": 0, "active_workers": 0},
}
CONNECT = "Error: MCP endpoint connection failed"
DECLARED = "Error: declared MCP endpoint did not finish connecting"


def case(name, **changes):
    value = deepcopy(BASE)
    value.update(changes)
    return {"name": name, "input": value, "expected": classify(value)}


def startup(error=CONNECT, **changes):
    events = [{"type": "episode_error", "phase": "startup", "retryableInfrastructure": True, "error": error}]
    return {"events": events, **changes}


cases = [
    case("finished"),
    case("no_process", exit_code=None),
    case("nonzero_exit", exit_code=1),
    case("missing_start", events=[{"type": "episode_end", "status": "finished"}]),
    case("missing_end", events=[{"type": "episode_start"}]),
    case("producer_error", events=[{"type": "episode_start"}, {"type": "episode_error"}, {"type": "episode_end"}]),
    case("controller_error", controller_error="child failed"),
    case("isolated_no_record", isolated=True),
    case(
        "isolated_incomplete",
        isolated=True,
        isolation={"record": {"isolation_observed": True, "assets_unchanged": True, "cleanup_complete": False}},
    ),
    case(
        "isolated_complete",
        isolated=True,
        isolation={"record": {"isolation_observed": True, "assets_unchanged": True, "cleanup_complete": True}},
    ),
    case("active_session", active={"active_sessions": 1, "active_children": 0, "active_workers": 0}),
    case("active_child", active={"active_sessions": 0, "active_children": 1, "active_workers": 0}),
    case("active_worker", active={"active_sessions": 0, "active_children": 0, "active_workers": 1}),
    case("startup_connect", **startup()),
    case("startup_declared", **startup(DECLARED)),
    case("startup_after_inference", **startup(events=[{"type": "inference_start"}, startup()["events"][0]])),
    case("startup_wrong_error", **startup("Error: unrelated")),
    case(
        "startup_wrong_phase",
        events=[{"type": "episode_error", "phase": "runtime", "retryableInfrastructure": True, "error": CONNECT}],
    ),
    case(
        "startup_not_retryable",
        events=[{"type": "episode_error", "phase": "startup", "retryableInfrastructure": False, "error": CONNECT}],
    ),
    case("startup_with_controller_error", **startup(controller_error="controller failed")),
    case(
        "startup_with_cleanup_error",
        **startup(active={"active_sessions": 1, "active_children": 0, "active_workers": 0}),
    ),
    case(
        "last_terminal_wins",
        events=[
            {"type": "episode_start"},
            {"type": "episode_end", "status": "finished"},
            {"type": "episode_end", "status": "budget-exhausted"},
        ],
    ),
    case(
        "retryable_even_with_end",
        events=[{"type": "episode_start"}, startup()["events"][0], {"type": "episode_end", "status": "finished"}],
    ),
]

fixture = {
    "schema": "hol-gauntlet-python-pilot-terminal-fixtures.v1",
    "python_source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
    "branch_ast_sha256": BRANCH_SHA,
    "cases": cases,
}
OUTPUT.write_text(json.dumps(fixture, sort_keys=True, indent=2) + "\n", encoding="utf-8")
