"""Freeze the Python host's fixed model-launch command and return shape."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[3]
LOCAL = ROOT / "ci/gauntlet/control_plane/live_local.py"
PROVIDER = ROOT / "ci/gauntlet/control_plane/live_provider.py"
OUTPUT = ROOT / "ci/gauntlet-rs/crates/gauntlet-host-state/tests/python_live_provider_start_v1.json"
REPOSITORY = Path("/reviewed/hol/workflow-benchmark-implementation")
JOB = "0123456789abcdef"
SOURCE = "a" * 40
KNOWN = 13_746_906


def function(path, name):
    module = ast.parse(path.read_text(encoding="utf-8"))
    return next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == name)


def command_expression():
    run = function(LOCAL, "run")
    matches = [
        node.value
        for node in ast.walk(run)
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "command" for target in node.targets)
        and isinstance(node.value, ast.List)
        and any(
            isinstance(item, ast.Constant) and item.value == "ci.gauntlet.control_plane.live_provider"
            for item in node.value.elts
        )
    ]
    if len(matches) != 1:
        raise ValueError("Python model provider command shape changed")
    return ast.fix_missing_locations(ast.Expression(body=matches[0]))


def return_expression():
    start = function(PROVIDER, "start")
    matches = [
        node.value
        for node in ast.walk(start)
        if isinstance(node, ast.Return)
        and isinstance(node.value, ast.Dict)
        and any(isinstance(key, ast.Constant) and key.value == "provider_manifest" for key in node.value.keys)
    ]
    if len(matches) != 1:
        raise ValueError("Python model provider startup return shape changed")
    return ast.fix_missing_locations(ast.Expression(body=matches[0]))


COMMAND = compile(command_expression(), str(LOCAL), "eval")
RETURN = compile(return_expression(), str(PROVIDER), "eval")


def case(profile):
    command = eval(
        COMMAND,
        {
            "UV": "/opt/homebrew/bin/uv",
            "job": JOB,
            "profile": profile,
            "candidate": {"sha": SOURCE},
        },
    )
    provider_root = REPOSITORY.parent / ("local-model-provider-gauntlet-" + JOB)
    result = eval(
        RETURN,
        {
            "root": provider_root,
            "config": {"binding_sha256": "c" * 64},
            "sha": lambda path: "b" * 64 if Path(path).name == "provider-manifest.json" else "d" * 64,
            "process": SimpleNamespace(pid=1234),
            "before": {"known_tokens": KNOWN},
            "CEILING": 14_468_885,
            "MODEL_ID": "mlx-community/Qwen3.6-35B-A3B-8bit",
        },
    )
    return {
        "profile": profile,
        "plan": {
            "argv": command,
            "cwd": str(REPOSITORY),
            "timeout_seconds": 900,
            "execution_eligible": False,
        },
        "stdout": "loading local model\n" + json.dumps(result, sort_keys=True) + "\n",
        "result": result,
    }


fixture = {
    "schema": "hol-gauntlet-python-live-provider-start-fixtures.v1",
    "source_sha256": {
        "live_local": hashlib.sha256(LOCAL.read_bytes()).hexdigest(),
        "live_provider": hashlib.sha256(PROVIDER.read_bytes()).hexdigest(),
    },
    "command_ast_sha256": hashlib.sha256(ast.unparse(command_expression()).encode()).hexdigest(),
    "return_ast_sha256": hashlib.sha256(ast.unparse(return_expression()).encode()).hexdigest(),
    "job_id": JOB,
    "candidate_source_sha": SOURCE,
    "known_tokens_before": KNOWN,
    "cases": [case(profile) for profile in ("beta-e2e", "feature-ai", "feature-ai-protocol")],
}
OUTPUT.write_text(json.dumps(fixture, sort_keys=True, indent=2) + "\n", encoding="utf-8")
