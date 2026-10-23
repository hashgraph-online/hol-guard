"""Freeze the pinned Python worker's fixed launch vector without spawning it."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "ci/gauntlet/control_plane/vm_worker.py"
SOURCE_SHA256 = "fb95cd33bf04c3e68c641972dc6bd5340a8cd87b1ad2948ba131c4a71c60aa9e"


def assignment(function: ast.FunctionDef, name: str) -> ast.expr:
    matches = [
        node.value
        for node in ast.walk(function)
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)
    ]
    if len(matches) != 1:
        raise ValueError(f"expected one {name} assignment in pinned worker")
    return matches[0]


def evaluate(node: ast.expr, names: dict[str, object]) -> object:
    """Interpret only literals, bound names, list items, indexing and str()."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name) and node.id in names:
        return names[node.id]
    if isinstance(node, ast.List):
        return [evaluate(item, names) for item in node.elts]
    if isinstance(node, ast.Subscript):
        return evaluate(node.value, names)[evaluate(node.slice, names)]
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "str"
        and len(node.args) == 1
        and not node.keywords
    ):
        return str(evaluate(node.args[0], names))
    raise ValueError(f"unexpected pinned worker launch expression: {ast.dump(node)}")


def main() -> None:
    raw = SOURCE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_SHA256:
        raise ValueError("pinned Python worker source changed")
    module = ast.parse(raw, filename=str(SOURCE))
    execute = next(
        node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == "execute"
    )
    code = ast.literal_eval(assignment(execute, "code"))
    command = assignment(execute, "command")
    popen = [
        node
        for node in ast.walk(execute)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subprocess"
        and node.func.attr == "Popen"
    ]
    if len(popen) != 1:
        raise ValueError("expected one pinned worker spawn boundary")
    environment = ast.literal_eval(next(item.value for item in popen[0].keywords if item.arg == "env"))
    cases = []
    for source, job, config_digest, deployment_digest in [
        ("a" * 40, "d" * 16, "b" * 64, "c" * 64),
        ("0123456789abcdef" * 2 + "01234567", "0123456789abcdef", "f" * 64, "e" * 64),
    ]:
        value = {
            "python": "/opt/hol-benchmark-controller-20261013/.venv/bin/python",
            "controller": "/opt/hol-gauntlet/controller-0123456789abcdef",
            "config": f"/opt/hol-gauntlet/candidates/{source}/config.json",
            "config_digest": config_digest,
            "asset_root": "/opt",
        }
        state = f"/home/hg-{job}"
        output = f"/var/lib/hol-gauntlet/outputs/{job}"
        argv = evaluate(
            command,
            {"value": value, "sha": source, "job": job, "state": state, "output": output, "code": code},
        )
        cases.append(
            {
                "source_sha": source,
                "job_id": job,
                "config_digest": config_digest,
                "deployment_digest": deployment_digest,
                "controller_path": value["controller"],
                "python_path": value["python"],
                "argv": argv,
                "cwd": value["controller"],
                "env": environment,
                "state_root": state,
                "output_dir": output,
                "log_path": output + ".log",
            }
        )
    print(
        json.dumps(
            {
                "schema": "gauntlet-worker-launch-fixtures.v1",
                "source_sha256": SOURCE_SHA256,
                "cases": cases,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
