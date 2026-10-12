"""Capture current-main unittest argv outcomes before Python retirement."""

import ast
import hashlib
import json
import re
import subprocess
from collections.abc import Sequence
from pathlib import Path

BASE = "68558a59d9e8b6d4a8a86ef9de9263de41248068"
ROOT = Path(__file__).resolve().parents[2]


def record():
    path = "src/codex_plugin_scanner/guard/runtime/restricted_inline_eval.py"
    source = subprocess.check_output(["git", "show", f"{BASE}:{path}"], cwd=ROOT)
    names = {
        "_TEST_SCRIPT_NAME",
        "_NODE_TEST_SCRIPT_NAME",
        "_UNITTEST_ARGUMENT_REJECT",
        "_test_script",
        "_python_runtime_args",
    }
    tree = ast.parse(source)
    nodes = [
        node
        for node in tree.body
        if (isinstance(node, ast.FunctionDef) and node.name in names)
        or (
            isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id in names for target in node.targets)
        )
    ]
    scope = {"re": re, "Path": Path, "Sequence": Sequence}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), path, "exec"), scope)
    commands = [
        ["python3", "-m", "unittest"],
        ["python3", "-m", "unittest", "-q"],
        ["python", "-I", "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"],
        ["python3", "-IS", "-m", "unittest", "test_calc.CalcTest.test_add", "-v"],
        ["python3", "-I", "-I", "-m", "unittest"],
        ["python3", "-m", "arbitrary"],
        *[["python3", "-m", "unittest", "prefix" + symbol + "suffix"] for symbol in "<>|&;`$"],
    ]
    return {
        "revision": BASE,
        "source_sha256": hashlib.sha256(source).hexdigest(),
        "cases": [
            {
                "operation": "python_runtime_args",
                "input": {"command": command},
                "expected": {"value": scope["_python_runtime_args"](command)},
            }
            for command in commands
        ],
    }


if __name__ == "__main__":
    print(json.dumps(record(), indent=2))
