"""Capture incoming main's lexical Node/tsx script contracts without native calls."""

import ast
import hashlib
import json
import re
import subprocess
from collections.abc import Sequence
from pathlib import Path

BASE = "e4ddb0636c4b457d5d831527af78ced271e42487"
ROOT = Path(__file__).resolve().parents[2]


def record():
    scope = {"re": re, "Path": Path, "Sequence": Sequence, "_normalized_command": tuple}
    hashes = {}
    for module, names in (
        ("restricted_node_test", {"_node_runtime_args", "_NODE_MEMORY_OPTION"}),
        (
            "restricted_inline_eval",
            {
                "_TEST_SCRIPT_NAME",
                "_NODE_TEST_SCRIPT_NAME",
                "_NODE_SCRIPT_FLAGS",
                "_test_script",
                "_node_script_index",
                "_python_runtime_args",
                "is_inline_eval",
            },
        ),
        ("restricted_vitest", {"tsx_test_invocation"}),
    ):
        path = f"src/codex_plugin_scanner/guard/runtime/{module}.py"
        source = subprocess.check_output(["git", "show", f"{BASE}:{path}"], cwd=ROOT)
        hashes[path] = hashlib.sha256(source).hexdigest()
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
        exec(compile(ast.Module(body=nodes, type_ignores=[]), path, "exec"), scope)
    commands = [
        ["node", "math.test.mjs"],
        ["node", "--experimental-strip-types", "src/math.test.ts"],
        ["node", "--no-warnings", "--experimental-transform-types", "tests/api.spec.ts", "--verbose"],
        ["node", "--disable-warning=ExperimentalWarning", "test_calc.js"],
        ["nodejs", "tests.js"],
        ["node", "build.ts"],
        ["node", "math.test.py"],
        ["node", "../math.test.ts"],
        ["node", "/tmp/math.test.ts"],
        ["node", "--import", "evil.mjs", "math.test.ts"],
        ["node", "--experimental-strip-types"],
        ["node", "./node_modules/tsx/dist/cli.mjs", "src/math.test.ts"],
        ["tsx", "math.test.ts", "--flag"],
        ["npx", "tsx", "tests/api.spec.ts"],
        ["npx", "--no-install", "tsx", "test_math.ts"],
        ["./node_modules/.bin/tsx", "math.test.ts"],
        ["tsx"],
        ["tsx", "scripts/deploy.ts"],
        ["tsx", "watch", "math.test.ts"],
        ["tsx", "../math.test.ts"],
        ["npx", "tsx@latest", "math.test.ts"],
        ["npx", "--yes", "tsx", "math.test.ts"],
    ]
    cases = []
    for command in commands:
        for operation, function in (("inline_eval", "is_inline_eval"), ("tsx_test_invocation", "tsx_test_invocation")):
            cases.append(
                {"operation": operation, "input": {"command": command}, "expected": {"value": scope[function](command)}}
            )
    return {"revision": BASE, "sources": hashes, "cases": cases}


if __name__ == "__main__":
    print(json.dumps(record(), indent=2))
