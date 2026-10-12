"""Synthetic public-policy vectors; all policy bodies come from pinned Git objects.

Parsed shell segments and trusted binaries are explicit fixture service facts.
The candidate native tests parse the commands themselves and never load Python.
No wire or production API accepts the synthetic package trust root used here.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import shlex
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

PREFIX = "src/codex_plugin_scanner/guard/runtime/"
DEPENDENCIES = ("node_semver.py", "github_actions_read_workflow.py", "direct_typescript_diagnostics.py")
INTEGRITY = "sha512-jl1vZzPDinLr9eUt3J/t7V6FgNEw9QjvBPdysz9KfQDD41fQrC2Y4vKQdiaUpFT4bXlb1RHhLpp8wtm6M5TgSw=="
TRUSTED = ["bun", "grep", "head", "node", "npx", "tail", "wc"]


def load_services(repo: Path, commit: str, source_at: Any) -> tuple[dict[str, Any], dict[str, str]]:
    namespace: dict[str, Any] = {
        "__name__": "recorded_direct_tool_services",
        "git_binary_path_is_trusted": lambda *_args, **_kwargs: False,
    }
    hashes = {}
    for name in DEPENDENCIES:
        path = PREFIX + name
        source = source_at(repo, commit, path)
        tree = ast.parse(source, filename=path)
        tree.body = [node for node in tree.body if not isinstance(node, ast.ImportFrom) or node.level == 0]
        exec(compile(tree, path, "exec"), namespace)
        hashes[path] = hashlib.sha256(source).hexdigest()
    return namespace, hashes


def fixture() -> dict[str, Any]:
    def encode(path: str, value: Any, *, raw: bool = False, executable: bool = False) -> dict[str, Any]:
        text = value if raw else json.dumps(value, sort_keys=True)
        return {"path": path, "bytes_hex": text.encode().hex(), "executable": executable}

    return {
        "files": [
            encode(
                "home/subject/package.json",
                {"name": "synthetic", "devDependencies": {"vitest": "^4.1.8", "typescript": "^5.9.3"}},
            ),
            encode(
                "home/subject/bun.lock",
                {
                    "packages": {
                        "vitest": ["vitest@4.1.8", "", {}, "synthetic"],
                        "typescript": ["typescript@5.9.3", "", {"bin": {"tsc": "bin/tsc"}}, INTEGRITY],
                    }
                },
            ),
            encode(
                "home/subject/node_modules/vitest/package.json",
                {"name": "vitest", "version": "4.1.8", "bin": {"vitest": "./vitest.mjs"}},
            ),
            encode("home/subject/node_modules/vitest/vitest.mjs", "#!/usr/bin/env node\n", raw=True, executable=True),
            encode(
                "home/subject/node_modules/typescript/package.json",
                {"name": "typescript", "version": "5.9.3", "bin": {"tsc": "./bin/tsc"}},
            ),
            encode("home/subject/node_modules/typescript/bin/tsc", "#!/usr/bin/env node\n", raw=True, executable=True),
            encode("home/subject/tests/unit.test.ts", "export {};\n", raw=True),
            encode("home/subject/src/index.ts", "export {};\n", raw=True),
            encode("home/subject/tsconfig.json", "{}", raw=True),
        ],
        "symlinks": [
            {"path": "home/subject/node_modules/.bin/vitest", "target": "../vitest/vitest.mjs"},
            {"path": "home/subject/node_modules/.bin/tsc", "target": "../typescript/bin/tsc"},
        ],
    }


def prepare(root: Path, data: dict[str, Any]) -> None:
    (root / "home/caller").mkdir(parents=True)
    for row in data["files"]:
        path = root / row["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(bytes.fromhex(row["bytes_hex"]))
        if row["executable"]:
            path.chmod(0o755)
    for row in data["symlinks"]:
        path = root / row["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(row["target"])


def parsed_fixture_model(script: str, *, cwd: Path, workspace_root: Path, **_kwargs: Any) -> Any:
    # Templates intentionally delimit controls with spaces. These input facts
    # replace only the already-native shell-model service in the legacy caller.
    segments = []
    before: tuple[str, ...] = ()
    tokens = []
    effective = cwd.resolve()
    for token in [*shlex.split(script), "__END__"]:
        if token not in {"&&", "||", "|", ";", "__END__"}:
            tokens.append(token)
            continue
        operation = "cd" if tokens[:1] == ["cd"] else None
        segments.append(
            SimpleNamespace(
                tokens=tuple(tokens), control_before=before, effective_cwd=effective, directory_operation=operation
            )
        )
        if operation == "cd" and len(tokens) == 2:
            operand = Path(tokens[1])
            effective = (operand if operand.is_absolute() else effective / operand).resolve()
        tokens = []
        before = (token,)
    return SimpleNamespace(complete=True, segments=segments, workspace_root=workspace_root.resolve())


def public_cases() -> list[dict[str, Any]]:
    rows = []
    vitest = "cd {workspace} && {runner} run tests/unit.test.ts --no-coverage 2>&1 | tail -40"
    count = (
        'cd {workspace} && NODE_OPTIONS="--max-old-space-size=8192" '
        "bun --smol ./node_modules/typescript/bin/tsc --noEmit 2>&1 "
        '| grep "error TS" | wc -l ; echo MY_TSC_ERRORS_COUNT_DONE'
    )
    routine = 'cd {workspace} && npx tsc --noEmit src/index.ts 2>&1 | grep -v "npm warn" | head -8 ; echo TSC_DONE'
    diagnostic = (
        "cd {workspace} && npx tsc --noEmit 2>&1 "
        '| grep -E "harnesses/page|enterprises/page" || echo NO_ERRORS_IN_TOUCHED_FILES'
    )
    for tool, commands in (
        (
            "vitest",
            [
                vitest,
                vitest.replace("tail -40", "head -1"),
                vitest.replace("{runner}", "npx vitest").replace(" --no-coverage", ""),
                vitest.replace("{runner}", "npx --no --no-install vitest").replace(" --no-coverage", ""),
                *[
                    vitest.replace("--no-coverage", suffix)
                    for suffix in [
                        "",
                        "--no-coverage --no-coverage",
                        "--config attacker.ts",
                        "--watch",
                        "--no-coverage extra.ts",
                        "--no-coverage ../outside.test.ts",
                    ]
                ],
                *[
                    vitest.replace("tail -40", observer)
                    for observer in ["tail -0", "tail -1001", "tail --lines=40", "cat", "tail -40 > output.txt"]
                ],
            ],
        ),
        (
            "typescript",
            [
                count,
                count.replace("8192", "256"),
                count.replace("8192", "32768"),
                *[
                    count.replace(a, b)
                    for a, b in [
                        ("8192", "255"),
                        ("8192", "65536"),
                        ("--noEmit", "--emitDeclarationOnly"),
                        ("wc -l", "wc -c"),
                        ("MY_TSC_ERRORS_COUNT_DONE", "OTHER"),
                        ("error TS", "other"),
                    ]
                ],
                routine,
                routine.replace(' | grep -v "npm warn" | head -8 ; echo TSC_DONE', ""),
                routine.replace("head -8", "tail -200"),
                routine.replace('grep -v "npm warn"', "grep"),
                routine.replace('grep -v "npm warn"', "grep -v"),
                routine.replace('grep -v "npm warn" | head -8', "grep error | head -200"),
                *[
                    routine.replace('grep -v "npm warn"', observer)
                    for observer in ("grep -a ^*", "grep error?", "grep [error]")
                ],
                *[
                    routine.replace(a, b)
                    for a, b in [
                        ("--noEmit", "--noEmit false"),
                        ("--noEmit", "--noEmit --build"),
                        ("src/index.ts", "@response"),
                        ("src/index.ts", "--project tsconfig.json"),
                        ("src/index.ts", "--types @cloudflare/workers-types"),
                        ("head -8", "head -201"),
                        ("TSC_DONE", "9INVALID"),
                        ("head -8", "grep second"),
                    ]
                ],
                diagnostic,
                diagnostic.replace("harnesses/page|enterprises/page", r"src/index\.ts"),
                diagnostic.replace("||", ";"),
                diagnostic.replace("npx tsc", "npx --package=typescript tsc"),
                diagnostic.replace("NO_ERRORS_IN_TOUCHED_FILES", "OTHER"),
            ],
        ),
    ):
        for command in commands:
            rows.append(
                {"tool": tool, "command": command, "environment": {}, "trusted_commands": TRUSTED, "mutations": []}
            )
    for command, tool in [
        (vitest, "vitest"),
        (count, "typescript"),
        (routine, "typescript"),
        (diagnostic, "typescript"),
    ]:
        for untrusted in ["node", "npx", "tail", "bun", "grep", "head", "wc"]:
            rows.append(
                {
                    "tool": tool,
                    "command": command,
                    "environment": {},
                    "trusted_commands": [c for c in TRUSTED if c != untrusted],
                    "mutations": [],
                }
            )
        for path in [
            "home/subject/package.json",
            "home/subject/bun.lock",
            "home/subject/node_modules/.bin/tsc",
            "home/subject/node_modules/.bin/vitest",
            "home/subject/node_modules/typescript/bin/tsc",
            "home/subject/node_modules/vitest/vitest.mjs",
        ]:
            rows.append(
                {
                    "tool": tool,
                    "command": command,
                    "environment": {},
                    "trusted_commands": TRUSTED,
                    "mutations": [{"kind": "remove", "path": path}],
                }
            )
    for command in [routine, diagnostic]:
        for key in [
            "NODE_OPTIONS",
            "node_options",
            "NODE_PATH",
            "NPM_CONFIG_SCRIPT_SHELL",
            "npm_config_node_options",
            "BASH_ENV",
            "ZDOTDIR",
            "HTTPS_PROXY",
            "DYLD_SYNTHETIC",
            "LD_PRELOAD",
        ]:
            rows.append(
                {
                    "tool": "typescript",
                    "command": command,
                    "environment": {key: "synthetic"},
                    "trusted_commands": TRUSTED,
                    "mutations": [],
                }
            )
        for content in [
            "audit=false\nregistry=https://example.invalid\n",
            "node-options=--require=synthetic.js\n",
            "malformed\n",
            "@synthetic:registry=https://example.invalid\n",
        ]:
            rows.append(
                {
                    "tool": "typescript",
                    "command": command,
                    "environment": {},
                    "trusted_commands": TRUSTED,
                    "mutations": [
                        {"kind": "write", "path": "home/subject/.npmrc", "bytes_hex": content.encode().hex()}
                    ],
                }
            )
    for content in ["[install]\nsmol=true\n", "[install]\ncache=true\n", '[run]\npreload="synthetic.js"\n']:
        rows.append(
            {
                "tool": "typescript",
                "command": count,
                "environment": {},
                "trusted_commands": TRUSTED,
                "mutations": [
                    {"kind": "write", "path": "home/subject/bunfig.toml", "bytes_hex": content.encode().hex()}
                ],
            }
        )
    return rows


def record_public(namespace: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    data = fixture()
    recorded = []
    saved_environment = dict(os.environ)
    try:
        for case in public_cases():
            with tempfile.TemporaryDirectory(prefix="guard-direct-public-") as temporary:
                root = Path(temporary).resolve()
                prepare(root, data)
                home, caller, workspace = (root / p for p in ["home", "home/caller", "home/subject"])
                digest = namespace["_package_tree_digest"](workspace / "node_modules/typescript")
                namespace["_TRUSTED_TYPESCRIPT_PACKAGES"] = {("5.9.3", INTEGRITY): digest}
                namespace["_trusted_path_command"] = (
                    lambda command, commands=tuple(case["trusted_commands"]), **_kwargs: command in commands
                )
                namespace["model_shell_execution_context"] = parsed_fixture_model
                for mutation in case["mutations"]:
                    path = root / mutation["path"]
                    if mutation["kind"] == "remove":
                        path.unlink()
                    else:
                        path.write_bytes(bytes.fromhex(mutation["bytes_hex"]))
                os.environ.clear()
                os.environ.update(case["environment"])
                command = case["command"].format(
                    workspace=workspace, runner=workspace / "node_modules/vitest/vitest.mjs"
                )
                result = namespace[f"direct_local_{case['tool']}_execution_context"](command, cwd=caller, home_dir=home)
                recorded.append({**case, "trusted_tree_sha256": digest, "expected": result is not None})
    finally:
        os.environ.clear()
        os.environ.update(saved_environment)
    assert sum(c["expected"] for c in recorded) >= 10, "baseline services must produce supported positive contexts"
    return data, recorded
