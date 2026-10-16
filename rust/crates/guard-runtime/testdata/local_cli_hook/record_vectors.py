"""Record local CLI command-id resolution from the Python owner before it retires.

Run with the source tree whose ``command_tokens_for_invocation``
(``runtime/local_cli_commands.py``) still splits the parsed argv in Python.
Each vector starts after the shell parse: the first segment's arguments, the
identity's runner, kind and name, and the CLI's catalog ids. The token step
below is that function's post-parse branch transcribed verbatim; the runner
split, name pattern, depth cap and ``match_command_id`` are the real owner
objects, loaded from the owner source without importing its package (which
needs the generated command catalog). No resident runs.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
from collections.abc import Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from codex_plugin_scanner.guard.runtime import local_cli_runner
from codex_plugin_scanner.guard.runtime.local_cli_runner import runner_inner_arguments

_OWNER_NAMES = frozenset({"ROOT_COMMAND_ID", "OTHER_COMMAND_ID", "_COMMAND_NAME", "_MAX_DEPTH", "match_command_id"})


def _owner_objects() -> dict[str, Any]:
    """Execute the owner's constants and ``match_command_id`` from source."""

    path = Path(local_cli_runner.__file__).with_name("local_cli_commands.py")
    tree = ast.parse(path.read_text(encoding="utf-8"))
    body = [
        node
        for node in tree.body
        if (isinstance(node, ast.FunctionDef) and node.name in _OWNER_NAMES)
        or (
            isinstance(node, ast.Assign)
            and all(isinstance(target, ast.Name) and target.id in _OWNER_NAMES for target in node.targets)
        )
    ]
    namespace: dict[str, Any] = {"re": re, "Sequence": Sequence, "LocalCliCommand": object}
    exec(compile(ast.Module(body=body, type_ignores=[]), str(path), "exec"), namespace)
    assert set(namespace) >= _OWNER_NAMES
    return namespace


_OWNER = _owner_objects()
_COMMAND_NAME = _OWNER["_COMMAND_NAME"]
_MAX_DEPTH = _OWNER["_MAX_DEPTH"]
match_command_id = _OWNER["match_command_id"]


def _tokens(arguments: list[str], *, runner: str | None, kind: str, name: str) -> list[str]:
    if runner is not None:
        split = runner_inner_arguments(runner, arguments)
        if split is None:
            return []
        arguments = split
    elif kind == "script" and arguments:
        first_name = Path(arguments[0]).name
        if first_name == name:
            arguments = arguments[1:]
    tokens: list[str] = []
    for argument in arguments:
        if argument.startswith("-") or not _COMMAND_NAME.fullmatch(argument):
            break
        tokens.append(argument)
        if len(tokens) >= _MAX_DEPTH:
            break
    return tokens


_CATALOG = ["root", "deploy", "deploy.prod", "db", "db.migrate", "db.migrate.up", "a.b.c.d", "other"]

# (name, arguments, runner, kind, identity name, catalog)
_CASES: list[tuple[str, list[str], str | None, str, str, list[str]]] = [
    ("plain-empty", [], None, "executable", "tool", _CATALOG),
    ("plain-one", ["deploy"], None, "executable", "tool", _CATALOG),
    ("plain-nested", ["deploy", "prod"], None, "executable", "tool", _CATALOG),
    ("plain-nested-unknown-tail", ["deploy", "staging"], None, "executable", "tool", _CATALOG),
    ("plain-unknown", ["status"], None, "executable", "tool", _CATALOG),
    ("plain-flag-first", ["--verbose", "deploy"], None, "executable", "tool", _CATALOG),
    ("plain-flag-stops", ["deploy", "--force", "prod"], None, "executable", "tool", _CATALOG),
    ("plain-dash-only", ["-", "deploy"], None, "executable", "tool", _CATALOG),
    ("plain-path-stops", ["./deploy"], None, "executable", "tool", _CATALOG),
    ("plain-digit-start", ["1deploy"], None, "executable", "tool", _CATALOG),
    ("plain-underscore", ["db_migrate"], None, "executable", "tool", _CATALOG),
    ("plain-max-depth", ["a", "b", "c", "d", "e"], None, "executable", "tool", _CATALOG),
    ("plain-depth-prefix", ["db", "migrate", "up", "now", "later"], None, "executable", "tool", _CATALOG),
    ("plain-long-name", ["a" * 41], None, "executable", "tool", _CATALOG),
    ("plain-too-long-name", ["a" * 42], None, "executable", "tool", _CATALOG),
    ("plain-unicode", ["déploy"], None, "executable", "tool", _CATALOG),
    ("plain-dot-token", ["deploy.prod"], None, "executable", "tool", _CATALOG),
    ("plain-empty-catalog", ["deploy"], None, "executable", "tool", []),
    ("plain-root-word", ["root"], None, "executable", "tool", _CATALOG),
    ("script-strip", ["tool.py", "deploy"], None, "script", "tool.py", _CATALOG),
    ("script-strip-path", ["./bin/tool.py", "db", "migrate"], None, "script", "tool.py", _CATALOG),
    ("script-strip-trailing-dot", ["bin/tool.py/.", "deploy"], None, "script", "tool.py", _CATALOG),
    ("script-no-strip", ["other.py", "deploy"], None, "script", "tool.py", _CATALOG),
    ("script-no-strip-name-token", ["deploy", "prod"], None, "script", "deploy", _CATALOG),
    ("script-only-script", ["tool.py"], None, "script", "tool.py", _CATALOG),
    ("script-empty", [], None, "script", "tool.py", _CATALOG),
    ("executable-no-strip", ["tool", "deploy"], None, "executable", "tool", _CATALOG),
    ("runner-npx", ["wrangler", "deploy"], "npx", "executable", "wrangler", _CATALOG),
    ("runner-npx-yes", ["-y", "wrangler", "deploy", "prod"], "npx", "executable", "wrangler", _CATALOG),
    ("runner-npx-long-yes", ["--yes", "--", "wrangler", "db"], "npx", "executable", "wrangler", _CATALOG),
    ("runner-npx-package-flag", ["--package", "x", "wrangler", "deploy"], "npx", "executable", "wrangler", _CATALOG),
    ("runner-npx-no-target", ["-y"], "npx", "executable", "wrangler", _CATALOG),
    ("runner-npx-target-only", ["wrangler"], "npx", "executable", "wrangler", _CATALOG),
    ("runner-npm-exec", ["exec", "wrangler", "deploy"], "npm", "executable", "wrangler", _CATALOG),
    ("runner-pnpm-x", ["x", "wrangler", "db", "migrate"], "pnpm", "executable", "wrangler", _CATALOG),
    ("runner-yarn-exec-twice", ["exec", "exec", "deploy"], "yarn", "executable", "exec", _CATALOG),
    ("runner-npx-exec-is-target", ["exec", "deploy"], "npx", "executable", "exec", _CATALOG),
    ("runner-bunx", ["tool", "--flag", "deploy"], "bunx", "executable", "tool", _CATALOG),
    ("runner-empty", [], "npx", "executable", "tool", _CATALOG),
    ("runner-script-kind", ["tool.py", "deploy"], "npx", "script", "tool.py", _CATALOG),
    ("runner-max-depth", ["tool", "a", "b", "c", "d", "e"], "pnpx", "executable", "tool", _CATALOG),
]


def build() -> dict[str, object]:
    vectors = []
    for name, arguments, runner, kind, identity_name, catalog in _CASES:
        tokens = _tokens(list(arguments), runner=runner, kind=kind, name=identity_name)
        commands = [SimpleNamespace(command_id=item) for item in catalog]
        vectors.append(
            {
                "name": name,
                "arguments": arguments,
                "runner": runner,
                "kind": kind,
                "identity_name": identity_name,
                "catalog": catalog,
                "tokens": tokens,
                "command_id": match_command_id(tokens, commands),
            }
        )
    return {"schema": "guard-local-cli-hook-vectors.v1", "vectors": vectors}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name("vectors.json"))
    options = parser.parse_args()
    options.output.write_text(json.dumps(build(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
