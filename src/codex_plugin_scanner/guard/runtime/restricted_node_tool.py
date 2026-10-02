"""Local lint/typecheck resolution under the enforced read-only Node profile."""

from __future__ import annotations

import shlex
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

from .package_evidence_common import read_json_with_integrity
from .restricted_node_test import prepare_restricted_node_test
from .restricted_pytest_model import NODE_TOOL_READ_ONLY_PROFILE_VERSION, RestrictedPytestError, RestrictedPytestPlan
from .restricted_pytest_validation import _normalized_command, _path_is_within
from .restricted_vitest import run_restricted_node_plan

_ENTRIES = {"eslint": "eslint/bin/eslint.js", "tsc": "typescript/bin/tsc"}


def prepare_restricted_node_tool(
    command: Sequence[str], *, workspace: Path, cwd: Path | None = None
) -> RestrictedPytestPlan:
    argv = _normalized_command(command)
    name, args = Path(argv[0]).name, argv[1:]
    expected_entry = None
    if name in {"bun", "npm", "pnpm"}:
        if len(args) != 2 or args[0] != "run" or args[1] not in {"lint", "typecheck"}:
            raise RestrictedPytestError(
                "node_tool_invalid_command", "Only direct lint/typecheck scripts are supported."
            )
        manifest, _digest = read_json_with_integrity(workspace / "package.json")
        scripts = manifest.get("scripts") if isinstance(manifest, dict) else None
        script = scripts.get(args[1]) if isinstance(scripts, dict) else None
        if not isinstance(script, str):
            raise RestrictedPytestError("node_tool_invalid_command", "The requested local script is unavailable.")
        try:
            tokens = shlex.split(script)
        except ValueError as error:
            raise RestrictedPytestError("node_tool_invalid_command", "The local script could not be parsed.") from error
        if not tokens:
            raise RestrictedPytestError("node_tool_invalid_command", "The requested local script is empty.")
        name, args = tokens[0], tuple(tokens[1:])
    elif name in {"bunx", "npx"}:
        if args and args[0] == "--no-install":
            args = args[1:]
        if not args:
            raise RestrictedPytestError("node_tool_invalid_command", "Missing local runner.")
        name, args = args[0], args[1:]
    elif name in {"node", "nodejs"}:
        if not args:
            raise RestrictedPytestError("node_tool_invalid_command", "Missing local entrypoint.")
        expected_entry = Path(args[0])
        name = next(
            (tool for tool, entry in _ENTRIES.items() if str(expected_entry).endswith("/node_modules/" + entry)), ""
        )
        args = args[1:]
    if name not in _ENTRIES or (name == "tsc" and "--noEmit" not in args):
        raise RestrictedPytestError(
            "node_tool_invalid_command", "Only local ESLint and no-emit TypeScript are supported."
        )
    if any(
        token
        in {";", "&&", "||", "|", "|&", "&", "--fix", "--fix-dry-run", "--output-file", "-o", "--emitDeclarationOnly"}
        or token.startswith(("--fix=", "--output-file="))
        for token in args
    ):
        raise RestrictedPytestError("node_tool_invalid_command", "The lint/typecheck input has write or shell effects.")
    base = prepare_restricted_node_test(["node", "--test"], workspace=workspace, cwd=cwd)
    try:
        entry = (base.workspace / "node_modules" / _ENTRIES[name]).resolve(strict=True)
        if not entry.is_file() or not _path_is_within(entry, base.workspace / "node_modules"):
            raise OSError("external tool entrypoint")
        if expected_entry is not None and expected_entry.resolve(strict=True) != entry:
            raise OSError("unexpected tool entrypoint")
    except (OSError, RuntimeError) as error:
        raise RestrictedPytestError(
            "node_tool_dependency_unavailable",
            "The local lint/typecheck tool is unavailable; no replacement was downloaded.",
        ) from error
    return replace(
        base, profile_version=NODE_TOOL_READ_ONLY_PROFILE_VERSION, command=(str(base.executable), str(entry), *args)
    )


def run_restricted_node_tool(plan: RestrictedPytestPlan, *, timeout_seconds: int) -> int:
    return run_restricted_node_plan(plan, timeout_seconds=timeout_seconds)
