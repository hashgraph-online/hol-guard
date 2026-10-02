"""Local lint/typecheck resolution under the enforced read-only Node profile."""

from __future__ import annotations

import os
import shlex
import stat
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

from .package_evidence_common import read_json_with_integrity
from .restricted_node_test import prepare_restricted_node_test
from .restricted_pytest_model import (
    NODE_BUILD_OUTPUT_PROFILE_VERSION,
    NODE_TOOL_READ_ONLY_PROFILE_VERSION,
    RestrictedPytestError,
    RestrictedPytestPlan,
)
from .restricted_pytest_validation import _normalized_command, _path_is_within
from .restricted_vitest import run_restricted_node_plan
from .secret_sensitivity import classify_secret_path

_ENTRIES = {"eslint": "eslint/bin/eslint.js", "tsc": "typescript/bin/tsc", "vite": "vite/bin/vite.js"}


def validate_build_output_root(path: Path, *, workspace: Path) -> None:
    if path.parent != workspace or path.name not in {"dist", "build", "out"} or path.is_symlink():
        raise RestrictedPytestError(
            "node_build_invalid_output", "Build output must be a dedicated generated directory."
        )
    if not path.exists():
        return
    if not path.is_dir():
        raise RestrictedPytestError("node_build_invalid_output", "Build output is not a directory.")
    visited = 0
    for directory, folders, files in os.walk(path, followlinks=False):
        for name in (*folders, *files):
            visited += 1
            candidate = Path(directory) / name
            if classify_secret_path(str(candidate), cwd=workspace) is not None:
                raise RestrictedPytestError("node_build_invalid_output", "Build output contains protected data.")
            metadata = candidate.lstat()
            if (
                visited > 20_000
                or stat.S_ISLNK(metadata.st_mode)
                or (stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1)
            ):
                raise RestrictedPytestError(
                    "node_build_invalid_output", "Build output has unverified links or exceeds the discovery budget."
                )


def prepare_restricted_node_tool(
    command: Sequence[str], *, workspace: Path, cwd: Path | None = None
) -> RestrictedPytestPlan:
    argv = _normalized_command(command)
    name, args = Path(argv[0]).name, argv[1:]
    expected_entry = None
    if name in {"bun", "npm", "pnpm"}:
        if len(args) != 2 or args[0] != "run" or args[1] not in {"lint", "typecheck", "build"}:
            raise RestrictedPytestError(
                "node_tool_invalid_command", "Only direct lint/typecheck scripts are supported."
            )
        manifest, _digest = read_json_with_integrity(workspace / "package.json")
        scripts = manifest.get("scripts") if isinstance(manifest, dict) else None
        if isinstance(scripts, dict) and any(scripts.get(phase + args[1]) for phase in ("pre", "post")):
            raise RestrictedPytestError(
                "node_tool_invalid_command", "This script has lifecycle actions that need separate evaluation."
            )
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
    if (
        name not in _ENTRIES
        or (name == "tsc" and "--noEmit" not in args)
        or (name == "vite" and (not args or args[0] != "build"))
    ):
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
    output_roots = ()
    if name == "vite":
        output_name = "dist"
        for index, value in enumerate(args):
            if value.startswith("--outDir="):
                output_name = value.removeprefix("--outDir=")
            elif value == "--outDir":
                if index + 1 >= len(args):
                    raise RestrictedPytestError("node_build_invalid_output", "Missing output directory.")
                output_name = args[index + 1]
        output = base.cwd / output_name
        validate_build_output_root(output, workspace=base.workspace)
        output_roots = (output,)
        if not any(value == "--configLoader" or value.startswith("--configLoader=") for value in args):
            args = (*args, "--configLoader", "runner")
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
        base,
        profile_version=NODE_BUILD_OUTPUT_PROFILE_VERSION if name == "vite" else NODE_TOOL_READ_ONLY_PROFILE_VERSION,
        command=(str(base.executable), str(entry), *args),
        output_roots=output_roots,
        denied_capabilities=tuple(
            "workspace-source-write" if name == "vite" and value == "workspace-write" else value
            for value in base.denied_capabilities
        ),
    )


def run_restricted_node_tool(plan: RestrictedPytestPlan, *, timeout_seconds: int) -> int:
    return run_restricted_node_plan(plan, timeout_seconds=timeout_seconds)
