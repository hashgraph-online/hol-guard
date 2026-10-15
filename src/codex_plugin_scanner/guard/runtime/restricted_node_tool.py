"""Local lint/typecheck resolution under the enforced read-only Node profile."""

from __future__ import annotations

import os
import shlex
import stat
from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path

from .package_evidence_common import read_json_with_integrity
from .restricted_node_test import nearest_project_root, prepare_restricted_node_test
from .restricted_pytest_model import (
    NODE_BUILD_OUTPUT_PROFILE_VERSION,
    NODE_TOOL_READ_ONLY_PROFILE_VERSION,
    RestrictedPytestError,
    RestrictedPytestPlan,
)
from .restricted_pytest_validation import _normalized_command, _path_is_within
from .restricted_vite_output import config_bundle_directory, declared_vite_output
from .restricted_vitest import run_restricted_node_plan
from .secret_sensitivity import classify_secret_path

_ENTRIES = {"eslint": "eslint/bin/eslint.js", "tsc": "typescript/bin/tsc", "vite": "vite/bin/vite.js"}


def is_local_package_entry(argument: str, package_entry: str) -> bool:
    """`node_modules/<entry>`, `./node_modules/<entry>` or `<dir>/node_modules/<entry>`."""
    prefix = argument.removesuffix("node_modules/" + package_entry)
    return prefix != argument and (prefix == "" or prefix.endswith("/"))


def _package_directory(directory: Path, workspace: Path) -> bool:
    """The workspace root, or a package directory below it reached without links."""
    if directory == workspace:
        return True
    if not _path_is_within(directory, workspace) or not (directory / "package.json").is_file():
        return False
    parts = directory.relative_to(workspace).parts
    if any(part.startswith(".") or part == "node_modules" for part in parts):
        return False
    return not any((workspace.joinpath(*parts[: index + 1])).is_symlink() for index in range(len(parts)))


def _is_real_directory(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    return stat.S_ISDIR(info.st_mode)


def _reached_without_links(path: Path, workspace: Path) -> bool:
    """True when `path` is a real directory and no component up to `workspace` is a link."""
    if not _path_is_within(path, workspace):
        return False
    try:
        boundary = workspace.resolve()
    except OSError:
        return False
    current = path
    while True:
        if not _is_real_directory(current):
            return False
        try:
            here = current.resolve()
        except OSError:
            return False
        if here == boundary:
            return True
        if boundary not in here.parents:
            return False
        parent = current.parent
        if parent == current:
            return False
        current = parent


def _create_vite_temp_directory(root: Path, workspace: Path) -> None:
    """Create Vite's bundle directory only as a real directory under the workspace."""
    parent = root.parent
    if root.is_symlink() or not _reached_without_links(parent, workspace):
        raise RestrictedPytestError(
            "node_build_invalid_output",
            "Vite's config bundle directory is not a real directory inside the project.",
        )
    root.mkdir(mode=0o755, exist_ok=True)
    if not _is_real_directory(root):
        raise RestrictedPytestError(
            "node_build_invalid_output",
            "Vite's config bundle directory is not a real directory inside the project.",
        )


def _conventional_output(path: Path, workspace: Path) -> bool:
    # A package below the workspace (a monorepo app reached with `cd`) builds
    # into its own dist, next to its package.json.
    return _package_directory(path.parent, workspace) and path.name in {"dist", "build", "out"}


def validate_build_output_root(path: Path, *, workspace: Path, cwd: Path | None = None) -> None:
    """Accept a conventional build directory, or the literal one the Vite config in `cwd` names."""
    bundle = cwd is not None and not path.is_symlink() and config_bundle_directory(cwd, workspace, path.parent) == path
    conventional = _conventional_output(path, workspace)
    # A config that names a non-literal outDir raises. Check the bundle
    # directory first so that recheck does not refuse a command-line --outDir.
    declared = not bundle and not conventional and cwd is not None and declared_vite_output(cwd, workspace) == path
    if path.is_symlink() or not (conventional or declared or bundle):
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
    runtime_args: tuple[str, ...] = ()
    if name == "bun" and args[:1] == ("x",):
        # `bun x` is Bun's spelling of `bunx`.
        name, args = "bunx", args[1:]
    if name in {"bun", "npm", "pnpm"}:
        if len(args) != 2 or args[0] != "run" or args[1] not in {"lint", "typecheck", "build"}:
            raise RestrictedPytestError(
                "node_tool_invalid_command", "Only direct lint/typecheck scripts are supported."
            )
        package = nearest_project_root(cwd or workspace, workspace, "package.json")
        manifest, _digest = read_json_with_integrity(package / "package.json")
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
        if args and args[0].startswith("--max-old-space-size="):
            value = args[0].partition("=")[2]
            if not value.isascii() or not value.isdecimal() or not 16 <= int(value) <= 131072:
                raise RestrictedPytestError("node_tool_invalid_command", "Invalid bounded Node memory option.")
            runtime_args, args = (args[0],), args[1:]
        if not args:
            raise RestrictedPytestError("node_tool_invalid_command", "Missing local entrypoint.")
        expected_entry = Path(args[0])
        name = next((tool for tool, entry in _ENTRIES.items() if is_local_package_entry(args[0], entry)), "")
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
        output_name = None
        for index, value in enumerate(args):
            if value.startswith("--outDir="):
                output_name = value.removeprefix("--outDir=")
            elif value == "--outDir":
                if index + 1 >= len(args):
                    raise RestrictedPytestError("node_build_invalid_output", "Missing output directory.")
                output_name = args[index + 1]
        explicit_config = any(value in {"-c", "--config"} or value.startswith("--config=") for value in args)
        declared = None if output_name or explicit_config else declared_vite_output(base.cwd, base.workspace)
        output = declared or base.cwd / (output_name or "dist")
        validate_build_output_root(output, workspace=base.workspace, cwd=None if declared is None else base.cwd)
        output_roots = (output,)
    try:
        modules = nearest_project_root(base.cwd, base.workspace, "node_modules/" + _ENTRIES[name]) / "node_modules"
        entry = (modules / _ENTRIES[name]).resolve(strict=True)
        if not entry.is_file() or not _path_is_within(entry, modules):
            raise OSError("external tool entrypoint")
        # A relative entrypoint names a file below the command's directory.
        if expected_entry is not None and (base.cwd / expected_entry).resolve(strict=True) != entry:
            raise OSError("unexpected tool entrypoint")
    except (OSError, RuntimeError) as error:
        raise RestrictedPytestError(
            "node_tool_dependency_unavailable",
            "The local lint/typecheck tool is unavailable; no replacement was downloaded.",
        ) from error
    if name == "vite" and not any(value == "--configLoader" or value.startswith("--configLoader=") for value in args):
        explicit_config = any(value in {"-c", "--config"} or value.startswith("--config=") for value in args)
        bundle = None if explicit_config else config_bundle_directory(base.cwd, base.workspace, modules)
        if bundle is None:
            args = (*args, "--configLoader", "runner")
        else:
            output_roots = (*output_roots, bundle)
    return replace(
        base,
        profile_version=NODE_BUILD_OUTPUT_PROFILE_VERSION if name == "vite" else NODE_TOOL_READ_ONLY_PROFILE_VERSION,
        command=(str(base.executable), *runtime_args, str(entry), *args),
        output_roots=output_roots,
        denied_capabilities=tuple(
            "workspace-source-write" if name == "vite" and value == "workspace-write" else value
            for value in base.denied_capabilities
        ),
    )


def run_restricted_node_tool(
    plan: RestrictedPytestPlan,
    *,
    timeout_seconds: int,
    authorize_capability: Callable[[tuple[str, ...]], None] | None = None,
    merge_stderr: bool = False,
) -> int:
    for root in plan.output_roots:
        # Vite creates this directory itself; a sandbox grant needs it first.
        if root.name == ".vite-temp":
            _create_vite_temp_directory(root, plan.workspace)
    return run_restricted_node_plan(
        plan,
        timeout_seconds=timeout_seconds,
        authorize_capability=authorize_capability,
        merge_stderr=merge_stderr,
    )
