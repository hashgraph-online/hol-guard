"""Local lint/typecheck resolution under the enforced read-only Node profile."""

from __future__ import annotations

import os
import shlex
import stat
import sys
from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path
from typing import NamedTuple

from ..native_restricted_pytest import decode_native_plan, restricted_native
from .package_evidence_common import read_json_with_integrity
from .restricted_node_test import nearest_project_root, prepare_restricted_node_test
from .restricted_pytest_model import (
    NODE_BUILD_OUTPUT_PROFILE_VERSION,
    NODE_TOOL_READ_ONLY_PROFILE_VERSION,
    PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE,
    RestrictedPytestError,
    RestrictedPytestPlan,
)
from .restricted_pytest_sandbox import _run_backend_process
from .restricted_pytest_validation import _normalized_command, _path_is_within
from .restricted_vite_output import config_bundle_directory, declared_vite_output
from .restricted_vitest import run_restricted_node_plan
from .secret_sensitivity import classify_secret_path

# How much longer than the run's own deadline this waits for the native
# runner. The runner counts that deadline against the tool alone: staging a
# private copy of the workspace and publishing a build's output roots both
# happen outside it. Killing the runner on the same number would land in the
# middle of publishing, with the previous output already removed and the new
# one half written, and would leave the staged copy behind.
_WINDOWS_STAGING_GRACE_SECONDS = 120


def _tool_entry(entries: Sequence[str], cwd: Path, workspace: Path) -> tuple[Path, str]:
    """The `node_modules` directory holding the tool and its path below it.

    A tool may publish its executable under more than one name across major
    versions, so look for every spelling and keep the one the nearest project
    installs: a package that pins its own major is what the command would run,
    not a copy hoisted further up a monorepo. When no project has any of them,
    name the first spelling so the caller reports a missing dependency.
    """
    installed = []
    for relative in entries:
        try:
            modules = nearest_project_root(cwd, workspace, "node_modules/" + relative) / "node_modules"
        except OSError:
            continue
        if (modules / relative).is_file():
            installed.append((len(modules.parts), modules, relative))
    if installed:
        # Deepest wins, and a tie keeps the order the spellings are declared in.
        depth = max(entry[0] for entry in installed)
        _, modules, relative = next(entry for entry in installed if entry[0] == depth)
        return modules, relative
    first = entries[0]
    return nearest_project_root(cwd, workspace, "node_modules/" + first) / "node_modules", first


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


def _explicit_vite_config(args: Sequence[str], cwd: Path) -> Path | None:
    """The last `--config` file, relative to the build's working directory."""

    chosen: str | None = None
    index = 0
    while index < len(args):
        value = args[index]
        if value in {"-c", "--config"}:
            if index + 1 >= len(args) or args[index + 1].startswith("-"):
                raise RestrictedPytestError("node_build_invalid_output", "Missing Vite config.")
            chosen = args[index + 1]
            index += 2
            continue
        if value.startswith("--config="):
            chosen = value.removeprefix("--config=")
            if not chosen:
                raise RestrictedPytestError("node_build_invalid_output", "Missing Vite config.")
        index += 1
    if chosen is None:
        return None
    path = Path(chosen)
    return path if path.is_absolute() else cwd / path


def _vite_output(args: Sequence[str], *, workspace: Path, cwd: Path) -> Path:
    """The build's last `--outDir`, else the config's literal one, else `dist`."""
    output_name = None
    for index, value in enumerate(args):
        if value.startswith("--outDir="):
            output_name = value.removeprefix("--outDir=")
        elif value == "--outDir":
            if index + 1 >= len(args):
                raise RestrictedPytestError("node_build_invalid_output", "Missing output directory.")
            output_name = args[index + 1]
    # `--outDir` wins. Otherwise read the config the command names, or the
    # default vite.config.* when it names none. Skipping a named config used
    # to grant `dist` while Vite wrote the directory that file declared.
    declared = None if output_name else declared_vite_output(cwd, workspace, config=_explicit_vite_config(args, cwd))
    output = declared or cwd / (output_name or "dist")
    validate_build_output_root(output, workspace=workspace, cwd=None if declared is None else cwd)
    return output


def _prepare_windows_tool(
    name: str,
    args: Sequence[str],
    runtime_args: Sequence[str],
    expected_entry: Path | None,
    *,
    build: bool,
    workspace: Path,
    cwd: Path,
) -> RestrictedPytestPlan:
    """Windows stages the run in an AppContainer; the resident resolves Node and the tool.

    The private copy is writable, so Vite bundles its config in place and no
    config loader or bundle directory is added, and ESLint, TypeScript and
    Prettier write their caches where they expect them. Only a build names an
    output root; a reporting run declares none and its copy is discarded whole.
    """
    result = restricted_native(
        "prepare_node_build",
        {
            "workspace": workspace,
            "cwd": cwd,
            "tool": name,
            "runtime_arguments": list(runtime_args),
            "arguments": list(args),
            "expected_entry": None if expected_entry is None else expected_entry.as_posix(),
        },
        dict,
    )
    profile = NODE_BUILD_OUTPUT_PROFILE_VERSION if build else NODE_TOOL_READ_ONLY_PROFILE_VERSION
    plan = decode_native_plan(result, (profile,))
    if not build:
        return plan
    return replace(plan, output_roots=(_vite_output(args, workspace=plan.workspace, cwd=plan.cwd),))


class _ScriptRoute(NamedTuple):
    """A manager run that names one of the project's own scripts."""

    task: str


class _ToolRoute(NamedTuple):
    """A supported tool run, with the arguments and mode native authority read."""

    name: str
    arguments: tuple[str, ...]
    runtime_arguments: tuple[str, ...]
    expected_entry: str | None
    entries: tuple[str, ...]
    build: bool


def _native_route(command: Sequence[str], script_body: Sequence[str] | None) -> _ScriptRoute | _ToolRoute:
    """The route the classifier already read out of this command.

    The spelling, the tool it names and the mode gate are one reading in the
    native runtime, so the sink never recomputes a verdict the pre-tool scan
    has already produced. A reply this side cannot read is unavailability, not
    a weaker plan.
    """
    reply = restricted_native(
        "node_tool_route",
        {
            "command": list(command),
            "script_body": None if script_body is None else list(script_body),
            "windows": sys.platform == "win32",
        },
        dict,
    )
    kind, task = reply.get("kind"), reply.get("task")
    if kind == "script" and isinstance(task, str) and task:
        return _ScriptRoute(task)
    name, mode, entry = reply.get("name"), reply.get("mode"), reply.get("expected_entry")
    entries, arguments, runtime = reply.get("entries"), reply.get("arguments"), reply.get("runtime_arguments")
    if (
        kind == "tool"
        and isinstance(name, str)
        and mode in {"report", "build"}
        and (entry is None or isinstance(entry, str))
        and isinstance(entries, list)
        and entries
        and isinstance(arguments, list)
        and isinstance(runtime, list)
        and all(isinstance(value, str) for value in (*entries, *arguments, *runtime))
    ):
        return _ToolRoute(name, tuple(arguments), tuple(runtime), entry, tuple(entries), mode == "build")
    raise RestrictedPytestError(
        PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE,
        "Native restricted execution preparation is unavailable (node_tool_route); execution was not started.",
    )


def _script_body(task: str, *, workspace: Path, cwd: Path | None) -> tuple[str, ...]:
    """The words of the named script, read from the nearest project's manifest."""
    package = nearest_project_root(cwd or workspace, workspace, "package.json")
    manifest, _digest = read_json_with_integrity(package / "package.json")
    scripts = manifest.get("scripts") if isinstance(manifest, dict) else None
    if isinstance(scripts, dict) and any(scripts.get(phase + task) for phase in ("pre", "post")):
        raise RestrictedPytestError(
            "node_tool_invalid_command", "This script has lifecycle actions that need separate evaluation."
        )
    script = scripts.get(task) if isinstance(scripts, dict) else None
    if not isinstance(script, str):
        raise RestrictedPytestError("node_tool_invalid_command", "The requested local script is unavailable.")
    try:
        return tuple(shlex.split(script))
    except ValueError as error:
        raise RestrictedPytestError("node_tool_invalid_command", "The local script could not be parsed.") from error


def prepare_restricted_node_tool(
    command: Sequence[str], *, workspace: Path, cwd: Path | None = None, home_dir: Path | None = None
) -> RestrictedPytestPlan:
    argv = _normalized_command(command)
    route = _native_route(argv, None)
    if isinstance(route, _ScriptRoute):
        # Only the manifest read is this side's work: the script's own words go
        # back to the classifier, which gates them as the run they spell.
        route = _native_route(argv, _script_body(route.task, workspace=workspace, cwd=cwd))
    if isinstance(route, _ScriptRoute):
        raise RestrictedPytestError("node_tool_invalid_command", "Only a single named package script is supported.")
    name, args, runtime_args, entries, build = (
        route.name,
        route.arguments,
        route.runtime_arguments,
        route.entries,
        route.build,
    )
    expected_entry = None if route.expected_entry is None else Path(route.expected_entry)
    if sys.platform == "win32":
        return _prepare_windows_tool(
            name, args, runtime_args, expected_entry, build=build, workspace=workspace, cwd=cwd or workspace
        )
    base = prepare_restricted_node_test(["node", "--test"], workspace=workspace, cwd=cwd, home_dir=home_dir)
    output_roots = ()
    if build:
        output_roots = (_vite_output(args, workspace=base.workspace, cwd=base.cwd),)
    try:
        modules, relative = _tool_entry(entries, base.cwd, base.workspace)
        entry = (modules / relative).resolve(strict=True)
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
    if build and not any(value == "--configLoader" or value.startswith("--configLoader=") for value in args):
        explicit_config = any(value in {"-c", "--config"} or value.startswith("--config=") for value in args)
        bundle = None if explicit_config else config_bundle_directory(base.cwd, base.workspace, modules)
        if bundle is None:
            args = (*args, "--configLoader", "runner")
        else:
            output_roots = (*output_roots, bundle)
    return replace(
        base,
        profile_version=NODE_BUILD_OUTPUT_PROFILE_VERSION if build else NODE_TOOL_READ_ONLY_PROFILE_VERSION,
        command=(str(base.executable), *runtime_args, str(entry), *args),
        output_roots=output_roots,
        denied_capabilities=tuple(
            "workspace-source-write" if build and value == "workspace-write" else value
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
    if plan.backend == "windows-appcontainer":
        return _run_windows_node_tool(plan, timeout_seconds=timeout_seconds, merge_stderr=merge_stderr)
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


def _run_windows_node_tool(plan: RestrictedPytestPlan, *, timeout_seconds: int, merge_stderr: bool) -> int:
    """The native runner stages the run and publishes only the output roots.

    A build names those roots; a reporting run names none, so its staged copy
    leaves no trace in the workspace at all.
    """
    build = plan.profile_version == NODE_BUILD_OUTPUT_PROFILE_VERSION
    if (
        sys.platform != "win32"
        or plan.profile_version not in {NODE_BUILD_OUTPUT_PROFILE_VERSION, NODE_TOOL_READ_ONLY_PROFILE_VERSION}
        or bool(plan.output_roots) != build
        or not 0 < timeout_seconds <= 86400
    ):
        raise RestrictedPytestError("node_tool_invalid_command", "Unexpected protected run plan.")
    outputs = [option for root in plan.output_roots for option in ("--output", str(root))]
    argv = [
        str(plan.backend_executable),
        "contained-readonly-windows",
        "--profile",
        plan.profile_version,
        "--workspace",
        str(plan.workspace),
        "--cwd",
        str(plan.cwd),
        "--timeout-seconds",
        str(timeout_seconds),
        *outputs,
        "--",
        *plan.command,
    ]
    return _run_backend_process(
        argv,
        env=os.environ,
        timeout_seconds=timeout_seconds + _WINDOWS_STAGING_GRACE_SECONDS,
        cwd=plan.cwd,
        merge_stderr=merge_stderr,
    )
