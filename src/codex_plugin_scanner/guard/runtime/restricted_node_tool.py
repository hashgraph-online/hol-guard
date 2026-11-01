"""Local lint/typecheck resolution under the enforced read-only Node profile."""

from __future__ import annotations

import os
import stat
import sys
from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path
from typing import NamedTuple

from ..native_restricted_pytest import decode_native_plan, native_launch_plan, restricted_native
from .package_evidence_common import read_json_with_integrity
from .restricted_node_test import nearest_project_root
from .restricted_pytest_model import (
    NODE_BUILD_OUTPUT_PROFILE_VERSION,
    NODE_TOOL_READ_ONLY_PROFILE_VERSION,
    PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE,
    RestrictedPytestError,
    RestrictedPytestPlan,
)
from .restricted_pytest_sandbox import _run_backend_process
from .restricted_pytest_validation import _normalized_command, _path_is_within
from .restricted_vitest import run_restricted_node_plan

# How much longer than the run's own deadline this waits for the native
# runner. The runner counts that deadline against the tool alone: staging a
# private copy of the workspace and publishing a build's output roots both
# happen outside it. Killing the runner on the same number would land in the
# middle of publishing, with the previous output already removed and the new
# one half written, and would leave the staged copy behind.
_WINDOWS_STAGING_GRACE_SECONDS = 120


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


def validate_build_output_root(
    path: Path,
    *,
    workspace: Path,
    cwd: Path | None = None,
    arguments: Sequence[str] | None = None,
) -> None:
    """Ask native authority whether a build may write this directory.

    The reading is a verdict — a conventional `dist` beside a package
    manifest, the config loader's own bundle directory, or the literal
    directory the Vite config the command loads names, and nothing already
    there that emptying the directory would destroy or write through. The
    sandbox asks again just before it launches, so a plan cannot be granted
    one directory and started against another, and both askings read the same
    native answer.

    `arguments` are the command's own words. They travel with the question so
    native authority reads the config the build names rather than the default
    one beside it, which would refuse the directory the named config declares.
    """
    fields: dict[str, object] = {"path": path, "workspace": workspace}
    if cwd is not None:
        fields["cwd"] = cwd
    if arguments is not None:
        fields["arguments"] = list(arguments)
    restricted_native("node_build_output_admissible", fields, (bool,))


def _vite_output(args: Sequence[str], *, workspace: Path, cwd: Path) -> Path:
    """The one directory this build may write, as native authority reads it.

    The command's own `--outDir`, the config it names, and the admissibility
    of what that reading lands on are one native answer, so the words the
    build was given and the grant it receives cannot drift apart.
    """
    return Path(
        restricted_native(
            "node_build_output_root",
            {"arguments": list(args), "workspace": workspace, "cwd": cwd},
            (str,),
        )
    )


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


def _native_route(
    command: Sequence[str],
    script_body: Sequence[str] | None,
    *,
    cwd: Path,
) -> _ScriptRoute | _ToolRoute:
    """The route the classifier already read out of this command.

    The spelling, the tool it names and the mode gate are one reading in the
    native runtime, so the sink never recomputes a verdict the pre-tool scan
    has already produced. A reply this side cannot read is unavailability, not
    a weaker plan.

    The run directory travels with the request: a `tsc` run reads its no-emit
    mode from the project it names, so the route has to see the same project
    the run will, exactly as the admission that let it through did.
    """
    reply = restricted_native(
        "node_tool_route",
        {
            "command": list(command),
            "script_body": None if script_body is None else list(script_body),
            "windows": sys.platform == "win32",
            "cwd": str(cwd),
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
    # Reading a script into the words a run will execute is a reading of a
    # command, so the sink asks native authority for it rather than splitting
    # the text a second way.
    return tuple(restricted_native("script_words", {"script": script}, list))


def prepare_restricted_node_tool(
    command: Sequence[str], *, workspace: Path, cwd: Path | None = None, home_dir: Path | None = None
) -> RestrictedPytestPlan:
    if sys.platform == "win32":
        return _prepare_windows_route(command, workspace=workspace, cwd=cwd or workspace)
    # The route, a package script's own words, the tool's entrypoint in the
    # nearest `node_modules` and a build's output directory are one native
    # reading, so the plan cannot name a tool the classifier did not read.
    return native_launch_plan(
        "prepare_node_tool",
        command,
        workspace=workspace,
        cwd=cwd or workspace,
        home_dir=home_dir,
        platform=sys.platform,
        backend_executable=None,
        profile=(NODE_BUILD_OUTPUT_PROFILE_VERSION, NODE_TOOL_READ_ONLY_PROFILE_VERSION),
    )


def _prepare_windows_route(command: Sequence[str], *, workspace: Path, cwd: Path) -> RestrictedPytestPlan:
    argv = _normalized_command(command)
    route = _native_route(argv, None, cwd=cwd)
    if isinstance(route, _ScriptRoute):
        # Only the manifest read is this side's work: the script's own words go
        # back to the classifier, which gates them as the run they spell.
        route = _native_route(
            argv, _script_body(route.task, workspace=workspace, cwd=cwd), cwd=cwd
        )
    if isinstance(route, _ScriptRoute):
        raise RestrictedPytestError("node_tool_invalid_command", "Only a single named package script is supported.")
    expected_entry = None if route.expected_entry is None else Path(route.expected_entry)
    return _prepare_windows_tool(
        route.name,
        route.arguments,
        route.runtime_arguments,
        expected_entry,
        build=route.build,
        workspace=workspace,
        cwd=cwd,
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
