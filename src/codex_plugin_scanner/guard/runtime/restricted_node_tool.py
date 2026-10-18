"""Local lint/typecheck resolution under the enforced read-only Node profile."""

from __future__ import annotations

import os
import shlex
import stat
import sys
from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path, PureWindowsPath

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

# Each tool names the entrypoints its published versions install. Prettier 3
# moved its executable into `bin/`, and version 2 remains common enough to name.
_ENTRIES: dict[str, tuple[str, ...]] = {
    "eslint": ("eslint/bin/eslint.js",),
    "tsc": ("typescript/bin/tsc",),
    "vite": ("vite/bin/vite.js",),
    "prettier": ("prettier/bin/prettier.cjs", "prettier/bin-prettier.js"),
}
# Prettier reports in these two modes and rewrites files in every other one.
_PRETTIER_CHECKS = {"--check", "-c", "--list-different", "-l"}

# How much longer than the build's own deadline this waits for the native
# runner. The runner counts that deadline against the build alone: staging a
# private copy of the workspace and publishing the output roots both happen
# outside it. Killing the runner on the same number would land in the middle of
# publishing, with the previous output already removed and the new one half
# written, and would leave the staged copy behind. The runner stops the build
# itself, so this only has to outlast the copying around it.
_WINDOWS_BUILD_GRACE_SECONDS = 120


def _program_name(argument: str) -> str:
    """The program the command names, without the image extension Windows adds.

    A harness on Windows hands over the resolved `node.exe`, which is the
    program `node`. The pre-tool scan reads it that way, so the sink has to
    parse the same command the receipt was written for. Elsewhere a trailing
    `.exe` is part of an ordinary file name and stays.
    """
    if sys.platform != "win32":
        return Path(argument).name
    name = PureWindowsPath(argument).name
    stem, dot, extension = name.rpartition(".")
    if dot and stem and extension.lower() == "exe":
        # CreateProcess resolves images without regard to case, and the
        # receipt compares the program against its lowercase spelling.
        return stem.lower()
    return name


def is_local_package_entry(argument: str, package_entry: str) -> bool:
    """`node_modules/<entry>`, `./node_modules/<entry>` or `<dir>/node_modules/<entry>`."""
    prefix = argument.removesuffix("node_modules/" + package_entry)
    return prefix != argument and (prefix == "" or prefix.endswith("/"))


def _tool_entry(name: str, cwd: Path, workspace: Path) -> tuple[Path, str]:
    """The `node_modules` directory holding the tool and its path below it.

    A tool may publish its executable under more than one name across major
    versions, so look for every spelling and keep the one the nearest project
    installs: a package that pins its own major is what the command would run,
    not a copy hoisted further up a monorepo. When no project has any of them,
    name the first spelling so the caller reports a missing dependency.
    """
    installed = []
    for relative in _ENTRIES[name]:
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
    first = _ENTRIES[name][0]
    return nearest_project_root(cwd, workspace, "node_modules/" + first) / "node_modules", first


# Subcommands pnpm and Yarn classic run themselves. Both only fall back to a
# manifest script when the bare word is not one of their own, so a project that
# defines a `check` or `exec` script does not change what `yarn check` or
# `pnpm exec` runs. `test` and `start` are left out: those two are the script.
_MANAGER_SUBCOMMANDS = frozenset(
    {
        "add",
        "audit",
        "autoclean",
        "bin",
        "cache",
        "check",
        "config",
        "create",
        "dedupe",
        "deploy",
        "dlx",
        "doctor",
        "env",
        "exec",
        "fetch",
        "generate-lock-entry",
        "global",
        "help",
        "i",
        "import",
        "info",
        "init",
        "install",
        "licenses",
        "link",
        "list",
        "login",
        "logout",
        "ls",
        "node",
        "outdated",
        "owner",
        "pack",
        "patch",
        "pkg",
        "policies",
        "prune",
        "publish",
        "rebuild",
        "remove",
        "rm",
        "root",
        "run",
        "server",
        "setup",
        "store",
        "tag",
        "team",
        "unlink",
        "unplug",
        "up",
        "update",
        "upgrade",
        "upgrade-interactive",
        "version",
        "versions",
        "why",
        "whoami",
        "workspace",
        "workspaces",
    }
)


def _script_task(manager: str, args: Sequence[str]) -> str | None:
    """The script a package-manager command names.

    npm and Bun need the explicit `run`. pnpm and Yarn also run a script named
    directly, and a project that documents `pnpm lint` or `yarn build` means
    the same script, so both spellings resolve the same way here. The name the
    project chose decides nothing: the body behind it still has to be one of
    the tools below, in a mode that only reports.
    """
    if len(args) == 2 and args[0] == "run":
        return args[1]
    if len(args) == 1 and manager in {"pnpm", "yarn"} and args[0] not in _MANAGER_SUBCOMMANDS:
        return args[0]
    return None


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


def _prepare_windows_build(
    name: str,
    args: Sequence[str],
    runtime_args: Sequence[str],
    expected_entry: Path | None,
    *,
    workspace: Path,
    cwd: Path,
) -> RestrictedPytestPlan:
    """Windows stages the build in an AppContainer; the resident resolves Node and Vite.

    The private copy is writable, so Vite bundles its config in place and no
    config loader or bundle directory is added.
    """
    if name != "vite":
        raise RestrictedPytestError(
            PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE, "Only Vite builds run contained on Windows."
        )
    result = restricted_native(
        "prepare_node_build",
        {
            "workspace": workspace,
            "cwd": cwd,
            "runtime_arguments": list(runtime_args),
            "arguments": list(args),
            "expected_entry": None if expected_entry is None else expected_entry.as_posix(),
        },
        dict,
    )
    plan = decode_native_plan(result, (NODE_BUILD_OUTPUT_PROFILE_VERSION,))
    return replace(plan, output_roots=(_vite_output(args, workspace=plan.workspace, cwd=plan.cwd),))


def prepare_restricted_node_tool(
    command: Sequence[str], *, workspace: Path, cwd: Path | None = None
) -> RestrictedPytestPlan:
    argv = _normalized_command(command)
    name, args = _program_name(argv[0]), argv[1:]
    expected_entry = None
    runtime_args: tuple[str, ...] = ()
    if name == "bun" and args[:1] == ("x",):
        # `bun x` is Bun's spelling of `bunx`.
        name, args = "bunx", args[1:]
    if name == "pnpm" and args[:1] == ("exec",):
        # `pnpm exec` is pnpm's spelling of a local-bin run. A pnpm option before
        # the tool (`-c` runs a shell, `-r`/`--filter` fan out) is not accepted.
        if len(args) < 2 or args[1].startswith("-"):
            raise RestrictedPytestError("node_tool_invalid_command", "Missing local runner.")
        name, args = args[1], args[2:]
    elif name in {"bun", "npm", "pnpm", "yarn"}:
        task = _script_task(name, args)
        if task is None:
            raise RestrictedPytestError("node_tool_invalid_command", "Only a single named package script is supported.")
        if sys.platform == "win32":
            raise RestrictedPytestError(
                PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE, "Package scripts do not run contained on Windows yet."
            )
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
        name = next(
            (
                tool
                for tool, entries in _ENTRIES.items()
                if any(is_local_package_entry(args[0], entry) for entry in entries)
            ),
            "",
        )
        args = args[1:]
    if (
        name not in _ENTRIES
        or (name == "tsc" and "--noEmit" not in args)
        or (name == "vite" and (not args or args[0] != "build"))
        or (name == "prettier" and not _PRETTIER_CHECKS.intersection(args))
    ):
        raise RestrictedPytestError(
            "node_tool_invalid_command",
            "Only local ESLint, no-emit TypeScript and Prettier in a checking mode are supported.",
        )
    if any(
        token
        in {
            ";",
            "&&",
            "||",
            "|",
            "|&",
            "&",
            "--fix",
            "--fix-dry-run",
            "--output-file",
            "-o",
            "--emitDeclarationOnly",
            "--write",
            "-w",
        }
        # A value spelling enables the same write: `--write=true` turns
        # Prettier's rewrite on just as `--write` does.
        or token.startswith(("--fix=", "--output-file=", "--write="))
        for token in args
    ):
        raise RestrictedPytestError("node_tool_invalid_command", "The lint/typecheck input has write or shell effects.")
    if sys.platform == "win32":
        return _prepare_windows_build(
            name, args, runtime_args, expected_entry, workspace=workspace, cwd=cwd or workspace
        )
    base = prepare_restricted_node_test(["node", "--test"], workspace=workspace, cwd=cwd)
    output_roots = ()
    if name == "vite":
        output_roots = (_vite_output(args, workspace=base.workspace, cwd=base.cwd),)
    try:
        modules, relative = _tool_entry(name, base.cwd, base.workspace)
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
    if plan.backend == "windows-appcontainer":
        return _run_windows_node_build(plan, timeout_seconds=timeout_seconds, merge_stderr=merge_stderr)
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


def _run_windows_node_build(plan: RestrictedPytestPlan, *, timeout_seconds: int, merge_stderr: bool) -> int:
    """The native runner stages the build and publishes only the output roots."""
    if (
        sys.platform != "win32"
        or plan.profile_version != NODE_BUILD_OUTPUT_PROFILE_VERSION
        or not plan.output_roots
        or not 0 < timeout_seconds <= 86400
    ):
        raise RestrictedPytestError("node_tool_invalid_command", "Unexpected protected build plan.")
    outputs = [option for root in plan.output_roots for option in ("--output", str(root))]
    argv = [
        str(plan.backend_executable),
        "contained-readonly-windows",
        "--profile",
        NODE_BUILD_OUTPUT_PROFILE_VERSION,
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
        timeout_seconds=timeout_seconds + _WINDOWS_BUILD_GRACE_SECONDS,
        cwd=plan.cwd,
        merge_stderr=merge_stderr,
    )
