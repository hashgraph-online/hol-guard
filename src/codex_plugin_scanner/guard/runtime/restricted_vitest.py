"""Locally installed Vitest execution: no npx/bunx downloads or shell fallback."""

from __future__ import annotations

import json
import os
import stat
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from pathlib import Path

from .restricted_node_capabilities import linux_node_environment
from .restricted_node_test import _node_runtime_args, nearest_project_root, prepare_restricted_node_test
from .restricted_pytest_model import (
    NODE_BUILD_OUTPUT_PROFILE_VERSION,
    NODE_TOOL_READ_ONLY_PROFILE_VERSION,
    VITEST_READ_ONLY_PROFILE_VERSION,
    RestrictedPytestError,
    RestrictedPytestPlan,
)
from .restricted_pytest_sandbox import _backend_argv, _restricted_environment, _run_backend_process
from .restricted_pytest_validation import _normalized_command, _path_is_within


def bun_vitest_invocation(command: Sequence[str]) -> tuple[str | None, tuple[str, ...]] | None:
    """Recognize Bun's direct x wrapper, optionally with a leading cwd, or bunx with one."""
    if not command or Path(command[0]).name not in {"bun", "bunx"}:
        return None
    bunx = Path(command[0]).name == "bunx"
    args = tuple(command[1:])
    directory = None
    if args and args[0] == "--cwd":
        if len(args) < 2 or not args[1] or args[1].startswith("-"):
            return None
        directory, args = args[1], args[2:]
    elif args and args[0].startswith("--cwd="):
        directory, args = args[0][6:], args[1:]
        if not directory:
            return None
    if bunx:
        if directory is None:
            return None
    elif not args or args[0] != "x":
        return None
    else:
        args = args[1:]
    if args and args[0] == "--no-install":
        args = args[1:]
    if len(args) < 2 or args[:2] != ("vitest", "run"):
        return None
    return directory, args[1:]


def vitest_arguments(command: Sequence[str]) -> tuple[str, ...]:
    argv = _normalized_command(command)
    name = Path(argv[0]).name
    runtime_args = _node_runtime_args(argv)
    if name in {"bun", "bunx"} and (invocation := bun_vitest_invocation(argv)) is not None:
        args = invocation[1]
    elif name in {"bunx", "npx"}:
        args = argv[1:]
        if args and args[0] == "--no-install":
            args = args[1:]
        if not args or args[0] != "vitest":
            raise RestrictedPytestError("vitest_restricted_invalid_command", "Only local Vitest run is supported.")
        args = args[1:]
    elif name == "vitest":
        args = argv[1:]
    elif name in {"node", "nodejs"}:
        node_args = argv[1 + len(runtime_args) :]
        if len(node_args) < 2 or not node_args[0].endswith("/node_modules/vitest/vitest.mjs"):
            raise RestrictedPytestError("vitest_restricted_invalid_command", "Only local Vitest run is supported.")
        args = node_args[1:]
    else:
        raise RestrictedPytestError("vitest_restricted_invalid_command", "Only local Vitest run is supported.")
    if not args or args[0] != "run" or any(item in {";", "&&", "||", "|", "|&", "&"} for item in args):
        raise RestrictedPytestError("vitest_restricted_invalid_command", "Protected Vitest requires direct run argv.")
    return tuple(args)


def prepare_restricted_vitest(
    command: Sequence[str], *, workspace: Path, cwd: Path | None = None
) -> RestrictedPytestPlan:
    args = vitest_arguments(command)
    runtime_args = _node_runtime_args(command)
    invocation = bun_vitest_invocation(command)
    if invocation is not None and invocation[0] is not None:
        # Resolve against the original hook cwd, not the daemon's process cwd.
        target = Path(invocation[0]).expanduser()
        if not target.is_absolute():
            target = (cwd or workspace) / target
        try:
            original = workspace.resolve(strict=True)
            cwd = target.resolve(strict=True)
            if not cwd.is_dir():
                raise OSError("not a directory")
            if Path(command[0]).name == "bunx" and not _path_is_within(cwd, original):
                raise OSError("outside the workspace")
        except (OSError, RuntimeError) as error:
            raise RestrictedPytestError(
                "vitest_restricted_invalid_command", "Vitest working directory is unavailable."
            ) from error
        if not _path_is_within(cwd, original):
            workspace = cwd
    plan = prepare_restricted_node_test(["node", "--test"], workspace=workspace, cwd=cwd)
    try:
        # Keep the approved root: a package directory may rely on hoisted dependencies.
        modules = nearest_project_root(plan.cwd, plan.workspace, "node_modules/vitest/vitest.mjs") / "node_modules"
        entry = (modules / "vitest" / "vitest.mjs").resolve(strict=True)
        if not entry.is_file() or not _path_is_within(entry, modules):
            raise OSError("invalid local Vitest entrypoint")
        if (
            Path(command[0]).name in {"node", "nodejs"}
            and Path(command[1 + len(runtime_args)]).resolve(strict=True) != entry
        ):
            raise OSError("unexpected Vitest entrypoint")
    except (OSError, RuntimeError) as error:
        raise RestrictedPytestError(
            "vitest_restricted_dependency_unavailable",
            "Vitest is not installed inside this workspace. Guard did not download or execute a replacement.",
        ) from error
    args = _readonly_config_arguments(args, entry.parent / "package.json")
    return replace(
        plan,
        profile_version=VITEST_READ_ONLY_PROFILE_VERSION,
        command=(str(plan.executable), *runtime_args, str(entry), *args),
    )


def _readonly_config_arguments(args: tuple[str, ...], manifest: Path) -> tuple[str, ...]:
    """Avoid Vite's source-tree config bundle without overriding explicit loaders."""
    if any(value == "--configLoader" or value.startswith("--configLoader=") for value in args):
        return args
    try:
        descriptor = os.open(manifest, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                return args
            raw = handle.read(65537)
        if len(raw) > 65536:
            return args
        package = json.loads(raw)
        if not isinstance(package, dict):
            return args
        version = package.get("version", "")
        major = version.split(".", 1)[0] if isinstance(version, str) else ""
        # Older releases are not assumed to support this CLI/Vite capability.
        if package.get("name") == "vitest" and major.isascii() and major.isdigit() and int(major) >= 4:
            return (*args, "--configLoader", "runner")
    except (OSError, ValueError):
        pass
    return args


def run_restricted_vitest(
    command: Sequence[str],
    *,
    workspace: Path,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    timeout_seconds: int = 1800,
    prepared_plan: RestrictedPytestPlan | None = None,
    authorize_capability: Callable[[tuple[str, ...]], None] | None = None,
) -> int:
    if timeout_seconds <= 0 or timeout_seconds > 86400:
        raise RestrictedPytestError("vitest_restricted_invalid_command", "Protected Vitest timeout is out of bounds.")
    plan = prepared_plan or prepare_restricted_vitest(command, workspace=workspace, cwd=cwd)
    if plan.profile_version != VITEST_READ_ONLY_PROFILE_VERSION:
        raise RestrictedPytestError("vitest_restricted_invalid_command", "Unexpected Vitest profile.")
    return run_restricted_node_plan(
        plan, env=env, timeout_seconds=timeout_seconds, authorize_capability=authorize_capability
    )


def run_restricted_node_plan(
    plan: RestrictedPytestPlan,
    *,
    env: Mapping[str, str] | None = None,
    timeout_seconds: int = 1800,
    authorize_capability: Callable[[tuple[str, ...]], None] | None = None,
) -> int:
    if (
        not 0 < timeout_seconds <= 86400
        or plan.profile_version
        not in {
            VITEST_READ_ONLY_PROFILE_VERSION,
            NODE_TOOL_READ_ONLY_PROFILE_VERSION,
            NODE_BUILD_OUTPUT_PROFILE_VERSION,
        }
        or plan.backend not in {"macos-seatbelt", "linux-bubblewrap"}
    ):
        raise RestrictedPytestError(
            "vitest_restricted_invalid_command", "Protected Vitest requires its validated OS plan."
        )
    with (
        tempfile.TemporaryDirectory(prefix="hol-guard-vitest-") as temporary,
        tempfile.TemporaryDirectory(prefix="hol-guard-vitest-images-") as images,
    ):
        root = Path(temporary).resolve()
        home, tmp = root / "home", root / "tmp"
        home.mkdir(mode=0o700)
        tmp.mkdir(mode=0o700)
        esbuild = None
        if plan.profile_version == VITEST_READ_ONLY_PROFILE_VERSION:
            from .restricted_esbuild import snapshot_esbuild

            # Executable images have a separate read-only tree. A child cannot
            # replace the image by renaming a writable scratch ancestor.
            esbuild = snapshot_esbuild(plan.workspace, Path(images).resolve())
            if esbuild is not None:
                source, image, version = esbuild
                if authorize_capability is None:
                    raise RestrictedPytestError(
                        "vitest_restricted_esbuild_unavailable", "Transform execution needs native authorization."
                    )
                authorize_capability((str(source), f"--service={version}", "--ping"))
                plan = replace(plan, allowed_executables=(*plan.allowed_executables, image))
        launch_env = _restricted_environment(
            env if env is not None else os.environ,
            workspace=plan.workspace,
            cwd=plan.cwd,
            private_home=home,
            private_tmp=tmp,
            allowed_executables=plan.allowed_executables,
        )
        launch_env = linux_node_environment(
            plan,
            private_root=root,
            environment=launch_env,
            timeout_seconds=timeout_seconds,
            authorize_capability=authorize_capability,
        )
        if esbuild is not None:
            launch_env["ESBUILD_BINARY_PATH"] = str(esbuild[1])
        if plan.profile_version == VITEST_READ_ONLY_PROFILE_VERSION:
            from .restricted_localhost import prepare_localhost_resolver

            plan = prepare_localhost_resolver(plan, root)
            # Vitest supplies its own worker execArgv. Only Guard-owned
            # options, not caller NODE_OPTIONS, may reach those child runtimes.
            preload = json.dumps(str(root / "localhost-resolution.cjs"), ensure_ascii=False)
            # Caller NODE_OPTIONS were already removed by linux_node_environment;
            # keep only Guard-owned flags (e.g. --disable-wasm-trap-handler).
            guard_options = launch_env.get("NODE_OPTIONS", "")
            launch_env["NODE_OPTIONS"] = f"{guard_options} --require {preload}".strip()
        return _run_backend_process(
            _backend_argv(plan, private_root=root),
            env=launch_env,
            timeout_seconds=timeout_seconds,
            cwd=plan.cwd,
            node_virtual_address_space=plan.backend == "linux-bubblewrap",
        )
