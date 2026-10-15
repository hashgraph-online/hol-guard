"""Locally installed Vitest execution: no npx/bunx downloads or shell fallback."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from itertools import pairwise
from pathlib import Path
from urllib.parse import unquote, urlparse

from ..native_restricted_pytest import native_launch_plan, restricted_native
from .restricted_node_capabilities import linux_node_environment
from .restricted_pytest_model import (
    NODE_BUILD_OUTPUT_PROFILE_VERSION,
    NODE_TOOL_READ_ONLY_PROFILE_VERSION,
    VITEST_READ_ONLY_PROFILE_VERSION,
    RestrictedPytestError,
    RestrictedPytestPlan,
)
from .restricted_pytest_sandbox import _backend_argv, _restricted_environment, _run_backend_process

# Appended when a read-only run fails after printing a denied file operation.
READ_ONLY_WRITE_DENIAL_NOTE = (
    "This run hit a denied file operation (EPERM or EROFS). HOL Guard runs these tests with "
    "the project read-only; only $TMPDIR is writable. If a test writes reports, caches or other "
    "files into the project, point that output at $TMPDIR and run the same command again."
)


def _tsx_package_dir(command: Sequence[str]) -> Path | None:
    """Directory of the tsx package named by a contained `--import` loader."""
    for flag, value in pairwise(command):
        if flag != "--import" or not value.startswith("file:"):
            continue
        path = Path(unquote(urlparse(value).path))
        if path.name == "loader.mjs" and path.parent.name == "dist" and path.parent.parent.name == "tsx":
            return path.parent.parent
    return None


def bun_vitest_invocation(command: Sequence[str]) -> tuple[str | None, tuple[str, ...]] | None:
    result = restricted_native("bun_vitest_invocation", {"command": list(command)}, (list, type(None)))
    if result is None:
        return None
    if (
        len(result) != 2
        or (result[0] is not None and not isinstance(result[0], str))
        or not isinstance(result[1], list)
    ):
        raise ValueError("Invalid native Bun invocation")
    return result[0], tuple(result[1])


def tsx_test_invocation(command: Sequence[str]) -> tuple[str, tuple[str, ...]] | None:
    result = restricted_native("tsx_test_invocation", {"command": list(command)}, (list, type(None)))
    if result is None:
        return None
    if len(result) != 2 or not isinstance(result[0], str) or not isinstance(result[1], list):
        raise ValueError("Invalid native tsx invocation")
    return result[0], tuple(result[1])


def vitest_arguments(command: Sequence[str]) -> tuple[str, ...]:
    return tuple(restricted_native("vitest_arguments", {"command": list(command)}, list))


def prepare_restricted_vitest(
    command: Sequence[str], *, workspace: Path, cwd: Path | None = None
) -> RestrictedPytestPlan:
    return native_launch_plan(
        "prepare_vitest",
        command,
        workspace=workspace,
        cwd=cwd or workspace,
        platform=sys.platform,
        backend_executable=None,
        profile=VITEST_READ_ONLY_PROFILE_VERSION,
    )


def _readonly_config_arguments(args: tuple[str, ...], manifest: Path) -> tuple[str, ...]:
    return tuple(restricted_native("readonly_config_arguments", {"command": args, "path": manifest}, list))


def run_restricted_vitest(
    command: Sequence[str],
    *,
    workspace: Path,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    timeout_seconds: int = 1800,
    prepared_plan: RestrictedPytestPlan | None = None,
    authorize_capability: Callable[[tuple[str, ...]], None] | None = None,
    merge_stderr: bool = False,
) -> int:
    if timeout_seconds <= 0 or timeout_seconds > 86400:
        raise RestrictedPytestError("vitest_restricted_invalid_command", "Protected Vitest timeout is out of bounds.")
    plan = prepared_plan or prepare_restricted_vitest(command, workspace=workspace, cwd=cwd)
    if plan.profile_version != VITEST_READ_ONLY_PROFILE_VERSION:
        raise RestrictedPytestError("vitest_restricted_invalid_command", "Unexpected Vitest profile.")
    return run_restricted_node_plan(
        plan,
        env=env,
        timeout_seconds=timeout_seconds,
        authorize_capability=authorize_capability,
        merge_stderr=merge_stderr,
    )


def _transform_image(anchor: Path, workspace: Path, images: Path, *, required: bool) -> tuple[Path, Path, str] | None:
    """The private esbuild image, or None when a build can run without one.

    A build that never loads esbuild (tsc, a plain JavaScript config) keeps
    running when the image cannot be prepared; Vitest always needs it.
    """
    from .restricted_esbuild import snapshot_esbuild
    from .restricted_node_test import nearest_project_root

    try:
        project = nearest_project_root(anchor, workspace, "node_modules/esbuild/package.json")
        return snapshot_esbuild(project, images)
    except RestrictedPytestError:
        if required:
            raise
        return None


def run_restricted_node_plan(
    plan: RestrictedPytestPlan,
    *,
    env: Mapping[str, str] | None = None,
    timeout_seconds: int = 1800,
    authorize_capability: Callable[[tuple[str, ...]], None] | None = None,
    merge_stderr: bool = False,
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
        # Vite bundles a TypeScript config with esbuild before a build starts,
        # so a contained build needs the same transform image as Vitest.
        if plan.profile_version in {VITEST_READ_ONLY_PROFILE_VERSION, NODE_BUILD_OUTPUT_PROFILE_VERSION}:
            # Executable images have a separate read-only tree. A child cannot
            # replace the image by renaming a writable scratch ancestor.
            anchor = _tsx_package_dir(plan.command) or plan.cwd
            required = plan.profile_version == VITEST_READ_ONLY_PROFILE_VERSION
            esbuild = _transform_image(anchor, plan.workspace, Path(images).resolve(), required=required)
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
            merge_stderr=merge_stderr,
            write_denial_note=(
                READ_ONLY_WRITE_DENIAL_NOTE if plan.profile_version == VITEST_READ_ONLY_PROFILE_VERSION else None
            ),
        )
