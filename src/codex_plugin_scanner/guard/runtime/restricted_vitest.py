"""Locally installed Vitest execution: no npx/bunx downloads or shell fallback."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path

from .restricted_node_test import prepare_restricted_node_test
from .restricted_pytest_model import (
    NODE_BUILD_OUTPUT_PROFILE_VERSION,
    NODE_TOOL_READ_ONLY_PROFILE_VERSION,
    VITEST_READ_ONLY_PROFILE_VERSION,
    RestrictedPytestError,
    RestrictedPytestPlan,
)
from .restricted_pytest_sandbox import _backend_argv, _restricted_environment, _run_backend_process
from .restricted_pytest_validation import _normalized_command, _path_is_within


def vitest_arguments(command: Sequence[str]) -> tuple[str, ...]:
    argv = _normalized_command(command)
    name = Path(argv[0]).name
    if name in {"bunx", "npx"}:
        args = argv[1:]
        if args and args[0] == "--no-install":
            args = args[1:]
        if not args or args[0] != "vitest":
            raise RestrictedPytestError("vitest_restricted_invalid_command", "Only local Vitest run is supported.")
        args = args[1:]
    elif name == "vitest":
        args = argv[1:]
    elif name in {"node", "nodejs"} and len(argv) > 2 and argv[1].endswith("/node_modules/vitest/vitest.mjs"):
        args = argv[2:]
    else:
        raise RestrictedPytestError("vitest_restricted_invalid_command", "Only local Vitest run is supported.")
    if not args or args[0] != "run" or any(item in {";", "&&", "||", "|", "|&", "&"} for item in args):
        raise RestrictedPytestError("vitest_restricted_invalid_command", "Protected Vitest requires direct run argv.")
    return tuple(args)


def prepare_restricted_vitest(
    command: Sequence[str], *, workspace: Path, cwd: Path | None = None
) -> RestrictedPytestPlan:
    args = vitest_arguments(command)
    plan = prepare_restricted_node_test(["node", "--test"], workspace=workspace, cwd=cwd)
    lexical = plan.workspace / "node_modules" / "vitest" / "vitest.mjs"
    try:
        entry = lexical.resolve(strict=True)
        if not entry.is_file() or not _path_is_within(entry, plan.workspace / "node_modules"):
            raise OSError("invalid local Vitest entrypoint")
        if Path(command[0]).name in {"node", "nodejs"} and Path(command[1]).resolve(strict=True) != entry:
            raise OSError("unexpected Vitest entrypoint")
    except (OSError, RuntimeError) as error:
        raise RestrictedPytestError(
            "vitest_restricted_dependency_unavailable",
            "Vitest is not installed inside this workspace. Guard did not download or execute a replacement.",
        ) from error
    return replace(
        plan, profile_version=VITEST_READ_ONLY_PROFILE_VERSION, command=(str(plan.executable), str(entry), *args)
    )


def run_restricted_vitest(
    command: Sequence[str],
    *,
    workspace: Path,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    timeout_seconds: int = 1800,
    prepared_plan: RestrictedPytestPlan | None = None,
) -> int:
    if timeout_seconds <= 0 or timeout_seconds > 86400:
        raise RestrictedPytestError("vitest_restricted_invalid_command", "Protected Vitest timeout is out of bounds.")
    plan = prepared_plan or prepare_restricted_vitest(command, workspace=workspace, cwd=cwd)
    if plan.profile_version != VITEST_READ_ONLY_PROFILE_VERSION:
        raise RestrictedPytestError("vitest_restricted_invalid_command", "Unexpected Vitest profile.")
    return run_restricted_node_plan(plan, env=env, timeout_seconds=timeout_seconds)


def run_restricted_node_plan(
    plan: RestrictedPytestPlan, *, env: Mapping[str, str] | None = None, timeout_seconds: int = 1800
) -> int:
    if (
        not 0 < timeout_seconds <= 86400
        or plan.profile_version
        not in {
            VITEST_READ_ONLY_PROFILE_VERSION,
            NODE_TOOL_READ_ONLY_PROFILE_VERSION,
            NODE_BUILD_OUTPUT_PROFILE_VERSION,
        }
        or plan.backend != "macos-seatbelt"
    ):
        raise RestrictedPytestError(
            "vitest_restricted_invalid_command", "Protected Vitest requires its validated OS plan."
        )
    with tempfile.TemporaryDirectory(prefix="hol-guard-vitest-") as temporary:
        root = Path(temporary).resolve()
        home, tmp = root / "home", root / "tmp"
        home.mkdir(mode=0o700)
        tmp.mkdir(mode=0o700)
        launch_env = _restricted_environment(
            env if env is not None else os.environ,
            workspace=plan.workspace,
            cwd=plan.cwd,
            private_home=home,
            private_tmp=tmp,
            allowed_executables=plan.allowed_executables,
        )
        return _run_backend_process(
            _backend_argv(plan, private_root=root), env=launch_env, timeout_seconds=timeout_seconds, cwd=plan.cwd
        )
