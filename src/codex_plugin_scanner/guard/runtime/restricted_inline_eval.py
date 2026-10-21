"""Inline analysis runs in the same credential-filtered, read-only OS boundary."""

from __future__ import annotations

import os
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path

from ..native_restricted_pytest import native_launch_plan, restricted_native
from .restricted_node_capabilities import linux_node_environment
from .restricted_pytest_model import (
    NODE_EVAL_READ_ONLY_PROFILE_VERSION,
    PYTHON_EVAL_READ_ONLY_PROFILE_VERSION,
    RestrictedPytestError,
    RestrictedPytestPlan,
)
from .restricted_pytest_sandbox import _backend_argv, _restricted_environment, _run_backend_process


def _test_script(script: str, *, node: bool = False) -> bool:
    return restricted_native("test_script", {"value": script, "node": node}, bool)


def _python_runtime_args(command: Sequence[str]) -> tuple[str, ...] | None:
    value = restricted_native("python_runtime_args", {"command": list(command)}, (list, type(None)))
    return tuple(value) if value is not None else None


def is_inline_eval(command: Sequence[str]) -> bool:
    return restricted_native("inline_eval", {"command": list(command)}, bool)


def prepare_restricted_inline_eval(
    command: Sequence[str], *, workspace: Path, cwd: Path | None = None, home_dir: Path | None = None
) -> RestrictedPytestPlan:
    return native_launch_plan(
        "prepare_inline",
        command,
        workspace=workspace,
        cwd=cwd or workspace,
        home_dir=home_dir,
        platform=sys.platform,
        backend_executable=None,
        profile=(NODE_EVAL_READ_ONLY_PROFILE_VERSION, PYTHON_EVAL_READ_ONLY_PROFILE_VERSION),
    )


def run_restricted_inline_eval(
    plan: RestrictedPytestPlan,
    *,
    timeout_seconds: int,
    authorize_capability: Callable[[tuple[str, ...]], None],
    merge_stderr: bool = False,
) -> int:
    if (
        not 0 < timeout_seconds <= 86400
        or plan.profile_version not in {PYTHON_EVAL_READ_ONLY_PROFILE_VERSION, NODE_EVAL_READ_ONLY_PROFILE_VERSION}
        or plan.backend not in {"macos-seatbelt", "linux-bubblewrap", "windows-appcontainer"}
    ):
        raise RestrictedPytestError("inline_eval_invalid_command", "Unexpected protected inline evaluation plan.")
    if plan.backend == "windows-appcontainer":
        return _run_windows_inline_eval(plan, timeout_seconds=timeout_seconds, merge_stderr=merge_stderr)
    node = plan.profile_version == NODE_EVAL_READ_ONLY_PROFILE_VERSION
    with tempfile.TemporaryDirectory(prefix="hol-guard-inline-eval-") as temporary:
        root = Path(temporary).resolve()
        home, tmp = root / "home", root / "tmp"
        home.mkdir(mode=0o700)
        tmp.mkdir(mode=0o700)
        environment = _restricted_environment(
            os.environ,
            workspace=plan.workspace,
            cwd=plan.cwd,
            private_home=home,
            private_tmp=tmp,
            allowed_executables=plan.allowed_executables,
        )
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        if node:
            environment = linux_node_environment(
                plan,
                private_root=root,
                environment=environment,
                timeout_seconds=timeout_seconds,
                authorize_capability=authorize_capability,
            )
        return _run_backend_process(
            _backend_argv(plan, private_root=root),
            env=environment,
            timeout_seconds=timeout_seconds,
            cwd=plan.cwd,
            node_virtual_address_space=node and plan.backend == "linux-bubblewrap",
            merge_stderr=merge_stderr,
        )


def _run_windows_inline_eval(plan: RestrictedPytestPlan, *, timeout_seconds: int, merge_stderr: bool) -> int:
    """The native runner stages a credential-filtered snapshot and owns the environment."""
    if sys.platform != "win32" or plan.profile_version not in {
        PYTHON_EVAL_READ_ONLY_PROFILE_VERSION,
        NODE_EVAL_READ_ONLY_PROFILE_VERSION,
    }:
        raise RestrictedPytestError("inline_eval_invalid_command", "Unexpected protected inline evaluation plan.")
    argv = [
        str(plan.backend_executable),
        "contained-readonly-windows",
        "--workspace",
        str(plan.workspace),
        "--cwd",
        str(plan.cwd),
        "--timeout-seconds",
        str(timeout_seconds),
        *(
            ("--profile", NODE_EVAL_READ_ONLY_PROFILE_VERSION)
            if plan.profile_version == NODE_EVAL_READ_ONLY_PROFILE_VERSION
            else ()
        ),
        "--",
        *plan.command,
    ]
    return _run_backend_process(
        argv, env=os.environ, timeout_seconds=timeout_seconds, cwd=plan.cwd, merge_stderr=merge_stderr
    )
