"""Inline analysis runs in the same credential-filtered, read-only OS boundary."""

from __future__ import annotations

import os
import re
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path

from .restricted_node_capabilities import linux_node_environment
from .restricted_node_test import _node_runtime_args, prepare_restricted_node_test
from .restricted_pytest import prepare_restricted_pytest
from .restricted_pytest_model import (
    NODE_EVAL_READ_ONLY_PROFILE_VERSION,
    PYTHON_EVAL_READ_ONLY_PROFILE_VERSION,
    RestrictedPytestError,
    RestrictedPytestPlan,
)
from .restricted_pytest_sandbox import _backend_argv, _restricted_environment, _run_backend_process
from .restricted_pytest_validation import _normalized_command


def _python_runtime_args(command: Sequence[str]) -> tuple[str, ...] | None:
    """Accept only capability-reducing isolation flags before direct inline code."""
    flags = 0
    index = 1
    bits_by_flag = {"-I": 1, "-S": 2, "-IS": 3, "-SI": 3}
    while index < len(command) and command[index] in bits_by_flag:
        bits = bits_by_flag[command[index]]
        if flags & bits:
            return None
        flags |= bits
        index += 1
    if len(command) != index + 2 or command[index] != "-c":
        return None
    return tuple(command[1:index])


def is_inline_eval(command: Sequence[str]) -> bool:
    if not command:
        return False
    if re.fullmatch(r"python(?:\d+(?:\.\d+)*)?", Path(command[0]).name) is not None:
        return _python_runtime_args(command) is not None
    if Path(command[0]).name not in {"node", "nodejs"}:
        return False
    runtime_args = _node_runtime_args(command)
    eval_index = 1 + len(runtime_args)
    return len(command) == eval_index + 2 and command[eval_index] in {"-e", "--eval"}


def prepare_restricted_inline_eval(command: Sequence[str], *, workspace: Path) -> RestrictedPytestPlan:
    argv = _normalized_command(command)
    if not is_inline_eval(argv):
        raise RestrictedPytestError("inline_eval_invalid_command", "Protected evaluation requires direct inline argv.")
    node = Path(argv[0]).name in {"node", "nodejs"}
    runtime_args = _node_runtime_args(argv) if node else _python_runtime_args(argv) or ()
    eval_index = 1 + len(runtime_args)
    # Reuse runtime/backend validation only; neither preparation executes tests
    # or requires pytest installed. Launch the resolved native image, not PATH.
    base = (
        prepare_restricted_node_test([argv[0], "--test"], workspace=workspace, cwd=workspace)
        if node
        else prepare_restricted_pytest(
            [argv[0], "-m", "pytest"], workspace=workspace, cwd=workspace, read_only_workspace=True
        )
    )
    return replace(
        base,
        profile_version=NODE_EVAL_READ_ONLY_PROFILE_VERSION if node else PYTHON_EVAL_READ_ONLY_PROFILE_VERSION,
        command=(str(base.executable), *runtime_args, *argv[eval_index:]),
    )


def run_restricted_inline_eval(
    plan: RestrictedPytestPlan,
    *,
    timeout_seconds: int,
    authorize_capability: Callable[[tuple[str, ...]], None],
) -> int:
    if (
        not 0 < timeout_seconds <= 86400
        or plan.profile_version not in {PYTHON_EVAL_READ_ONLY_PROFILE_VERSION, NODE_EVAL_READ_ONLY_PROFILE_VERSION}
        or plan.backend not in {"macos-seatbelt", "linux-bubblewrap"}
    ):
        raise RestrictedPytestError("inline_eval_invalid_command", "Unexpected protected inline evaluation plan.")
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
        )
