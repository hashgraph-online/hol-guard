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

_TEST_SCRIPT_NAME = re.compile(r"(?:test_[A-Za-z0-9_-]*|[A-Za-z0-9_-]*_test|test|tests|runtests|run_tests)\.py")
_NODE_TEST_SCRIPT_NAME = re.compile(
    r"(?:[A-Za-z0-9_.-]*(?:\.test|\.spec|_test)|test_[A-Za-z0-9_.-]*|tests?)\.(?:js|mjs|cjs|jsx|ts|mts|cts|tsx)"
)
# Type stripping and warning filters change how Node loads and reports a
# script, not what the script can reach.
_NODE_SCRIPT_FLAGS = re.compile(
    r"--experimental-strip-types|--experimental-transform-types|--no-warnings|--disable-warning=[A-Za-z0-9_]{1,64}"
)


def _test_script(script: str, *, node: bool = False) -> bool:
    """A lexical workspace-relative, test-named script; the plan resolves it."""
    parts = script.rstrip("/").split("/")
    name = _NODE_TEST_SCRIPT_NAME if node else _TEST_SCRIPT_NAME
    return (
        bool(script)
        and not script.startswith(("-", "/", "~", "$"))
        and not any(character in script for character in "\\$`")
        and all(part and part != ".." for part in parts)
        and name.fullmatch(script.rsplit("/", 1)[-1]) is not None
    )


def _node_script_index(command: Sequence[str], start: int) -> int | None:
    """The index of a test-named script after neutral Node flags, if any."""
    index = start
    while index < len(command) and _NODE_SCRIPT_FLAGS.fullmatch(command[index]) is not None:
        index += 1
    return index if index < len(command) and _test_script(command[index], node=True) else None


def _python_runtime_args(command: Sequence[str]) -> tuple[str, ...] | None:
    """Accept only capability-reducing isolation flags before inline code or a test script."""
    flags = 0
    index = 1
    bits_by_flag = {"-I": 1, "-S": 2, "-IS": 3, "-SI": 3}
    while index < len(command) and command[index] in bits_by_flag:
        bits = bits_by_flag[command[index]]
        if flags & bits:
            return None
        flags |= bits
        index += 1
    inline = len(command) == index + 2 and command[index] == "-c"
    if not inline and not (len(command) > index and _test_script(command[index])):
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
    inline = len(command) == eval_index + 2 and command[eval_index] in {"-e", "--eval"}
    return inline or _node_script_index(command, eval_index) is not None


def prepare_restricted_inline_eval(
    command: Sequence[str], *, workspace: Path, cwd: Path | None = None
) -> RestrictedPytestPlan:
    argv = _normalized_command(command)
    if not is_inline_eval(argv):
        raise RestrictedPytestError("inline_eval_invalid_command", "Protected evaluation requires direct inline argv.")
    node = Path(argv[0]).name in {"node", "nodejs"}
    runtime_args = _node_runtime_args(argv) if node else _python_runtime_args(argv) or ()
    eval_index = 1 + len(runtime_args)
    script_index = None
    if node and argv[eval_index] not in {"-e", "--eval"}:
        script_index = _node_script_index(argv, eval_index)
    elif not node and argv[eval_index] != "-c":
        script_index = eval_index
    if script_index is not None:
        # A test script runs from the workspace, never from a link out of it.
        outside = RestrictedPytestError("inline_eval_invalid_command", "Test script is not in the workspace.")
        try:
            script = ((cwd or workspace) / argv[script_index]).resolve(strict=True)
        except OSError as error:
            raise outside from error
        if not script.is_relative_to(workspace.resolve()) or not script.is_file():
            raise outside
    # Reuse runtime/backend validation only; neither preparation executes tests
    # or requires pytest installed. Launch the resolved native image, not PATH.
    base = (
        prepare_restricted_node_test([argv[0], "--test"], workspace=workspace, cwd=cwd or workspace)
        if node
        else prepare_restricted_pytest(
            [argv[0], "-m", "pytest"], workspace=workspace, cwd=cwd or workspace, read_only_workspace=True
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
