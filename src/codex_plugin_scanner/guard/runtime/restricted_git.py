"""Read-only Git inspections without executable helpers or host routing overrides."""

from __future__ import annotations

import os
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path

from .git_execution_safety import git_binary_path_is_trusted
from .restricted_pytest_model import GIT_READ_ONLY_PROFILE_VERSION, RestrictedPytestError, RestrictedPytestPlan
from .restricted_pytest_sandbox import _backend_argv, _restricted_environment, _run_backend_process
from .restricted_pytest_validation import (
    _normalized_command,
    _resolve_cwd,
    _resolve_executable,
    _resolve_workspace,
    _select_backend,
)


def prepare_restricted_git(command: Sequence[str], *, workspace: Path, cwd: Path | None = None) -> RestrictedPytestPlan:
    argv = _normalized_command(command)
    # Native authority validates the complete original command. This local gate
    # independently excludes mutation, helper selection, and shell operators.
    if (
        len(argv) < 2
        or Path(argv[0]).name != "git"
        or argv[1] not in {"diff", "log", "show"}
        or any(
            value in {";", "&&", "||", "|", "&", "--ext-diff", "--textconv", "--output", "-o"}
            or value.startswith(("--output=", "--exec-path="))
            for value in argv[2:]
        )
    ):
        raise RestrictedPytestError("git_restricted_invalid_command", "Protected Git requires direct read-only argv.")
    root = _resolve_workspace(workspace)
    directory = _resolve_cwd(cwd or root, workspace=root)
    backend, backend_path = _select_backend(platform=sys.platform, backend_executable=None)
    if backend != "macos-seatbelt":
        raise RestrictedPytestError("git_restricted_sandbox_unavailable", "Protected Git filtering is unavailable.")
    executable = _resolve_executable(argv[0], cwd=directory)
    if not git_binary_path_is_trusted(executable, cwd=directory):
        raise RestrictedPytestError("git_restricted_invalid_command", "Git does not resolve to a trusted executable.")
    # Options precede '--' so option-shaped filenames cannot override the floor.
    operation = argv[1]
    transformed = (
        str(executable),
        "--no-pager",
        "-c",
        "core.fsmonitor=false",
        operation,
        "--no-ext-diff",
        "--no-textconv",
        *argv[2:],
    )
    return RestrictedPytestPlan(
        profile_version=GIT_READ_ONLY_PROFILE_VERSION,
        backend=backend,
        backend_executable=backend_path,
        workspace=root,
        cwd=directory,
        command=transformed,
        executable=executable,
        allowed_executables=(executable,),
        denied_capabilities=(
            "workspace-write",
            "workspace-credential-read",
            "network",
            "unapproved-process-exec",
            "host-secret-environment",
            "host-home-read",
        ),
    )


def run_restricted_git(
    plan: RestrictedPytestPlan, *, timeout_seconds: int, env: Mapping[str, str] | None = None
) -> int:
    if (
        plan.profile_version != GIT_READ_ONLY_PROFILE_VERSION
        or plan.backend != "macos-seatbelt"
        or not 0 < timeout_seconds <= 86400
    ):
        raise RestrictedPytestError("git_restricted_invalid_command", "Invalid protected Git plan.")
    with tempfile.TemporaryDirectory(prefix="hol-guard-git-") as temporary:
        root = Path(temporary).resolve()
        home, tmp = root / "home", root / "tmp"
        home.mkdir(mode=0o700)
        tmp.mkdir(mode=0o700)
        source_env = {
            key: value
            for key, value in (env if env is not None else os.environ).items()
            if key not in {"PYTHONPATH", "VIRTUAL_ENV"}
        }
        launch_env = _restricted_environment(
            source_env,
            workspace=plan.workspace,
            cwd=plan.cwd,
            private_home=home,
            private_tmp=tmp,
            allowed_executables=plan.allowed_executables,
        )
        for key in tuple(launch_env):
            if key.startswith("GIT_") or key in {"PAGER", "XDG_CONFIG_HOME"}:
                del launch_env[key]
        launch_env.update(
            {
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_NO_LAZY_FETCH": "1",
            }
        )
        return _run_backend_process(
            _backend_argv(plan, private_root=root), env=launch_env, timeout_seconds=timeout_seconds, cwd=plan.cwd
        )
