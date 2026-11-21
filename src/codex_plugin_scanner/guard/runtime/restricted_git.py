"""Read-only Git inspections without executable helpers or host routing overrides."""

from __future__ import annotations

import os
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path

from ..native_restricted_pytest import decode_native_plan, restricted_native
from .restricted_pytest_model import GIT_READ_ONLY_PROFILE_VERSION, RestrictedPytestError, RestrictedPytestPlan
from .restricted_pytest_sandbox import _backend_argv, _restricted_environment, _run_backend_process


def prepare_restricted_git(
    command: Sequence[str], *, workspace: Path, cwd: Path | None = None, home_dir: Path | None = None
) -> RestrictedPytestPlan:
    # The resident reads the argv, walks Git's -C path inside the workspace,
    # proves the Git executable and resolves linked worktree metadata.
    result = restricted_native(
        "prepare_git",
        {
            "command": list(command),
            "workspace": workspace,
            "cwd": cwd or workspace,
            "home": home_dir,
            "platform": sys.platform,
            "backend_executable": None,
            "account_home": Path.home(),
            "groups": sorted(os.getgroups()),
        },
        dict,
    )
    return decode_native_plan(result, (GIT_READ_ONLY_PROFILE_VERSION,))


def run_restricted_git(
    plan: RestrictedPytestPlan,
    *,
    timeout_seconds: int,
    env: Mapping[str, str] | None = None,
    merge_stderr: bool = False,
) -> int:
    if (
        plan.profile_version != GIT_READ_ONLY_PROFILE_VERSION
        or plan.backend not in {"macos-seatbelt", "linux-bubblewrap"}
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
        return _run_backend_process(
            _backend_argv(plan, private_root=root),
            env=restricted_native("git_environment", {"source": launch_env}, dict),
            timeout_seconds=timeout_seconds,
            cwd=plan.cwd,
            merge_stderr=merge_stderr,
        )
