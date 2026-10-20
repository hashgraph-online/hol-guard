"""Fail-closed launcher for repository-controlled pytest execution.

Pytest imports tests, conftest.py files, configured plugins, and application
modules during collection. This module treats pytest as repository-code
execution and intentionally has no unsandboxed fallback.
"""

from __future__ import annotations

import os
import shlex
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path

from ..native_restricted_pytest import decode_native_plan, restricted_native
from .restricted_pytest_model import (
    _DEFAULT_TIMEOUT_SECONDS,
    PYTEST_EXTERNAL_PYTHONPATH_REASON_CODE,
    PYTEST_INVALID_COMMAND_REASON_CODE,
    PYTEST_INVALID_WORKSPACE_REASON_CODE,
    PYTEST_READ_ONLY_PROFILE_VERSION,
    PYTEST_RESTRICTED_PROFILE_VERSION,
    PYTEST_RESTRICTED_REASON_CODE,
    PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE,
    RestrictedPytestError,
    RestrictedPytestPlan,
)
from .restricted_pytest_sandbox import (
    _backend_argv as _build_backend_argv,
)
from .restricted_pytest_sandbox import (
    _link_user_site,
    _restricted_environment,
    _run_backend_process,
)
from .restricted_pytest_sandbox import (
    _macos_profile as _build_macos_profile,
)


def prepare_restricted_pytest(
    command: Sequence[str],
    *,
    workspace: Path,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    platform: str | None = None,
    backend_executable: Path | None = None,
    read_only_workspace: bool = False,
) -> RestrictedPytestPlan:
    """Present the native validated launch plan without recalculating authority."""
    result = restricted_native(
        "prepare",
        {
            "command": [str(item) for item in command],
            "workspace": workspace,
            "cwd": cwd or Path.cwd(),
            "home": home_dir,
            "platform": platform or sys.platform,
            "backend_executable": backend_executable,
            "read_only_workspace": read_only_workspace,
        },
        dict,
    )
    profile = PYTEST_READ_ONLY_PROFILE_VERSION if read_only_workspace else PYTEST_RESTRICTED_PROFILE_VERSION
    return decode_native_plan(result, (profile,))


def run_restricted_pytest(
    command: Sequence[str],
    *,
    workspace: Path,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    env: Mapping[str, str] | None = None,
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
    platform: str | None = None,
    backend_executable: Path | None = None,
    read_only_workspace: bool = False,
    merge_stderr: bool = False,
) -> int:
    """Run pytest inside the default restricted profile, with no fallback."""

    if timeout_seconds <= 0 or timeout_seconds > 24 * 60 * 60:
        raise RestrictedPytestError(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Restricted pytest timeout must be between 1 second and 24 hours.",
        )
    plan = prepare_restricted_pytest(
        command,
        workspace=workspace,
        cwd=cwd,
        home_dir=home_dir,
        platform=platform,
        backend_executable=backend_executable,
        read_only_workspace=read_only_workspace,
    )
    with tempfile.TemporaryDirectory(prefix="hol-guard-pytest-") as temporary_directory:
        private_root = Path(temporary_directory).resolve()
        private_home = private_root / "home"
        private_tmp = private_root / "tmp"
        private_home.mkdir(mode=0o700)
        private_tmp.mkdir(mode=0o700)
        source = env if env is not None else os.environ
        user_site_root = _link_user_site(source, private_home)
        launch_env = _restricted_environment(
            source,
            workspace=plan.workspace,
            cwd=plan.cwd,
            private_home=private_home,
            private_tmp=private_tmp,
            allowed_executables=plan.allowed_executables,
            user_site_root=user_site_root,
        )
        if read_only_workspace:
            # Normal pytest caches belong to this run, not the protected source tree.
            launch_env["PYTHONDONTWRITEBYTECODE"] = "1"
            launch_env["PYTEST_ADDOPTS"] = f"-o cache_dir={shlex.quote(str(private_tmp / 'pytest-cache'))}"
        backend_argv = _backend_argv(plan, private_root=private_root, user_site_root=user_site_root)
        return _run_backend_process(
            backend_argv,
            env=launch_env,
            timeout_seconds=timeout_seconds,
            cwd=plan.cwd,
            merge_stderr=merge_stderr,
        )


def _backend_argv(plan: RestrictedPytestPlan, *, private_root: Path, user_site_root: Path | None = None) -> list[str]:
    """Compatibility wrapper for focused profile tests."""

    return _build_backend_argv(plan, private_root=private_root, user_site_root=user_site_root)


def _macos_profile(plan: RestrictedPytestPlan, *, private_root: Path) -> str:
    """Compatibility wrapper for focused profile tests."""

    return _build_macos_profile(plan, private_root=private_root)


__all__ = [
    "PYTEST_EXTERNAL_PYTHONPATH_REASON_CODE",
    "PYTEST_INVALID_COMMAND_REASON_CODE",
    "PYTEST_INVALID_WORKSPACE_REASON_CODE",
    "PYTEST_RESTRICTED_PROFILE_VERSION",
    "PYTEST_RESTRICTED_REASON_CODE",
    "PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE",
    "RestrictedPytestError",
    "RestrictedPytestPlan",
    "prepare_restricted_pytest",
    "run_restricted_pytest",
]
