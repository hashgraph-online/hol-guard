"""Fail-closed launcher for repository-controlled pytest execution.

Pytest imports tests, conftest.py files, configured plugins, and application
modules during collection. This module treats pytest as repository-code
execution and intentionally has no unsandboxed fallback.
"""

from __future__ import annotations

import os
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path

from .restricted_pytest_model import (
    _DEFAULT_TIMEOUT_SECONDS,
    PYTEST_EXTERNAL_PYTHONPATH_REASON_CODE,
    PYTEST_INVALID_COMMAND_REASON_CODE,
    PYTEST_INVALID_WORKSPACE_REASON_CODE,
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
    _macos_profile as _build_macos_profile,
)
from .restricted_pytest_sandbox import (
    _restricted_environment,
    _run_backend_process,
)
from .restricted_pytest_validation import (
    _allowed_executables,
    _normalized_command,
    _resolve_cwd,
    _resolve_pytest_executable,
    _resolve_workspace,
    _select_backend,
)


def prepare_restricted_pytest(
    command: Sequence[str],
    *,
    workspace: Path,
    cwd: Path | None = None,
    platform: str | None = None,
    backend_executable: Path | None = None,
) -> RestrictedPytestPlan:
    """Validate and resolve a pytest argv without executing repository code."""

    normalized_command = _normalized_command(command)
    selected_backend, selected_backend_executable = _select_backend(
        platform=platform or sys.platform,
        backend_executable=backend_executable,
    )
    resolved_workspace = _resolve_workspace(workspace)
    resolved_cwd = _resolve_cwd(cwd or Path.cwd(), workspace=resolved_workspace)
    launch_executable, executable = _resolve_pytest_executable(
        normalized_command,
        cwd=resolved_cwd,
        workspace=resolved_workspace,
    )
    allowed_executables = _allowed_executables(
        executable,
        launch_executable,
        normalized_command,
        cwd=resolved_cwd,
        workspace=resolved_workspace,
    )
    return RestrictedPytestPlan(
        profile_version=PYTEST_RESTRICTED_PROFILE_VERSION,
        backend=selected_backend,
        backend_executable=selected_backend_executable,
        workspace=resolved_workspace,
        cwd=resolved_cwd,
        command=(str(launch_executable), *normalized_command[1:]),
        executable=executable,
        allowed_executables=allowed_executables,
        denied_capabilities=(
            "host-home-read",
            "host-secret-environment",
            "network",
            "docker-socket",
            "write-outside-workspace-and-private-temp",
            "unapproved-process-exec",
            "privileged-operation",
        ),
    )


def run_restricted_pytest(
    command: Sequence[str],
    *,
    workspace: Path,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
    platform: str | None = None,
    backend_executable: Path | None = None,
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
        platform=platform,
        backend_executable=backend_executable,
    )
    with tempfile.TemporaryDirectory(prefix="hol-guard-pytest-") as temporary_directory:
        private_root = Path(temporary_directory).resolve()
        private_home = private_root / "home"
        private_tmp = private_root / "tmp"
        private_home.mkdir(mode=0o700)
        private_tmp.mkdir(mode=0o700)
        launch_env = _restricted_environment(
            env if env is not None else os.environ,
            workspace=plan.workspace,
            cwd=plan.cwd,
            private_home=private_home,
            private_tmp=private_tmp,
            allowed_executables=plan.allowed_executables,
        )
        backend_argv = _backend_argv(plan, private_root=private_root)
        return _run_backend_process(
            backend_argv,
            env=launch_env,
            timeout_seconds=timeout_seconds,
        )


def _backend_argv(plan: RestrictedPytestPlan, *, private_root: Path) -> list[str]:
    """Compatibility wrapper for focused profile tests."""

    return _build_backend_argv(plan, private_root=private_root)


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
