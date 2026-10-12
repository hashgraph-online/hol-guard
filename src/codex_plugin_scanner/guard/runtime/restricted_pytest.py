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

from ..native_restricted_pytest import restricted_native
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
    _macos_profile as _build_macos_profile,
)
from .restricted_pytest_sandbox import (
    _restricted_environment,
    _run_backend_process,
)


def prepare_restricted_pytest(
    command: Sequence[str],
    *,
    workspace: Path,
    cwd: Path | None = None,
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
            "platform": platform or sys.platform,
            "backend_executable": backend_executable,
            "read_only_workspace": read_only_workspace,
        },
        dict,
    )
    scalar = {"profile_version", "backend", "backend_executable", "workspace", "cwd", "executable"}
    arrays = {"command", "allowed_executables", "denied_capabilities"}
    if (
        set(result) != scalar | arrays
        or any(not isinstance(result[key], str) for key in scalar)
        or any(
            not isinstance(result[key], list) or not all(isinstance(item, str) for item in result[key])
            for key in arrays
        )
        or result["backend"] not in {"macos-seatbelt", "linux-bubblewrap"}
        or result["profile_version"]
        != (PYTEST_READ_ONLY_PROFILE_VERSION if read_only_workspace else PYTEST_RESTRICTED_PROFILE_VERSION)
        or not result["command"]
        or not result["allowed_executables"]
    ):
        raise RestrictedPytestError(PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE, "Invalid native restricted launch plan.")
    return RestrictedPytestPlan(
        profile_version=result["profile_version"],
        backend=result["backend"],
        backend_executable=Path(result["backend_executable"]),
        workspace=Path(result["workspace"]),
        cwd=Path(result["cwd"]),
        command=tuple(result["command"]),
        executable=Path(result["executable"]),
        allowed_executables=tuple(Path(path) for path in result["allowed_executables"]),
        denied_capabilities=tuple(result["denied_capabilities"]),
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
    read_only_workspace: bool = False,
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
        read_only_workspace=read_only_workspace,
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
        if read_only_workspace:
            # Normal pytest caches belong to this run, not the protected source tree.
            launch_env["PYTHONDONTWRITEBYTECODE"] = "1"
            launch_env["PYTEST_ADDOPTS"] = f"-o cache_dir={shlex.quote(str(private_tmp / 'pytest-cache'))}"
        backend_argv = _backend_argv(plan, private_root=private_root)
        return _run_backend_process(
            backend_argv,
            env=launch_env,
            timeout_seconds=timeout_seconds,
            cwd=plan.cwd,
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
