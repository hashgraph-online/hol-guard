"""Shared constants and immutable data for restricted pytest execution."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

PYTEST_RESTRICTED_PROFILE_VERSION = "pytest-restricted-v1"
PYTEST_READ_ONLY_PROFILE_VERSION = "pytest-readonly-v2"
NODE_TEST_READ_ONLY_PROFILE_VERSION = "node-test-readonly-v1"
VITEST_READ_ONLY_PROFILE_VERSION = "vitest-readonly-v1"
GIT_READ_ONLY_PROFILE_VERSION = "git-readonly-v1"
NODE_TOOL_READ_ONLY_PROFILE_VERSION = "node-tool-readonly-v1"
NODE_BUILD_OUTPUT_PROFILE_VERSION = "node-build-output-v1"
PYTHON_EVAL_READ_ONLY_PROFILE_VERSION = "python-eval-readonly-v1"
NODE_EVAL_READ_ONLY_PROFILE_VERSION = "node-eval-readonly-v1"
READ_ONLY_TEST_PROFILES = frozenset(
    {
        PYTEST_READ_ONLY_PROFILE_VERSION,
        NODE_TEST_READ_ONLY_PROFILE_VERSION,
        VITEST_READ_ONLY_PROFILE_VERSION,
        GIT_READ_ONLY_PROFILE_VERSION,
        NODE_TOOL_READ_ONLY_PROFILE_VERSION,
        NODE_BUILD_OUTPUT_PROFILE_VERSION,
        PYTHON_EVAL_READ_ONLY_PROFILE_VERSION,
        NODE_EVAL_READ_ONLY_PROFILE_VERSION,
    }
)
PYTEST_RESTRICTED_REASON_CODE = "pytest_restricted_profile_required"
PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE = "pytest_restricted_sandbox_unavailable"
PYTEST_INVALID_COMMAND_REASON_CODE = "pytest_restricted_invalid_command"
PYTEST_INVALID_WORKSPACE_REASON_CODE = "pytest_restricted_invalid_workspace"
PYTEST_EXTERNAL_PYTHONPATH_REASON_CODE = "pytest_restricted_external_pythonpath"

RestrictedPytestBackend = Literal["macos-seatbelt", "linux-bubblewrap", "windows-appcontainer"]

_DEFAULT_TIMEOUT_SECONDS = 30 * 60
_DEFAULT_CPU_SECONDS = 20 * 60
_DEFAULT_MEMORY_BYTES = 4 * 1024 * 1024 * 1024
_DEFAULT_FILE_BYTES = 256 * 1024 * 1024
_DEFAULT_OPEN_FILES = 256
_DEFAULT_PROCESSES = 64


class RestrictedPytestError(RuntimeError):
    """A stable fail-closed error emitted before repository code executes."""

    reason_code: str
    exit_code: int

    def __init__(self, reason_code: str, message: str, *, exit_code: int = 126) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.exit_code = exit_code


@dataclass(frozen=True, slots=True)
class RestrictedPytestPlan:
    """Resolved, non-shell launch plan for one restricted pytest run."""

    profile_version: str
    backend: RestrictedPytestBackend
    backend_executable: Path
    workspace: Path
    cwd: Path
    command: tuple[str, ...]
    executable: Path
    allowed_executables: tuple[Path, ...]
    denied_capabilities: tuple[str, ...]
    read_only_roots: tuple[Path, ...] = ()
    output_roots: tuple[Path, ...] = ()

    def to_evidence(self) -> dict[str, object]:
        return {
            "profile_version": self.profile_version,
            "backend": self.backend,
            "workspace": str(self.workspace),
            "cwd": str(self.cwd),
            "command": list(self.command),
            "executable": str(self.executable),
            "allowed_executables": [str(path) for path in self.allowed_executables],
            "denied_capabilities": list(self.denied_capabilities),
            "network": "denied",
            "host_home": "unmounted-or-denied",
            "writes": (
                ["private-temporary-directory", *(str(path) for path in self.output_roots)]
                if self.profile_version in READ_ONLY_TEST_PROFILES
                else ["workspace", "private-temporary-directory"]
            ),
        }
