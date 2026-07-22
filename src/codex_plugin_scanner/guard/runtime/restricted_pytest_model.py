"""Shared constants and immutable data for restricted pytest execution."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

PYTEST_RESTRICTED_PROFILE_VERSION = "pytest-restricted-v1"
PYTEST_RESTRICTED_REASON_CODE = "pytest_restricted_profile_required"
PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE = "pytest_restricted_sandbox_unavailable"
PYTEST_INVALID_COMMAND_REASON_CODE = "pytest_restricted_invalid_command"
PYTEST_INVALID_WORKSPACE_REASON_CODE = "pytest_restricted_invalid_workspace"
PYTEST_EXTERNAL_PYTHONPATH_REASON_CODE = "pytest_restricted_external_pythonpath"

RestrictedPytestBackend = Literal["macos-seatbelt", "linux-bubblewrap"]

_MAX_ARG_COUNT = 4_096
_MAX_ARG_BYTES = 1_048_576
_DEFAULT_TIMEOUT_SECONDS = 30 * 60
_DEFAULT_CPU_SECONDS = 20 * 60
_DEFAULT_MEMORY_BYTES = 4 * 1024 * 1024 * 1024
_DEFAULT_FILE_BYTES = 256 * 1024 * 1024
_DEFAULT_OPEN_FILES = 256
_DEFAULT_PROCESSES = 64

_PYTEST_EXECUTABLE_NAMES = frozenset({"pytest", "py.test", "pytest.exe", "py.test.exe"})
_PYTHON_EXECUTABLE_PATTERN = re.compile(r"^(?:python|pythonw)(?:\d+(?:\.\d+)*)?(?:\.exe)?$", re.IGNORECASE)
_PROJECT_WORKSPACE_MARKERS = (
    ".git",
    "pyproject.toml",
    "pytest.ini",
    "setup.cfg",
    "setup.py",
    "tox.ini",
)
_SENSITIVE_HOME_ROOT_NAMES = frozenset(
    {
        ".aws",
        ".azure",
        ".config",
        ".docker",
        ".gnupg",
        ".kube",
        ".ssh",
        "Library",
    }
)
_SECRET_ENV_MARKERS = (
    r"API_?KEY",
    r"AUTH(?:ORIZATION)?",
    "BEARER",
    "COOKIE",
    r"CREDENTIALS?",
    "DSN",
    r"KEY(?:_?ID)?",
    "PASSWORD",
    r"PRIVATE_?KEY",
    "SECRET",
    "SESSION",
    "TOKEN",
)
_SECRET_ENV_PATTERN = re.compile(
    rf"(?:^|_)(?:{'|'.join(_SECRET_ENV_MARKERS)})(?:_|$)",
    re.IGNORECASE,
)
_DENIED_ENV_KEYS = frozenset(
    {
        "AWS_CONFIG_FILE",
        "AWS_SHARED_CREDENTIALS_FILE",
        "BASH_ENV",
        "DATABASE_URL",
        "DOCKER_CONFIG",
        "DOCKER_HOST",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "ENV",
        "GIT_ASKPASS",
        "GNUPGHOME",
        "KRB5CCNAME",
        "KUBECONFIG",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "MONGODB_URI",
        "MYSQL_PWD",
        "NODE_AUTH_TOKEN",
        "NPM_CONFIG_USERCONFIG",
        "PGPASSWORD",
        "PIP_CONFIG_FILE",
        "PYTHONBREAKPOINT",
        "PYTHONHOME",
        "PYTHONINSPECT",
        "PYTHONSTARTUP",
        "PYTHONUSERBASE",
        "PYTHONWARNINGS",
        "REDIS_URL",
        "SSH_ASKPASS",
        "SSH_AUTH_SOCK",
        "ZDOTDIR",
    }
)
_PROXY_ENV_KEYS = frozenset(
    {
        "ALL_PROXY",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "NO_PROXY",
        "all_proxy",
        "https_proxy",
        "http_proxy",
        "no_proxy",
    }
)
_SAFE_ENV_KEYS = frozenset(
    {
        "CI",
        "CLICOLOR",
        "CLICOLOR_FORCE",
        "COLORTERM",
        "COLUMNS",
        "FORCE_COLOR",
        "GITHUB_ACTIONS",
        "GITLAB_CI",
        "LANG",
        "LANGUAGE",
        "LINES",
        "LOGNAME",
        "NO_COLOR",
        "PYTHONHASHSEED",
        "PYTHONIOENCODING",
        "PYTHONUNBUFFERED",
        "PYTHONUTF8",
        "PYTHONDONTWRITEBYTECODE",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
        "SOURCE_DATE_EPOCH",
        "TERM",
        "TERM_PROGRAM",
        "TERM_PROGRAM_VERSION",
        "TF_BUILD",
        "TZ",
        "USER",
        "VIRTUAL_ENV_PROMPT",
    }
)
_TRUSTED_EXECUTABLE_ROOTS = (
    Path("/bin"),
    Path("/opt/homebrew"),
    Path("/opt/hostedtoolcache/Python"),
    Path("/System"),
    Path("/usr/bin"),
    Path("/usr/local"),
)
_SEALED_SYSTEM_EXECUTABLE_ROOTS = (
    Path("/bin"),
    Path("/System"),
    Path("/usr/bin"),
)
_MACOS_READ_ROOTS = (
    Path("/System"),
    Path("/Library/Apple"),
    Path("/Library/Frameworks"),
    Path("/opt/homebrew/Cellar"),
    Path("/opt/homebrew/opt"),
    Path("/usr/lib"),
    Path("/usr/local/Cellar"),
    Path("/usr/local/opt"),
    Path("/usr/share"),
)
_MACOS_READ_FILES = (
    Path("/dev/null"),
    Path("/dev/random"),
    Path("/dev/urandom"),
    Path("/private/etc/hosts"),
    Path("/private/etc/protocols"),
    Path("/private/etc/resolv.conf"),
    Path("/private/etc/services"),
)
_LINUX_READ_ROOTS = (
    Path("/lib"),
    Path("/lib64"),
    Path("/usr/lib"),
    Path("/usr/lib64"),
    Path("/usr/share"),
    Path("/usr/local/lib"),
)
_LINUX_READ_FILES = (
    Path("/etc/hosts"),
    Path("/etc/ld.so.cache"),
    Path("/etc/nsswitch.conf"),
    Path("/etc/protocols"),
    Path("/etc/resolv.conf"),
    Path("/etc/services"),
)


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
            "writes": ["workspace", "private-temporary-directory"],
        }
