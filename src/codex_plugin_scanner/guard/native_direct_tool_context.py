"""Bound resident transport for verified local JavaScript execution contexts.

Python reports the caller's routing environment and presents the native shell
DTO. Filesystem, toolchain identity, configuration and command verdicts belong
to the resident. Missing or malformed replies cannot authorize a context.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from .native_git_execution_safety import _process_groups
from .native_request_context import (
    NativeRequestContextFailure,
    _absolute_text,
    _call,
    _decode_build,
)

if TYPE_CHECKING:
    from .runtime.shell_execution_context import ShellExecutionContext

_ENVIRONMENT_NAMES = frozenset(
    {
        "PATH",
        "HOME",
        "USERPROFILE",
        "SYSTEMROOT",
        "WINDIR",
        "XDG_CONFIG_HOME",
        "BUN_OPTIONS",
        "NODE_OPTIONS",
        "NODE_PATH",
        "BASH_ENV",
        "ENV",
        "PYTHONHOME",
        "PYTHONPATH",
        "RUBYLIB",
        "RUBYOPT",
        "SSH_ASKPASS",
        "CURL_CA_BUNDLE",
        "GH_CONFIG_DIR",
        "ALL_PROXY",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "NODE_EXTRA_CA_CERTS",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "ZDOTDIR",
        "all_proxy",
        "https_proxy",
        "http_proxy",
    }
)
_ENVIRONMENT_PREFIXES = ("GIT_", "BASH_FUNC_", "DYLD_", "LD_")
_BUDGET_MS = 9_000


def _facts(cwd: Path, home_dir: Path) -> dict[str, Any]:
    from . import shims
    from .package_shim_frozen import package_shim_interpreter

    return {
        "cwd": _absolute_text(cwd),
        "home_dir": _absolute_text(home_dir),
        "environment": {
            key: value
            for key, value in os.environ.items()
            if key in _ENVIRONMENT_NAMES
            or key.startswith(_ENVIRONMENT_PREFIXES)
            or key.casefold() in {"node_options", "node_path"}
            or key.casefold().startswith("npm_config_")
        },
        "caller_home": str(Path.home().absolute()),
        "temp_dir": tempfile.gettempdir(),
        "groups": _process_groups(),
        "launcher": {
            "python_executable": sys.executable,
            "interpreter": package_shim_interpreter(),
            "import_root": str(Path(shims.__file__).absolute().parents[2]),
            "frozen": bool(getattr(sys, "frozen", False)),
            "python_version": [sys.version_info.major, sys.version_info.minor],
        },
    }


def native_direct_tool_context(
    tool: Literal["vitest", "typescript"],
    command_text: str,
    *,
    cwd: Path | None,
    home_dir: Path,
) -> ShellExecutionContext | None:
    # Necessary literal fragments only: this avoids transport for impossible
    # inputs without granting a command verdict. Native parsing and proofs
    # still decide every candidate. Strip shell quoting/escaping conservatively.
    fragments = command_text.translate(str.maketrans("", "", "'\"\\\n\r")).casefold()
    if "cd" not in fragments or ("vitest" if tool == "vitest" else "tsc") not in fragments:
        return None

    from .runtime.shell_execution_context import _context_from_report

    try:
        payload = _call(
            {
                "kind": "direct_tool",
                "body": {"tool": tool, "script": command_text, "facts": _facts(cwd or home_dir, home_dir)},
            },
            source="direct_command",
            guard_home=None,
            budget_ms=_BUDGET_MS,
        )
        if isinstance(payload, NativeRequestContextFailure):
            return None
        if set(payload) != {"kind", "accepted", "context"} or payload["kind"] != "direct_tool":
            return None
        if payload["accepted"] is not True or not isinstance(payload["context"], dict):
            return None
        context = _decode_build(payload["context"])
        if context is None or context.shell is None:
            return None
        return _context_from_report(context.shell)
    except (OSError, RuntimeError, TypeError, ValueError, KeyError):
        return None


def native_trusted_tool_command(command: str, *, cwd: Path, home_dir: Path) -> bool:
    try:
        payload = _call(
            {"kind": "trusted_tool", "body": {"command": command, "facts": _facts(cwd, home_dir)}},
            source="direct_command",
            guard_home=None,
            budget_ms=_BUDGET_MS,
        )
        return (
            not isinstance(payload, NativeRequestContextFailure)
            and set(payload) == {"kind", "trusted"}
            and payload["kind"] == "trusted_tool"
            and payload["trusted"] is True
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return False
