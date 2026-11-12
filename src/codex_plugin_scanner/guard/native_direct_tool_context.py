"""Caller routing facts that native request contexts are built from.

Python reports only the caller's routing environment. Filesystem, toolchain
identity, configuration and command verdicts belong to the resident.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from .native_git_execution_safety import _process_groups
from .native_request_context import _absolute_text

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
