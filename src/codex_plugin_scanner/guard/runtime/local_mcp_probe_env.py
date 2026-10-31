"""Probe environment isolation for local MCP catalog discovery."""

from __future__ import annotations

import os
from pathlib import Path


def probe_search_path() -> str:
    """PATH for MCP probes, without Guard package-shim wrappers."""

    fallback = os.environ.get("PATH", "/usr/bin:/bin:/opt/homebrew/bin:/usr/local/bin")
    filtered = [entry for entry in fallback.split(os.pathsep) if entry and not _is_package_shim_dir(entry)]
    for extra in ("/usr/bin", "/bin", "/opt/homebrew/bin", "/usr/local/bin"):
        if extra not in filtered and Path(extra).is_dir():
            filtered.append(extra)
    return os.pathsep.join(filtered)


def is_package_shim_executable(path: str) -> bool:
    candidate = Path(path)
    parent = candidate.parent
    return parent.name == "bin" and parent.parent.name == "package-shims"


def _is_package_shim_dir(entry: str) -> bool:
    path = Path(entry)
    return path.name == "bin" and path.parent.name == "package-shims"
