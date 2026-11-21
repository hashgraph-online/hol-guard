"""Keep a host Guard's package shims out of the processes Gauntlet launches.

A package shim hands a launch to the host's own Guard runtime. A case is
judged by the Guard its fixture installed, so a host shim in front of Bun,
npm or pip would put the host's Guard in the way of the case's own launches
and of every package command the agent runs. The SDK's ``omp`` launcher is
``#!/usr/bin/env bun``, so even ``omp --version`` would reach the host shim.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

_SHIM_DIRECTORY = ("package-shims", "bin")


def _is_shim_directory(entry: str) -> bool:
    parts = Path(os.path.normcase(entry)).parts[-2:]
    return tuple(os.path.normcase(part) for part in parts) == tuple(os.path.normcase(part) for part in _SHIM_DIRECTORY)


def without_package_shims(path: str) -> str:
    """``path`` without the host Guard's package-shim directories."""
    return os.pathsep.join(entry for entry in path.split(os.pathsep) if not _is_shim_directory(entry))


def prepend_path(directory: str, path: str) -> str:
    """``directory`` ahead of ``path``, with no empty entry when ``path`` is empty."""
    return directory + os.pathsep + path if path else directory


def omp_version(executable: str) -> str:
    """``omp --version`` with the host's package shims off PATH."""
    environment = dict(os.environ, PATH=without_package_shims(os.environ.get("PATH", "")))
    return subprocess.check_output([executable, "--version"], text=True, timeout=15, env=environment).strip()
