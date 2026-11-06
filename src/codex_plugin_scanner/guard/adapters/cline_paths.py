"""Resolve Cline-owned data, hook, and plugin locations without executing Cline.

The native ``cline_paths`` kind owns the destination checks; this module reads
the environment overrides and the working directory the resident cannot see.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .base import HarnessContext


def _configured(variable: str) -> str:
    value = os.environ.get(variable, "").strip()
    return os.path.join(os.getcwd(), os.path.expanduser(value)) if value else ""


def ask_cline_paths(context: HarnessContext, op: str, **fields: Any) -> dict[str, Any]:
    """One ``cline_paths`` answer; a refusal or an unavailable runtime raises ``RuntimeError``."""

    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    request = {
        "op": op,
        "home": str(context.home_dir.absolute()),
        "guard_home": str(context.guard_home.absolute()),
        "cwd": os.getcwd(),
        "data_dirs": [_configured("CLINE_DATA_DIR"), _configured("CLINE_DIR")],
        **fields,
    }
    try:
        answer = native_runner_authority("cline_paths", request, guard_home=context.guard_home)
    except NativeRunnerAuthorityError as exc:
        raise RuntimeError("Cline paths require the HOL Guard native runtime") from exc
    refusal = answer.get("refusal")
    if isinstance(refusal, str):
        raise RuntimeError(refusal)
    return answer


def _path(value: object) -> Path:
    if not isinstance(value, str):
        raise RuntimeError("HOL Guard native runtime returned a malformed Cline path")
    return Path(value)


def cline_data_dir(context: HarnessContext) -> Path:
    """Cline's data directory; an override counts only while it stays inside the home."""

    return _path(ask_cline_paths(context, "roots").get("data_dir"))


def cline_hook_roots(context: HarnessContext) -> tuple[Path, ...]:
    """Return global hook roots used by Cline UI and data-dir based runtimes."""

    roots = ask_cline_paths(context, "roots").get("hook_roots")
    return tuple(_path(root) for root in (roots if isinstance(roots, list) and roots else (None,)))


def cline_plugin_root(context: HarnessContext) -> Path:
    """Return the Guard-owned plugin root under Cline's selected data directory."""

    return _path(ask_cline_paths(context, "plugin_root").get("path"))


def ensure_safe_cline_destination(context: HarnessContext, path: Path) -> Path:
    """Validate nodes from the trusted root down and return the rebuilt destination."""

    return _path(ask_cline_paths(context, "check", path=os.fspath(path)).get("path"))


__all__ = [
    "ask_cline_paths",
    "cline_data_dir",
    "cline_hook_roots",
    "cline_plugin_root",
    "ensure_safe_cline_destination",
]
