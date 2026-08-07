"""Resolve Cline-owned data, hook, and plugin locations without executing Cline."""

from __future__ import annotations

import os
from pathlib import Path

from .base import HarnessContext


def _safe_configured_data_dir(context: HarnessContext, value: str) -> Path | None:
    candidate = Path(value).expanduser().resolve(strict=False)
    home = context.home_dir.resolve(strict=False)
    if candidate == home or candidate.is_relative_to(home):
        return candidate
    return None


def cline_data_dir(context: HarnessContext) -> Path:
    """Resolve a writable Cline data directory across current and legacy hosts.

    Environment overrides are honored only when they remain inside the user's
    home. This prevents an inherited environment variable from redirecting
    Guard-managed hook/plugin writes to an arbitrary filesystem location.
    """

    for variable in ("CLINE_DATA_DIR", "CLINE_DIR"):
        configured = os.environ.get(variable, "").strip()
        if configured:
            safe = _safe_configured_data_dir(context, configured)
            if safe is not None:
                return safe
    return context.home_dir / ".cline"


def cline_hook_roots(context: HarnessContext) -> tuple[Path, ...]:
    """Return global hook roots used by Cline UI and data-dir based runtimes."""

    data_hooks = cline_data_dir(context) / "hooks"
    candidates = (
        context.home_dir / "Documents" / "Cline" / "Hooks",
        data_hooks,
        context.home_dir / ".cline" / "hooks",
    )
    configured = any(
        os.environ.get(variable, "").strip()
        and _safe_configured_data_dir(context, os.environ[variable].strip()) == cline_data_dir(context)
        for variable in ("CLINE_DATA_DIR", "CLINE_DIR")
    )
    if configured:
        candidates = (data_hooks, *candidates)
    unique: list[Path] = []
    seen: set[str] = set()
    for path in candidates:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
    return tuple(unique)


def cline_plugin_root(context: HarnessContext) -> Path:
    """Return the Guard-owned plugin root under Cline's selected data directory."""

    root = cline_data_dir(context) / "plugins" / "hol-guard"
    ensure_safe_cline_destination(context, root / "index.js")
    return root


def is_cline_owned_path(context: HarnessContext, path: Path) -> bool:
    """Return true when a path is inside the user's writable Cline roots."""

    candidate = path.resolve(strict=False)
    roots = (context.home_dir.resolve(strict=False), cline_data_dir(context).resolve(strict=False))
    return any(candidate == root or candidate.is_relative_to(root) for root in roots)


def ensure_safe_cline_destination(context: HarnessContext, path: Path) -> None:
    """Reject writes outside known roots or through an existing symlink ancestor."""

    home = context.home_dir.resolve(strict=False)
    guard_home = context.guard_home.resolve(strict=False)
    data_root = cline_data_dir(context).resolve(strict=False)
    parent = path.parent.resolve(strict=False)
    permitted_roots = (home, guard_home, data_root)
    if not any(parent == root or parent.is_relative_to(root) for root in permitted_roots):
        raise RuntimeError("Cline destination escapes Guard-managed or configured Cline roots")

    lexical_roots = {context.home_dir.absolute(), context.guard_home.absolute(), cline_data_dir(context).absolute()}
    current = path.parent.absolute()
    while True:
        if current.exists() and current.is_symlink():
            raise RuntimeError(f"Cline destination parent is a symlink: {current}")
        if current in lexical_roots:
            break
        if current == current.parent:
            raise RuntimeError("Cline destination could not be anchored to a trusted root")
        current = current.parent
    if path.exists() and path.is_symlink():
        raise RuntimeError(f"Cline destination is a symlink: {path}")


__all__ = [
    "cline_data_dir",
    "cline_hook_roots",
    "cline_plugin_root",
    "ensure_safe_cline_destination",
    "is_cline_owned_path",
]
