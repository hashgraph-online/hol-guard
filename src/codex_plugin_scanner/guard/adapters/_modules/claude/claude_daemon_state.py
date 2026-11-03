"""Validated daemon discovery state for Claude hook transport."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import parse_qs


def canonical_daemon_state_path(state_path: str | Path) -> Path:
    raw_path = str(state_path)
    if not raw_path or "\x00" in raw_path:
        raise ValueError("daemon state path must be a non-empty filesystem path")
    path = Path(raw_path)
    if not path.is_absolute() or path.name != "daemon-state.json":
        raise ValueError("daemon state path must be an absolute daemon-state.json path")
    return path


def state_path_for_query(state_path: str | Path, query: str) -> Path:
    path = canonical_daemon_state_path(state_path)
    guard_home_values = parse_qs(query).get("guard-home")
    if not guard_home_values or len(guard_home_values) != 1 or not guard_home_values[0]:
        raise ValueError("daemon hook query must bind one Guard home")
    guard_home_value = guard_home_values[0]
    if "\x00" in guard_home_value:
        raise ValueError("daemon hook query contains an invalid Guard home")
    guard_home = Path(guard_home_value)
    if not guard_home.is_absolute() or path.parent.resolve() != guard_home.resolve():
        raise ValueError("daemon state path does not match the hook Guard home")
    return path
