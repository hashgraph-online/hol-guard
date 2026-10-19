"""Trusted task write limits installed into an isolated product Guard home."""

from __future__ import annotations

import os
import re
from pathlib import Path

from .contracts import canonical_json


def _valid_names(names: tuple[str, ...]) -> bool:
    return (isinstance(names, tuple) and len(names) <= 128
            and all(isinstance(name, str)
                    and re.fullmatch(r"[A-Za-z0-9_.:/-]{1,256}", name) for name in names)
            and len(set(names)) == len(names))


def task_write_policy(*, max_writes: int | None,
                      read_only_tools: tuple[str, ...],
                      reserved_record_ids: tuple[str, ...],
                      required_source_ids: tuple[str, ...],
                      tool_write_limits: dict[str, int] | None) -> dict | None:
    """Validate only operator-supplied task limits, never model or MCP content."""
    limits = {} if tool_write_limits is None else tool_write_limits
    groups = (read_only_tools, reserved_record_ids, required_source_ids)
    if max_writes is None:
        if any(groups) or limits:
            raise ValueError("task write policy requires a bounded maximum")
        return None
    if (type(max_writes) is not int or not 1 <= max_writes <= 1000
            or not read_only_tools or not all(_valid_names(names) for names in groups)
            or not isinstance(limits, dict) or len(limits) > 128
            or any(not isinstance(name, str)
                   or not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,256}", name)
                   or type(limit) is not int or not 1 <= limit <= max_writes
                   for name, limit in limits.items())
            or (limits and sum(limits.values()) < max_writes)):
        raise ValueError("bounded trusted task write policy required")
    return {
        "schema": "guard-mcp-task-write-budget.v1",
        "max_writes": max_writes,
        "read_only_tools": list(read_only_tools),
        "reserved_record_ids": list(reserved_record_ids),
        "required_source_ids": list(required_source_ids),
        "tool_write_limits": dict(limits),
    }


def install_task_write_policy(guard_home: Path, uid: int, policy: dict | None) -> None:
    if policy is None:
        return
    path = guard_home / "mcp-task-write-budget.json"
    with path.open("x", encoding="utf-8") as stream:
        stream.write(canonical_json(policy))
    path.chmod(0o600)
    os.chown(path, uid, uid)
