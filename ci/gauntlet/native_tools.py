"""Scope rules for benign first-contact native-tool scenarios."""

from __future__ import annotations

from typing import Any

from .catalog import Scenario

PRIVATE_TEMP_ROOTS = ("/tmp/", "/private/tmp/", "/var/folders/", "/private/var/folders/")


def native_tools_scope_error(scenario: Scenario, calls: list[dict[str, Any]], case: dict[str, Any]) -> str | None:
    """Return why the model left the scenario, or None when it stayed inside the ordinary task.

    Product false positives are only meaningful when the model really did the intended work, so a
    deviation is reported as not-exercised and retried rather than blamed on Guard.
    """
    allowed = set(scenario.required_tools) | ({"bash"} if scenario.commands else set())
    if any(call["name"] not in allowed for call in calls):
        return "the model used a tool outside the scenario"
    if not set(scenario.required_tools) <= {call["name"] for call in calls}:
        return "the model did not use every tool the scenario names"
    listed = set(scenario.commands)
    for call in calls:
        if call["name"] == "bash" and call["args"].get("command") not in listed:
            return "the model ran a shell command the scenario did not list"
    ran = {call["args"].get("command") for call in calls if call["name"] == "bash"}
    if listed - ran:
        return "the model skipped a listed shell command"
    if any(call["name"] == "bash" for call in calls) != bool(scenario.commands):
        return "the shell commands were omitted or unexpected"
    if "private-temp-write" in scenario.id:
        writes = [c for c in calls if c["name"] == "write"]
        for call in writes:
            path = str(call["args"].get("path", call["args"].get("file_path", "")))
            if not path.startswith(PRIVATE_TEMP_ROOTS):
                return "the model wrote outside the private temporary directory"
    return None


def cleanup_private_temp(events: list[dict[str, Any]]) -> None:
    """Remove scratch directories a model created under the system temp area, and only those.

    A directory qualifies only when it is a direct, non-symlink child of a system temp root, is
    owned by this user with mode 0700 and holds nothing but regular files.
    """
    import os
    import shutil
    from pathlib import Path

    roots = {Path(root.rstrip("/")) for root in PRIVATE_TEMP_ROOTS[:2]} | {Path(os.environ.get("TMPDIR", "/tmp"))}
    for event in events:
        args = event.get("args") if event.get("type") == "tool_execution_start" else None
        if event.get("toolName") != "write" or not isinstance(args, dict):
            continue
        target = args.get("path", args.get("file_path"))
        if not isinstance(target, str):
            continue
        directory = Path(target).parent
        try:
            info = directory.lstat()
            if (
                directory.parent not in roots
                or directory.is_symlink()
                or not directory.is_dir()
                or info.st_uid != os.getuid()
                or info.st_mode & 0o077
                or any(not child.is_file() or child.is_symlink() for child in directory.iterdir())
            ):
                continue
            shutil.rmtree(directory)
        except OSError:
            continue
