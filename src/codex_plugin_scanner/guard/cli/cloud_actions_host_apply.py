"""Write, and put back, the one settings entry that adds Cloud actions to an AI tool.

Guard's native runtime does the writing: `apply_host_config` asks it to write
the file a preview rendered, and the native side does so only if the file
still holds the bytes that preview read, since AI tools such as Claude Code
rewrite their settings while they run. It keeps a copy of the previous file in
the Guard home, moves the new file into place in one step, reads it back, and
puts the previous file back if it does not read back as rendered.

`restore_host_config` asks it to undo the most recent write for an AI tool.
While the file still holds exactly what Guard wrote, the earlier copy is put
back as it was; when the file has changed since, only Guard's entry is put back
as it was (or removed) and everything else edited since stays; if Guard's entry
itself was changed, nothing is touched. A settings file that is a link is
refused.

This module only validates the request, asks the native runtime and turns its
answer into a result or an error to show.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .cloud_actions_host_config import HostConfigPlan, host_native_answer, supported_tool


class HostConfigWriteError(Exception):
    """The settings file was not changed; `reason` says why."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class HostConfigRestore:
    """What `restore_host_config` did.

    `scope` is "file" when the whole earlier file was put back, "entry" when only Guard's entry was.
    """

    path: Path
    removed_file: bool
    scope: Literal["file", "entry"]
    entry_removed: bool


def apply_host_config(plan: HostConfigPlan, *, guard_home: Path) -> None:
    """Write `plan.after` to `plan.path` if the file is still as previewed."""

    if not plan.changes or plan.after is None:
        raise ValueError("Only a plan that changes the file can be applied.")
    try:
        after = plan.after.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Only a plan that changes the file can be applied.") from None
    answer = host_native_answer(
        {
            "op": "apply",
            "ai_tool": plan.ai_tool,
            "path": os.path.abspath(plan.path),
            "guard_home": os.path.abspath(guard_home),
            "entry": dict(plan.entry),
            "action": plan.action,
            "before_sha256": plan.before_sha256,
            "after": after,
        }
    )
    _raise_refusal(answer, plan.path)
    if answer is None or answer.get("ok") is not True:
        raise _unavailable(plan.path)


def restore_host_config(ai_tool: str, *, path: Path, guard_home: Path) -> HostConfigRestore | None:
    """Undo Guard's most recent write to `path`; None when there is nothing to undo."""

    supported_tool(ai_tool)
    answer = host_native_answer(
        {
            "op": "restore",
            "ai_tool": ai_tool,
            "path": os.path.abspath(path),
            "guard_home": os.path.abspath(guard_home),
        }
    )
    _raise_refusal(answer, path)
    restored = answer.get("restored", False) if answer is not None else False
    if restored is None:
        return None
    if not isinstance(restored, dict):
        raise _unavailable(path)
    scope, removed_file, entry_removed = (
        restored.get("scope"),
        restored.get("removed_file"),
        restored.get("entry_removed"),
    )
    if scope not in {"file", "entry"} or not isinstance(removed_file, bool) or not isinstance(entry_removed, bool):
        raise _unavailable(path)
    return HostConfigRestore(
        path=path,
        removed_file=removed_file,
        scope="file" if scope == "file" else "entry",
        entry_removed=entry_removed,
    )


def _raise_refusal(answer: dict[str, object] | None, path: Path) -> None:
    error = answer.get("error") if answer is not None else None
    if not isinstance(error, dict):
        return
    reason, message = error.get("reason"), error.get("message")
    if not isinstance(reason, str) or not isinstance(message, str):
        raise _unavailable(path)
    raise HostConfigWriteError(reason, message)


def _unavailable(path: Path) -> HostConfigWriteError:
    return HostConfigWriteError(
        "native_unavailable",
        f"Guard's native runtime is not available, so {path} was left as it is.",
    )


__all__ = [
    "HostConfigRestore",
    "HostConfigWriteError",
    "apply_host_config",
    "restore_host_config",
]
