"""Remove Guard-owned entries from a Cursor hooks.json payload, keeping third-party hooks."""

from __future__ import annotations

import json
from pathlib import Path

from .adapter_safe_output import write_text_at_authorized_path
from .cursor_hook_config import _is_managed_hook_entry


def _remove_managed_hook_entries(*, hooks_path: Path, script_path: Path) -> bool:
    try:
        payload = json.loads(hooks_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    cleaned, removed = _render_without_managed_hook_entries(payload, script_path=script_path)
    if not removed:
        return False
    if cleaned is None:
        hooks_path.unlink()
    else:
        write_text_at_authorized_path(hooks_path, json.dumps(cleaned, indent=2) + "\n")
    return True


def _render_without_managed_hook_entries(
    payload: object,
    *,
    script_path: Path,
) -> tuple[dict[str, object] | None, bool]:
    if not isinstance(payload, dict):
        return None, False
    hooks = payload.get("hooks")
    has_managed_hooks = False
    has_other_hooks = False
    if not isinstance(hooks, dict):
        return payload, False
    cleaned_hooks: dict[str, object] = {}
    managed_command = str(script_path.resolve())
    for event, entries in hooks.items():
        if isinstance(entries, list):
            filtered: list[object] = []
            for entry in entries:
                if _is_managed_hook_entry(entry, command=managed_command):
                    has_managed_hooks = True
                else:
                    filtered.append(entry)
            if filtered:
                cleaned_hooks[str(event)] = filtered
                has_other_hooks = True
        else:
            cleaned_hooks[str(event)] = entries
            has_other_hooks = True
    if not has_managed_hooks:
        return payload, False
    if has_other_hooks:
        payload["hooks"] = cleaned_hooks
        return payload, True
    return None, True
