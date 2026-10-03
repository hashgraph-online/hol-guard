"""Bounded execution context captured by the outer host hook bridge."""

from __future__ import annotations

import hashlib
import json
import os

HOOK_EXECUTION_ENVIRONMENT_KEY = "guard_execution_environment"
_GIT_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})


def git_config_no_system_enabled(value: str | None) -> bool:
    """Match Git's accepted truthy spellings for GIT_CONFIG_NOSYSTEM."""
    return value is not None and value.casefold() in _GIT_TRUE_VALUES


def collect_hook_execution_environment() -> dict[str, object]:
    active = {key: value for key, value in os.environ.items() if value}
    return {
        "path": os.environ.get("PATH", ""),
        "home": os.environ.get("HOME"),
        "git_pager_disabled": "GIT_PAGER" in os.environ and os.environ["GIT_PAGER"] in {"", "cat"},
        "pager_disabled": "PAGER" in os.environ and os.environ["PAGER"] in {"", "cat"},
        "environment_names": sorted(active),
        "xdg_config_home": os.environ.get("XDG_CONFIG_HOME") or None,
        "git_config_no_system": git_config_no_system_enabled(os.environ.get("GIT_CONFIG_NOSYSTEM")),
        "environment_digest": hashlib.sha256(
            json.dumps(active, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }


def stamp_hook_input_text(text: str) -> str:
    try:
        payload = json.loads(text)
    except (ValueError, TypeError):
        return text
    if not isinstance(payload, dict):
        return text
    payload[HOOK_EXECUTION_ENVIRONMENT_KEY] = collect_hook_execution_environment()
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
