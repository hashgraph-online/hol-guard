"""Grok managed state and runtime hook verification."""

import json
from pathlib import Path

from .base import HarnessContext
from .grok_config import GUARD_HOOK_PRETOOL_FILE, GUARD_HOOK_PROMPT_FILE


def _prior_compat_hooks_from_state(
    state_path: Path,
    *,
    payload: dict[str, object] | None = None,
) -> dict[str, str | None]:
    if payload is None:
        if not state_path.is_file():
            return {}
        try:
            payload = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
    raw = payload.get("prior_compat_hooks") if isinstance(payload, dict) else None
    if not isinstance(raw, dict):
        return {}
    restored: dict[str, str | None] = {}
    for key, value in raw.items():
        if isinstance(key, str) and (value is None or isinstance(value, str)):
            restored[key] = value
    return restored


def grok_runtime_hooks_verified(context: HarnessContext) -> bool:
    """Return whether Grok catch-all PreToolUse and prompt screening hooks are installed.

    Managed permission rules in ``managed_config.toml`` are a second layer. Missing
    that file must not fail machine-wide local protection health while hooks still
    intercept every tool.
    """

    from ..cli.install_commands import _grok_pretool_is_catchall, _grok_prompt_hook_is_observe
    from .grok import GrokHarnessAdapter

    hooks_dir = GrokHarnessAdapter._hooks_dir(context)
    return _grok_pretool_is_catchall(hooks_dir / GUARD_HOOK_PRETOOL_FILE, context) and _grok_prompt_hook_is_observe(
        hooks_dir / GUARD_HOOK_PROMPT_FILE, context
    )
