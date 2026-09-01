"""Health-only Codex hook intercept proof.

Authenticated Codex hook manifests remain the repair contract. Local protection
health only needs evidence that Guard still intercepts PreToolUse and
PermissionRequest on the live Codex config.
"""

from __future__ import annotations

from .adapters.base import HarnessContext
from .codex_hook_registration import live_guard_codex_hooks_intercept


def codex_runtime_hooks_verified(context: HarnessContext) -> bool:
    """Return whether live Codex hooks still intercept Guard's shell boundary."""

    from .adapters.codex import CodexHarnessAdapter, _json_object, _read_toml

    config_payload = _read_toml(CodexHarnessAdapter._hook_config_path(context))
    features = config_payload.get("features") if isinstance(config_payload, dict) else None
    toml_hooks = config_payload.get("hooks") if isinstance(config_payload, dict) else None
    json_hooks = _json_object(CodexHarnessAdapter._hooks_path(context)).get("hooks")
    hooks = toml_hooks if isinstance(toml_hooks, dict) else json_hooks
    hooks_enabled = not isinstance(features, dict) or features.get("hooks") is not False
    return bool(hooks_enabled) and live_guard_codex_hooks_intercept(hooks)


__all__ = ["codex_runtime_hooks_verified"]
