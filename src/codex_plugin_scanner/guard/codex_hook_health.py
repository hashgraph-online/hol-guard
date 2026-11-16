"""Health-only Codex hook intercept proof.

Authenticated Codex hook manifests remain the repair contract. Local protection
health only needs evidence that Guard still intercepts PreToolUse and
PermissionRequest on the live Codex config; the runtime reads and decides it.
"""

from __future__ import annotations

from .harness.base import HarnessContext


def codex_runtime_hooks_verified(context: HarnessContext) -> bool:
    """Return whether live Codex hooks still intercept Guard's shell boundary."""

    from .codex_harness_client import live_hook_ask

    try:
        answer = live_hook_ask("runtime_hooks_verified", context)
    except Exception:
        return False
    return answer.get("verified") is True


__all__ = ["codex_runtime_hooks_verified"]
