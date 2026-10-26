"""Watch/observe Grok hooks must allow instead of deny."""

from __future__ import annotations

from codex_plugin_scanner.guard.adapters.grok_hooks import (
    grok_hook_response_from_guard,
)


def test_watch_mode_never_denies_review_or_block() -> None:
    for action in ("review", "require-reapproval", "sandbox-required", "block"):
        payload = grok_hook_response_from_guard(
            policy_action=action,
            reason="Would have stopped this in Protected.",
            recording_only=True,
        )
        assert payload == {"decision": "allow"}, action
