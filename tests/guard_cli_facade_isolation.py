"""Patch CLI facade names that sticky-sync into hook modules."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


def isolate_terminal_block_patches(monkeypatch: Any, unexpected: Callable[..., object]) -> None:
    from codex_plugin_scanner.guard.cli import _commands_shared as shared
    from codex_plugin_scanner.guard.cli import commands as commands_module
    from codex_plugin_scanner.guard.cli import commands_hook_generic as generic
    from codex_plugin_scanner.guard.cli import commands_support_interaction as interaction

    for module in (commands_module, generic, shared):
        monkeypatch.setattr(module, "ensure_guard_daemon", unexpected)
        monkeypatch.setattr(module, "queue_blocked_approvals", unexpected)
        monkeypatch.setattr(module, "wait_for_approval_requests", unexpected)
    monkeypatch.setattr(interaction, "wait_for_approval_requests", unexpected)
