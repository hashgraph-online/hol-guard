"""Patch CLI facade names that sticky-sync into hook modules."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


def isolate_terminal_block_patches(monkeypatch: Any, unexpected: Callable[..., object]) -> None:
    from codex_plugin_scanner.guard.cli import _commands_shared as shared
    from codex_plugin_scanner.guard.cli import commands as commands_module
    from codex_plugin_scanner.guard.cli import commands_hook_generic as generic
    from codex_plugin_scanner.guard.cli import commands_support_interaction as interaction

    monkeypatch.setattr(commands_module, "ensure_guard_daemon", unexpected)
    monkeypatch.setattr(commands_module, "queue_blocked_approvals", unexpected)
    monkeypatch.setattr(generic, "ensure_guard_daemon", unexpected)
    monkeypatch.setattr(generic, "queue_blocked_approvals", unexpected)
    monkeypatch.setattr(shared, "queue_blocked_approvals", unexpected)
    monkeypatch.setattr(interaction, "wait_for_approval_requests", unexpected)
