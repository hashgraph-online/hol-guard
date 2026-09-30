"""Patch CLI facade names that sticky-sync into hook modules."""

from __future__ import annotations

import sys
from collections.abc import Callable
from typing import Any


def isolate_terminal_block_patches(monkeypatch: Any, unexpected: Callable[..., object]) -> None:
    from codex_plugin_scanner.guard.cli import _commands_shared as shared
    from codex_plugin_scanner.guard.cli import commands as commands_module
    from codex_plugin_scanner.guard.cli import commands_hook_generic as generic
    from codex_plugin_scanner.guard.cli import commands_support_interaction as interaction
    from codex_plugin_scanner.guard.cli.commands_hook_compat_loader import load_hook_compatibility_surface

    # Bootstrap the test oracle before the sentinel can be copied into a newly
    # imported module outside the facade's existing-module restore snapshots.
    assert load_hook_compatibility_surface() is not None

    for module in (commands_module, generic, shared):
        monkeypatch.setattr(module, "ensure_guard_daemon", unexpected)
        monkeypatch.setattr(module, "queue_blocked_approvals", unexpected)
        monkeypatch.setattr(module, "wait_for_approval_requests", unexpected)
    monkeypatch.setattr(interaction, "wait_for_approval_requests", unexpected)


def restore_cli_facade_approval_hooks() -> None:
    from codex_plugin_scanner.guard.approvals import queue_blocked_approvals, wait_for_approval_requests
    from codex_plugin_scanner.guard.cli.commands_support import _sync_namespace
    from codex_plugin_scanner.guard.daemon.manager import ensure_guard_daemon

    restored = {
        "ensure_guard_daemon": ensure_guard_daemon,
        "queue_blocked_approvals": queue_blocked_approvals,
        "wait_for_approval_requests": wait_for_approval_requests,
    }
    _sync_namespace(restored)
    prefix = "codex_plugin_scanner.guard.cli."
    for module in tuple(sys.modules.values()):
        if module is None:
            continue
        module_name = getattr(module, "__name__", "")
        if not module_name.startswith(prefix):
            continue
        for attr, value in restored.items():
            if hasattr(module, attr):
                setattr(module, attr, value)
