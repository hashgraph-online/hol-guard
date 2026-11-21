"""Patch CLI facade names that sticky-sync into hook modules."""

from __future__ import annotations

import sys
from collections.abc import Callable
from typing import Any


def isolate_terminal_block_patches(monkeypatch: Any, unexpected: Callable[..., object], *, launcher: str) -> None:
    from codex_plugin_scanner.guard.cli import _commands_shared as shared
    from codex_plugin_scanner.guard.cli import commands as commands_module
    from codex_plugin_scanner.guard.cli import commands_support_interaction as interaction
    from codex_plugin_scanner.guard.codex_hook_launch_runtime import LAUNCHER_ARGS

    for module in (commands_module, shared):
        monkeypatch.setattr(module, "ensure_guard_daemon", unexpected)
        monkeypatch.setattr(module, "queue_blocked_approvals", unexpected)
        monkeypatch.setattr(module, "wait_for_approval_requests", unexpected)
    monkeypatch.setattr(interaction, "wait_for_approval_requests", unexpected)
    real_run = commands_module.subprocess.run

    def run_launcher(command: object, *args: Any, **kwargs: Any) -> object:
        # Publication needs the native launcher to build the contained sink command.
        if command == [launcher, *LAUNCHER_ARGS]:
            return real_run(command, *args, **kwargs)  # type: ignore[call-overload]
        raise AssertionError("blocked request must not launch a tool subprocess")

    monkeypatch.setattr(commands_module.subprocess, "run", run_launcher)


def restore_cli_facade_approval_hooks() -> None:
    from codex_plugin_scanner.guard.approvals import queue_blocked_approvals, wait_for_approval_requests
    from codex_plugin_scanner.guard.cli.commands_support import _sync_namespace
    from codex_plugin_scanner.guard.native_daemon_manage import ensure_guard_daemon

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
