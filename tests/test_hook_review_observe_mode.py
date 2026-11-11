"""Watch-only behavior for resident hook output review."""

from __future__ import annotations

from typing import Protocol

from codex_plugin_scanner.guard.hook_review.hook_worker import HookWorker


class _Metrics:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def record(self, **kwargs: object) -> None:
        self.calls.append(kwargs)


class _DaemonServerAccess(Protocol):
    auth_token: str
    hook_worker: HookWorker
