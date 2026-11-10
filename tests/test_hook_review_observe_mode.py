"""Watch-only behavior for resident hook output review."""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from http.client import HTTPResponse
from pathlib import Path
from typing import Protocol, cast

import pytest

from ci.guard_daemon_harness import GuardDaemonServer
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.store import GuardStore
from tests.daemon_hook_test_client import open_authenticated_claude_request


class _Metrics:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def record(self, **kwargs: object) -> None:
        self.calls.append(kwargs)


class _DaemonServerAccess(Protocol):
    auth_token: str
    hook_worker: HookWorker


