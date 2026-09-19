"""Bounded ownership probe for detached approval workers in policy unit tests."""

from __future__ import annotations

import subprocess
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import manager


@dataclass
class DetachedApprovalProbe:
    requests: int = 0
    live_child_observed: bool = False
    children_reaped: bool = False


def _is_expected_ensure(command: object, guard_home: Path) -> bool:
    if not isinstance(command, (list, tuple)) or not all(isinstance(part, str) for part in command):
        return False
    for index in range(len(command) - 2):
        if tuple(command[index:index + 3]) != ("guard", "daemon", "ensure"):
            continue
        arguments = command[index + 3:]
        if "--guard-home" not in arguments or "--wake-token" not in arguments:
            return False
        home_index = arguments.index("--guard-home")
        token_index = arguments.index("--wake-token")
        return (
            home_index + 1 < len(arguments) and arguments[home_index + 1] == str(guard_home)
            and token_index + 1 < len(arguments) and bool(arguments[token_index + 1])
        )
    return False


@contextmanager
def capture_detached_approval_launches(monkeypatch: pytest.MonkeyPatch, guard_home: Path):
    original = subprocess.Popen
    children: list[subprocess.Popen[bytes]] = []
    probe = DetachedApprovalProbe()

    def launch(command, *args, **kwargs):
        if not _is_expected_ensure(command, guard_home):
            return original(command, *args, **kwargs)
        assert kwargs.get("start_new_session") is True
        assert all(kwargs.get(key) == subprocess.DEVNULL for key in ("stdin", "stdout", "stderr"))
        probe.requests += 1
        # Own a harmless real process instead of allowing an unowned daemon tree.
        # The actual scheduler, reservation, command construction and Popen call
        # have already run; this is an explicit executable double for that call.
        child = original(
            [sys.executable, "-I", "-c", "import time; time.sleep(20)"],
            *args,
            **kwargs,
        )
        children.append(child)
        probe.live_child_observed = probe.live_child_observed or child.poll() is None
        return child

    with monkeypatch.context() as patch:
        patch.setattr(manager.subprocess, "Popen", launch)
        try:
            yield probe
        finally:
            for child in children:
                if child.poll() is None:
                    child.terminate()
                try:
                    child.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=1)
            probe.children_reaped = all(child.poll() is not None for child in children)
