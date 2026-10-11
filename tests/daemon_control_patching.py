"""Patch a daemon server global in every module that holds a binding of it.

The daemon server's control-plane routes live in ``server_control_*`` modules that
import the same collaborators the server does, so a test that replaces a collaborator
must replace each module's binding.
"""

from __future__ import annotations

import importlib
from typing import Any

import pytest

_MODULES = (
    "codex_plugin_scanner.guard.daemon.server",
    "codex_plugin_scanner.guard.daemon.server_common",
    "codex_plugin_scanner.guard.daemon.server_control_cloud_connect",
    "codex_plugin_scanner.guard.daemon.server_control_cloud_sync",
    "codex_plugin_scanner.guard.daemon.server_control_connect_flow",
    "codex_plugin_scanner.guard.daemon.server_control_connect_state",
    "codex_plugin_scanner.guard.daemon.server_control_headless",
    "codex_plugin_scanner.guard.daemon.server_control_misc",
    "codex_plugin_scanner.guard.daemon.server_control_repair",
    "codex_plugin_scanner.guard.daemon.server_control_supply_chain",
)


def patch_daemon_global(monkeypatch: pytest.MonkeyPatch, name: str, value: Any, *, raising: bool = True) -> None:
    patched = False
    for module_name in _MODULES:
        module = importlib.import_module(module_name)
        if hasattr(module, name):
            monkeypatch.setattr(module, name, value)
            patched = True
    if not patched:
        monkeypatch.setattr(importlib.import_module(_MODULES[0]), name, value, raising=raising)
