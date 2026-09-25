"""Installed lab accepts native Codex denials without accepting warnings."""

from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest


def _lab() -> ModuleType:
    path = Path(__file__).parent / "dockerlabs/command-extension-analytics/installed_server.py"
    spec = importlib.util.spec_from_file_location("installed_dockerlab_server", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("policy_action", "permission_decision", "accepted"),
    [
        ("review", "deny", True),
        (None, "deny", True),
        ("warn", "allow", False),
        ("warn", "deny", False),
        ("review", "allow", False),
    ],
)
def test_installed_codex_native_status_requires_explicit_denial(
    policy_action: str | None,
    permission_decision: str,
    accepted: bool,
) -> None:
    lab = _lab()
    response: dict[str, object] = {"hookSpecificOutput": {"permissionDecision": permission_decision}}
    if policy_action is not None:
        response["policy_action"] = policy_action
    completed = subprocess.CompletedProcess([], 0, json.dumps(response), "")
    lab.subprocess = SimpleNamespace(run=lambda *_args, **_kwargs: completed)

    if accepted:
        lab._run_installed_hook("codex", {}, expected_status=1)
    else:
        with pytest.raises(RuntimeError, match="installed codex hook returned 0, expected 1"):
            lab._run_installed_hook("codex", {}, expected_status=1)
