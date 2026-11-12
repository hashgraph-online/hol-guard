"""The managed Grok client only carries constants, and fails closed when run on its own."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge import _render_bounded_hook_script


def _run_client(tmp_path: Path, event: object) -> dict[str, object]:
    script = tmp_path / "grok.py"
    script.write_text(
        _render_bounded_hook_script(guard_home=tmp_path / "guard", harness="grok", timeout_seconds=8),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [sys.executable, "-I", str(script), "{}"],
        input=json.dumps({"hook_event_name": event, "tool_name": "Write"}),
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    payload = json.loads(completed.stdout)
    assert isinstance(payload, dict)
    return payload


@pytest.mark.parametrize("event", ["PreToolUse", "pre_tool_use", "UserPromptSubmit", "PermissionRequest", None, 7])
def test_a_client_run_without_the_runtime_denies_a_deciding_hook(tmp_path: Path, event: object) -> None:
    assert _run_client(tmp_path, event)["decision"] == "deny"


@pytest.mark.parametrize("event", ["SessionStart", "post_tool_use", "PermissionDenied"])
def test_a_client_run_without_the_runtime_leaves_an_observed_hook_alone(tmp_path: Path, event: str) -> None:
    assert _run_client(tmp_path, event)["decision"] == "allow"


def test_the_rendered_client_names_its_home_harness_and_timeout(tmp_path: Path) -> None:
    source = _render_bounded_hook_script(guard_home=tmp_path / "guard", harness="Grok", timeout_seconds=2.5)

    assert f"GUARD_HOME = {json.dumps(str((tmp_path / 'guard').resolve()))}" in source
    assert 'HARNESS = "grok"' in source
    assert "TIMEOUT_SECONDS = 2.5" in source
    assert "urllib" not in source
