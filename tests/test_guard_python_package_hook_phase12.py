"""Phase 12 Python package-hook proofs for exec flows."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.store import GuardStore

from .guard_python_phase12_support import (
    WORKSPACE_ID,
    bundle_response_fixture,
    package_fixture,
)


def _write_codex_pre_tool_payload(path: Path, workspace_dir: Path, command: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "session_id": "session-1",
                "turn_id": "turn-1",
                "cwd": str(workspace_dir),
                "hook_event_name": "PreToolUse",
                "model": "gpt-5.4",
                "permission_mode": "bypassPermissions",
                "tool_name": "Bash",
                "tool_input": {"command": command},
                "tool_use_id": "call-1",
            }
        ),
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    ("command", "package_name", "version"),
    [
        ("pipx run httpie==3.2.2", "httpie", "3.2.2"),
        ("uvx ruff==0.6.9", "ruff", "0.6.9"),
    ],
)
def test_guard_hook_blocks_python_exec_flows_before_subprocess(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    command: str,
    package_name: str,
    version: str,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    payload_path = workspace_dir / "hook-event.json"
    _write_codex_pre_tool_payload(payload_path, workspace_dir, command)
    store = GuardStore(home_dir)
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "demo-token",
        "2026-05-19T00:00:00Z",
        workspace_id=WORKSPACE_ID,
    )
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        bundle_response_fixture(
            packages=[
                package_fixture(
                    name=package_name,
                    version=version,
                    default_action="block",
                    recommended_fix_version=None,
                )
            ]
        ),
        "2026-05-19T00:00:00Z",
    )
    (home_dir / "config.toml").write_text("approval_wait_timeout_seconds = 0\n", encoding="utf-8")
    monkeypatch.setenv("CODEX_MANAGED_BY_BUN", "1")
    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")

    def fail_daemon(_home: Path) -> object:
        raise RuntimeError("no daemon client")

    monkeypatch.setattr(guard_commands_module, "load_guard_surface_daemon_client", fail_daemon)

    def fail_subprocess(*args: object, **kwargs: object) -> object:
        raise AssertionError("blocked python exec flow must not launch a subprocess")

    monkeypatch.setattr(guard_commands_module.subprocess, "run", fail_subprocess)

    rc = main(
        [
            "guard",
            "hook",
            "--harness",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--event-file",
            str(payload_path),
        ]
    )
    captured = capsys.readouterr()

    assert rc == 2
    assert "blocked" in captured.err.lower()
    evidence = store.list_evidence()
    assert evidence
    assert evidence[0]["category"] == "supply-chain"
