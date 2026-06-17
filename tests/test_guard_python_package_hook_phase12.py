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


def _seed_guard_cloud(store, *, workspace_id=None, sync_url=None, token="demo-token", now="2026-05-19T00:00:00Z"):
    """Seed OAuth credentials (replaces legacy set_sync_credentials scaffolding).

    Also installs a test-only resolver override so sync-path exercises stay hermetic
    (no OAuth token refresh against the network). Tests that need real sync against a
    local server pass sync_url=<url>.
    """
    from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
    from codex_plugin_scanner.guard.runtime import runner as guard_runner_module

    dpop_key_material = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token=token,
        dpop_private_key_pem=dpop_key_material.private_key_pem,
        dpop_public_jwk=dpop_key_material.public_jwk,
        dpop_public_jwk_thumbprint=dpop_key_material.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id=workspace_id,
        now=now,
    )
    effective_sync_url = sync_url if sync_url is not None else "https://hol.org/api/guard/receipts/sync"
    guard_runner_module._test_sync_auth_context_override = {
        "sync_url": effective_sync_url,
        "access_token": token,
        "dpop_key_material": None,
    }


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
        ("pip install requests==2.31.0", "requests", "2.31.0"),
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
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
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

    payload = json.loads(captured.out)
    assert rc == 0
    assert captured.err == ""
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "blocked" in payload["hookSpecificOutput"]["permissionDecisionReason"].lower()
    evidence = store.list_evidence()
    assert evidence
    assert evidence[0]["category"] == "supply-chain"
