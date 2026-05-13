"""Phase 03 Guard local install, update, connect, and approval flow contracts."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import get_adapter
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import update_commands
from codex_plugin_scanner.guard.cli.approval_commands import run_approval_open_command
from codex_plugin_scanner.guard.cli.connect_flow import run_guard_connect_command
from codex_plugin_scanner.guard.cli.install_commands import apply_managed_install
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.runtime import GuardSyncNotAvailableError
from codex_plugin_scanner.guard.store import GuardStore


def _context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    workspace.mkdir(parents=True, exist_ok=True)
    return HarnessContext(home_dir=home, workspace_dir=workspace, guard_home=guard_home)


def test_update_failure_redacts_output_and_returns_retry_command(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.0")
    monkeypatch.setattr(update_commands, "_current_version_from_subprocess", lambda: "2.0.0")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pip")
    monkeypatch.setattr(update_commands.sys, "executable", "/opt/guard/bin/python")
    monkeypatch.setattr(
        update_commands.shutil,
        "which",
        lambda name: "/usr/local/bin/hol-guard" if name == "hol-guard" else None,
    )

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert command == ["/opt/guard/bin/python", "-m", "pip", "install", "--upgrade", "hol-guard"]
        return subprocess.CompletedProcess(command, 1, "", "AUTH_TOKEN=hunter2\nnetwork unreachable")

    monkeypatch.setattr(update_commands.subprocess, "run", fake_run)

    payload, exit_code = update_commands.run_guard_update(dry_run=False)

    assert exit_code == 1
    assert payload["status"] == "failed"
    assert payload["retry_command"] == "/opt/guard/bin/python -m pip install --upgrade hol-guard"
    assert "network unreachable" in str(payload["stderr"])
    assert "hunter2" not in json.dumps(payload)
    assert payload["binary_diagnostics"]["path_status"] == "path_mismatch"


def test_install_aliases_resolve_to_native_contracts() -> None:
    aliases = {
        "claude": "claude-code",
        "claude-code": "claude-code",
        "codex": "codex",
        "opencode": "opencode",
        "copilot": "copilot",
        "cursor": "cursor",
        "gemini": "gemini",
    }

    for alias, canonical in aliases.items():
        adapter = get_adapter(alias)
        contract = adapter.setup_contract()
        assert adapter.harness == canonical
        assert alias in contract.install_aliases
        assert contract.coverage.browser_fallback is True
        assert contract.coverage.native_hooks == contract.coverage.native_hooks


def test_managed_install_is_idempotent_and_uninstall_tracks_guard_owned_state(tmp_path: Path) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)

    first = apply_managed_install(
        "install", "opencode", False, context, store, str(context.workspace_dir), "2026-05-12T00:00:00Z"
    )
    second = apply_managed_install(
        "install", "opencode", False, context, store, str(context.workspace_dir), "2026-05-12T00:00:01Z"
    )
    removed = apply_managed_install(
        "uninstall",
        "opencode",
        False,
        context,
        store,
        str(context.workspace_dir),
        "2026-05-12T00:00:02Z",
    )

    assert first["managed_install"]["harness"] == "opencode"
    assert second["managed_install"]["config_path"] == first["managed_install"]["config_path"]
    assert removed["managed_install"]["active"] is False
    assert store.get_managed_install("opencode")["active"] is False


def test_connect_free_plan_error_keeps_local_pairing_successful(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")

    class DaemonClient:
        daemon_url = "http://127.0.0.1:4781"

        def create_connect_request(self, *, sync_url: str, allowed_origin: str) -> dict[str, object]:
            return {
                "request_id": "connect-free-plan",
                "pairing_secret": "pairing-secret",
                "expires_at": "2026-05-12T00:05:00Z",
            }

        def report_connect_result(
            self,
            *,
            request_id: str,
            status: str,
            milestone: str,
            reason: str | None = None,
            sync: dict[str, object] | None = None,
        ) -> dict[str, object]:
            return {
                "request_id": request_id,
                "status": status,
                "milestone": milestone,
                "reason": reason,
                "completed_at": "2026-05-12T00:00:10Z",
                "expires_at": "2026-05-12T00:05:00Z",
                "proof": sync or {},
            }

    monkeypatch.setattr("codex_plugin_scanner.guard.cli.connect_flow.ensure_guard_daemon", lambda guard_home: "ok")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.connect_flow.load_guard_surface_daemon_client",
        lambda guard_home: DaemonClient(),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.connect_flow.wait_for_connect_transition",
        lambda **kwargs: {
            "request_id": "connect-free-plan",
            "status": "connected",
            "milestone": "first_sync_pending",
            "completed_at": "2026-05-12T00:00:10Z",
            "proof": {},
        },
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.connect_flow.sync_runtime_session",
        lambda current_store, *, session: {
            "runtime_session_id": "guard-session-1",
            "runtime_session_synced_at": "2026-05-12T00:00:11Z",
            "runtime_sessions_visible": 1,
        },
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.connect_flow.sync_receipts",
        lambda current_store: (_ for _ in ()).throw(GuardSyncNotAvailableError("HTTP Error 403: plan required")),
    )

    payload = run_guard_connect_command(
        guard_home=tmp_path / "guard-home",
        store=store,
        sync_url="https://hol.org/api/guard/receipts/sync",
        connect_url="https://hol.org/guard/connect",
        opener=lambda url: False,
        wait_timeout_seconds=1,
    )

    assert payload["connected"] is True
    assert payload["sync_available"] is False
    assert payload["status"] == "connected"
    assert payload["milestone"] == "sync_not_available"
    assert payload["sync_message"] == "Local Guard is connected. Shared cloud sync needs a paid Guard plan."
    assert payload["next_action"]["label"] == "Copy pairing URL"


def test_approval_open_repairs_stale_local_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    request = GuardApprovalRequest(
        request_id="request-1",
        harness="codex",
        artifact_id="artifact-1",
        artifact_name="Tool",
        artifact_hash="hash",
        policy_action="block",
        recommended_scope="artifact",
        changed_fields=(),
        source_scope="local",
        config_path="config.toml",
        review_command="hol-guard approvals approve request-1",
        approval_url="http://127.0.0.1:4000/approvals/request-1",
    )
    store.add_approval_request(request, "2026-05-12T00:00:00Z")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.approval_commands.load_guard_daemon_url",
        lambda guard_home: "http://127.0.0.1:4781",
    )

    payload, exit_code = run_approval_open_command(argparse.Namespace(request_id="request-1"), store=store)

    assert exit_code == 0
    assert payload["approval_url"] == "http://127.0.0.1:4781/approvals/request-1"
    assert payload["repaired"] is True
