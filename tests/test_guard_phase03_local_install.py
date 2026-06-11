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
from codex_plugin_scanner.guard.cli.install_commands import apply_managed_install
from codex_plugin_scanner.guard.models import GuardApprovalRequest
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
    monkeypatch.setattr(update_commands.sysconfig, "get_path", lambda name: "/opt/guard/bin")
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


def test_update_binary_diagnostics_accepts_same_environment_script(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.0")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pip")
    monkeypatch.setattr(update_commands.sys, "executable", "/opt/guard/bin/python")
    monkeypatch.setattr(update_commands.sysconfig, "get_path", lambda name: "/opt/guard/bin")
    monkeypatch.setattr(
        update_commands.shutil,
        "which",
        lambda name: "/opt/guard/bin/hol-guard" if name == "hol-guard" else None,
    )

    payload, exit_code = update_commands.run_guard_update(dry_run=True)

    assert exit_code == 0
    assert payload["binary_diagnostics"]["path_status"] == "matches_installer"
    assert payload["binary_diagnostics"]["expected_script_dir"] == "/opt/guard/bin"


def test_update_binary_diagnostics_keeps_venv_script_dir_without_resolving_python(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.0")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pip")
    monkeypatch.setattr(update_commands.sys, "executable", "/workspace/.venv/bin/python")
    monkeypatch.setattr(update_commands.sysconfig, "get_path", lambda name: "/workspace/.venv/bin")
    monkeypatch.setattr(
        update_commands.shutil,
        "which",
        lambda name: "/workspace/.venv/bin/hol-guard" if name == "hol-guard" else None,
    )

    payload, exit_code = update_commands.run_guard_update(dry_run=True)

    assert exit_code == 0
    assert payload["binary_diagnostics"]["path_status"] == "matches_installer"
    assert payload["binary_diagnostics"]["expected_script_dir"] == "/workspace/.venv/bin"


def test_update_binary_diagnostics_uses_python_scripts_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.0")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pip")
    monkeypatch.setattr(update_commands.sys, "executable", "/opt/python/bin/python")
    monkeypatch.setattr(update_commands.sysconfig, "get_path", lambda name: "/opt/python/scripts")
    monkeypatch.setattr(
        update_commands.shutil,
        "which",
        lambda name: "/opt/python/scripts/hol-guard" if name == "hol-guard" else None,
    )

    payload, exit_code = update_commands.run_guard_update(dry_run=True)

    assert exit_code == 0
    assert payload["binary_diagnostics"]["path_status"] == "matches_installer"
    assert payload["binary_diagnostics"]["expected_script_dir"] == "/opt/python/scripts"


def test_update_binary_diagnostics_treats_pipx_shim_as_healthy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.0")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")
    monkeypatch.setattr(
        update_commands.shutil,
        "which",
        lambda name: "/mock-home/.local/bin/hol-guard" if name == "hol-guard" else None,
    )

    payload, exit_code = update_commands.run_guard_update(dry_run=True)

    assert exit_code == 0
    assert payload["binary_diagnostics"]["path_status"] == "pipx_shim_detected"
    assert payload["binary_diagnostics"]["expected_script_dir"] is None


def test_update_skips_existing_local_source_install(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    source_dir = tmp_path / "src-install"
    source_dir.mkdir()
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.345")
    monkeypatch.setattr(
        update_commands,
        "_direct_url_payload",
        lambda: {"dir_info": {}, "url": source_dir.as_uri()},
    )
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")
    monkeypatch.setattr(
        update_commands.shutil,
        "which",
        lambda name: "/mock-home/.local/bin/hol-guard" if name == "hol-guard" else None,
    )

    payload, exit_code = update_commands.run_guard_update(dry_run=False)

    assert exit_code == 0
    assert payload["status"] == "skipped"
    assert payload["changed"] is False
    assert "disabled for local source installs" in str(payload["error"])
    assert payload["source_install"]["path_exists"] is True
    assert "version_check" not in payload


def test_update_repairs_missing_pipx_local_source_install(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    missing_dir = tmp_path / "missing-src-install"
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.345")
    monkeypatch.setattr(update_commands, "_current_version_from_subprocess", lambda: "2.0.489")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.489")
    monkeypatch.setattr(
        update_commands,
        "_direct_url_payload",
        lambda: {"dir_info": {}, "url": missing_dir.as_uri()},
    )
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")
    monkeypatch.setattr(
        update_commands.shutil,
        "which",
        lambda name: "/mock-home/.local/bin/hol-guard" if name == "hol-guard" else None,
    )

    captured_commands: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured_commands.append(command)
        return subprocess.CompletedProcess(command, 0, "installed hol-guard", "")

    monkeypatch.setattr(update_commands.subprocess, "run", fake_run)

    payload, exit_code = update_commands.run_guard_update(dry_run=False)

    assert exit_code == 0
    assert captured_commands[0] == ["pipx", "install", "--force", "hol-guard"]
    assert payload["recovery_source_install"] is True
    assert payload["source_install"]["path_exists"] is False
    assert payload["status"] == "updated"
    assert payload["message"] == "Updated HOL Guard from 2.0.345 to 2.0.489."


def test_update_repairs_missing_pip_local_source_install(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    missing_dir = tmp_path / "missing-src-install"
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.489")
    monkeypatch.setattr(update_commands, "_current_version_from_subprocess", lambda: "2.0.489")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.489")
    monkeypatch.setattr(
        update_commands,
        "_direct_url_payload",
        lambda: {"dir_info": {}, "url": missing_dir.as_uri()},
    )
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pip")
    monkeypatch.setattr(update_commands.sys, "executable", "/opt/guard/bin/python")

    captured_commands: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured_commands.append(command)
        return subprocess.CompletedProcess(command, 0, "installed hol-guard", "")

    monkeypatch.setattr(update_commands.subprocess, "run", fake_run)

    payload, exit_code = update_commands.run_guard_update(dry_run=False)

    assert exit_code == 0
    assert captured_commands[0] == [
        "/opt/guard/bin/python",
        "-m",
        "pip",
        "install",
        "--upgrade",
        "--force-reinstall",
        "hol-guard",
    ]
    assert payload["recovery_source_install"] is True
    assert payload["upgrade_source"] == "pypi"


def test_update_skips_pypi_recovery_when_missing_local_source_is_newer_than_pypi(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    missing_dir = tmp_path / "missing-dev-install"
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.1.0.dev0")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.489")
    monkeypatch.setattr(
        update_commands,
        "_direct_url_payload",
        lambda: {"dir_info": {}, "url": missing_dir.as_uri()},
    )
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")

    payload, exit_code = update_commands.run_guard_update(dry_run=True)

    assert exit_code == 0
    assert payload["command"] == ["pipx", "upgrade", "hol-guard"]
    assert payload.get("upgrade_source") is None


def test_update_does_not_skip_local_wheel_install(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    wheel = tmp_path / "hol-guard.whl"
    wheel.write_bytes(b"fake-wheel")
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.345")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.345")
    monkeypatch.setattr(
        update_commands,
        "_direct_url_payload",
        lambda: {
            "url": wheel.as_uri(),
            "archive_info": {"hash": "sha256:abc", "hashes": {"sha256": "abc"}},
        },
    )
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")

    payload, exit_code = update_commands.run_guard_update(dry_run=True)

    assert exit_code == 0
    assert payload["status"] == "planned"
    assert payload.get("source_install") is None


def test_update_marks_partial_pypi_repair_as_stale(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.345")
    monkeypatch.setattr(update_commands, "_current_version_from_subprocess", lambda: "2.0.400")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.489")
    monkeypatch.setattr(
        update_commands,
        "_direct_url_payload",
        lambda: {
            "url": "https://github.com/hashgraph-online/hol-guard.git",
            "vcs_info": {
                "commit_id": "ea81cb21edf6fbf2c83658299a81043e9fe37c57",
                "requested_revision": "main",
                "vcs": "git",
            },
        },
    )
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, "installed hol-guard 2.0.400", "")

    monkeypatch.setattr(update_commands.subprocess, "run", fake_run)

    payload, exit_code = update_commands.run_guard_update(dry_run=False)

    assert exit_code == 0
    assert payload["status"] == "stale"
    assert payload["changed"] is True
    assert payload["resulting_version"] == "2.0.400"
    assert "behind PyPI 2.0.489" in str(payload["message"])


def test_update_marks_plain_pipx_upgrade_as_stale_when_version_does_not_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.584")
    monkeypatch.setattr(update_commands, "_current_version_from_subprocess", lambda: "2.0.584")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.585")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")
    monkeypatch.setattr(
        update_commands.shutil,
        "which",
        lambda name: "/mock-home/.local/bin/hol-guard" if name == "hol-guard" else None,
    )

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert command == ["pipx", "upgrade", "hol-guard"]
        return subprocess.CompletedProcess(
            command,
            0,
            "hol-guard is already at latest version 2.0.584",
            "upgrading shared libraries...\nupgrading hol-guard...\n",
        )

    monkeypatch.setattr(update_commands.subprocess, "run", fake_run)

    payload, exit_code = update_commands.run_guard_update(dry_run=False)

    assert exit_code == 0
    assert payload["status"] == "stale"
    assert payload["changed"] is False
    assert payload["resulting_version"] == "2.0.584"
    assert payload["retry_command"] == "pipx install --force hol-guard"
    assert "behind PyPI 2.0.585 after the update attempt" in str(payload["message"])


def test_update_switches_git_install_to_pypi_when_release_is_newer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.345")
    monkeypatch.setattr(update_commands, "_current_version_from_subprocess", lambda: "2.0.489")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.489")
    monkeypatch.setattr(
        update_commands,
        "_direct_url_payload",
        lambda: {
            "url": "https://github.com/hashgraph-online/hol-guard.git",
            "vcs_info": {
                "commit_id": "ea81cb21edf6fbf2c83658299a81043e9fe37c57",
                "requested_revision": "main",
                "vcs": "git",
            },
        },
    )
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")
    monkeypatch.setattr(
        update_commands.shutil,
        "which",
        lambda name: "/Users/test/.local/bin/hol-guard" if name == "hol-guard" else None,
    )

    captured_commands: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured_commands.append(command)
        return subprocess.CompletedProcess(command, 0, "installed hol-guard 2.0.489", "")

    monkeypatch.setattr(update_commands.subprocess, "run", fake_run)

    payload, exit_code = update_commands.run_guard_update(dry_run=False)

    assert exit_code == 0
    assert captured_commands[0] == ["pipx", "install", "--force", "hol-guard"]
    assert payload["upgrade_source"] == "pypi"
    assert payload["status"] == "updated"
    assert payload["message"] == "Updated HOL Guard from 2.0.345 to 2.0.489."


def test_update_marks_git_install_stale_when_pypi_upgrade_leaves_old_version(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.345")
    monkeypatch.setattr(update_commands, "_current_version_from_subprocess", lambda: "2.0.345")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.489")
    monkeypatch.setattr(
        update_commands,
        "_direct_url_payload",
        lambda: {
            "url": "https://github.com/hashgraph-online/hol-guard.git",
            "vcs_info": {
                "commit_id": "ea81cb21edf6fbf2c83658299a81043e9fe37c57",
                "requested_revision": "main",
                "vcs": "git",
            },
        },
    )
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")

    captured_commands: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured_commands.append(command)
        return subprocess.CompletedProcess(
            command,
            0,
            "hol-guard is already at latest version 2.0.345",
            "upgrading hol-guard from spec 'git+https://github.com/hashgraph-online/hol-guard.git@main'...",
        )

    monkeypatch.setattr(update_commands.subprocess, "run", fake_run)

    payload, exit_code = update_commands.run_guard_update(dry_run=False)

    assert exit_code == 0
    assert captured_commands[0] == ["pipx", "install", "--force", "hol-guard"]
    assert payload["status"] == "stale"
    assert "behind PyPI 2.0.489" in str(payload["message"])
    assert "pipx install --force hol-guard" in str(payload["message"])


def test_update_reports_current_after_successful_pypi_repair_when_post_check_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.345")
    monkeypatch.setattr(update_commands, "_current_version_from_subprocess", lambda: "2.0.489")
    call_count = {"count": 0}

    def fake_latest() -> str | None:
        call_count["count"] += 1
        return "2.0.489" if call_count["count"] == 1 else None

    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", fake_latest)
    monkeypatch.setattr(
        update_commands,
        "_direct_url_payload",
        lambda: {
            "url": "https://github.com/hashgraph-online/hol-guard.git",
            "vcs_info": {"vcs": "git", "requested_revision": "main", "commit_id": "abc"},
        },
    )
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, "installed hol-guard 2.0.489", "")

    monkeypatch.setattr(update_commands.subprocess, "run", fake_run)

    payload, exit_code = update_commands.run_guard_update(dry_run=False)

    assert exit_code == 0
    assert payload["status"] == "updated"
    assert payload["message"] == "Updated HOL Guard from 2.0.345 to 2.0.489."


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
        assert contract.coverage.native_hooks == (canonical in {"claude-code", "codex", "copilot"})


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


def test_approval_open_repairs_ipv6_local_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    request = GuardApprovalRequest(
        request_id="request-ipv6",
        harness="codex",
        artifact_id="artifact-1",
        artifact_name="Tool",
        artifact_hash="hash",
        policy_action="block",
        recommended_scope="artifact",
        changed_fields=(),
        source_scope="local",
        config_path="config.toml",
        review_command="hol-guard approvals approve request-ipv6",
        approval_url="http://[::1]:4000/approvals/request-ipv6",
    )
    store.add_approval_request(request, "2026-05-12T00:00:00Z")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.approval_commands.load_guard_daemon_url",
        lambda guard_home: "http://127.0.0.1:4781",
    )

    payload, exit_code = run_approval_open_command(argparse.Namespace(request_id="request-ipv6"), store=store)

    assert exit_code == 0
    assert payload["approval_url"] == "http://127.0.0.1:4781/approvals/request-ipv6"
    assert payload["repaired"] is True


def test_approval_open_preserves_malformed_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    request = GuardApprovalRequest(
        request_id="request-bad-url",
        harness="codex",
        artifact_id="artifact-1",
        artifact_name="Tool",
        artifact_hash="hash",
        policy_action="block",
        recommended_scope="artifact",
        changed_fields=(),
        source_scope="local",
        config_path="config.toml",
        review_command="hol-guard approvals approve request-bad-url",
        approval_url="http://[::1:4000/approvals/request-bad-url",
    )
    store.add_approval_request(request, "2026-05-12T00:00:00Z")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.approval_commands.load_guard_daemon_url",
        lambda guard_home: "http://127.0.0.1:4781",
    )

    payload, exit_code = run_approval_open_command(argparse.Namespace(request_id="request-bad-url"), store=store)

    assert exit_code == 0
    assert payload["approval_url"] == "http://[::1:4000/approvals/request-bad-url"
    assert payload["repaired"] is False
