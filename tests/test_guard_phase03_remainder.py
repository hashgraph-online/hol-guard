"""Remaining Phase 03 Guard local install, update, and connect contracts."""

from __future__ import annotations

import http.client
import json
import urllib.parse
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import update_commands
from codex_plugin_scanner.guard.cli.connect_flow import build_guard_connect_browser_url, run_guard_connect_command
from codex_plugin_scanner.guard.cli.install_commands import apply_managed_install, list_harness_setup_items
from codex_plugin_scanner.guard.store import GuardStore


def _context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    workspace.mkdir(parents=True, exist_ok=True)
    return HarnessContext(home_dir=home, workspace_dir=workspace, guard_home=guard_home)


def test_update_detects_uv_tool_install_and_plans_uv_upgrade(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_commands.sys, "prefix", "/Users/test/.local/share/uv/tools/hol-guard")
    monkeypatch.setattr(update_commands.shutil, "which", lambda name: f"/Users/test/.local/bin/{name}")
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.0")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)

    payload, exit_code = update_commands.run_guard_update(dry_run=True)

    assert exit_code == 0
    assert payload["installer"] == "uv"
    assert payload["command"] == ["uv", "tool", "upgrade", "hol-guard"]
    assert payload["retry_command"] == "uv tool upgrade hol-guard"
    assert payload["binary_diagnostics"]["path_status"] == "uv_tool_shim_detected"


def test_update_version_check_marks_stale_local_install(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_commands.sys, "prefix", "/opt/guard-venv")
    monkeypatch.setattr(update_commands.sys, "executable", "/opt/guard-venv/bin/python")
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.0")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.10")

    payload, exit_code = update_commands.run_guard_update(dry_run=True)

    assert exit_code == 0
    assert payload["version_check"] == {
        "source": "pypi",
        "status": "stale",
        "current_version": "2.0.0",
        "latest_version": "2.0.10",
        "update_available": True,
    }


def test_update_version_check_treats_stable_release_newer_than_prerelease(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(update_commands.sys, "prefix", "/opt/guard-venv")
    monkeypatch.setattr(update_commands.sys, "executable", "/opt/guard-venv/bin/python")
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.0rc1")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.0")

    payload, exit_code = update_commands.run_guard_update(dry_run=True)

    assert exit_code == 0
    assert payload["version_check"] == {
        "source": "pypi",
        "status": "stale",
        "current_version": "2.0.0rc1",
        "latest_version": "2.0.0",
        "update_available": True,
    }


def test_update_version_check_handles_latest_lookup_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_commands.sys, "prefix", "/opt/guard-venv")
    monkeypatch.setattr(update_commands.sys, "executable", "/opt/guard-venv/bin/python")
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.0")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: None)

    payload, exit_code = update_commands.run_guard_update(dry_run=True)

    assert exit_code == 0
    assert payload["version_check"] == {
        "source": "pypi",
        "status": "unavailable",
        "current_version": "2.0.0",
        "latest_version": None,
        "update_available": None,
    }


def test_update_version_check_reports_invalid_current_version_as_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(update_commands.sys, "prefix", "/opt/guard-venv")
    monkeypatch.setattr(update_commands.sys, "executable", "/opt/guard-venv/bin/python")
    monkeypatch.setattr(update_commands, "_current_version", lambda: "unknown")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.1")

    payload, exit_code = update_commands.run_guard_update(dry_run=True)

    assert exit_code == 0
    assert payload["version_check"] == {
        "source": "pypi",
        "status": "unavailable",
        "current_version": "unknown",
        "latest_version": "2.0.1",
        "update_available": None,
    }


def test_latest_version_lookup_uses_practical_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    timeouts: list[float] = []

    class FakeResponse:
        def __enter__(self) -> FakeResponse:
            return self

        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            exc_value: BaseException | None,
            traceback: object,
        ) -> None:
            return None

        def read(self) -> bytes:
            return b'{"info":{"version":"2.0.1"}}'

    def fake_urlopen(request: object, timeout: float) -> FakeResponse:
        timeouts.append(timeout)
        return FakeResponse()

    monkeypatch.setattr(update_commands.urllib.request, "urlopen", fake_urlopen)

    assert update_commands._latest_version_from_pypi() == "2.0.1"
    assert timeouts == [3.0]


def test_latest_version_lookup_handles_truncated_response(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(request: object, timeout: float) -> object:
        raise http.client.IncompleteRead(partial=b'{"info":')

    monkeypatch.setattr(update_commands.urllib.request, "urlopen", fake_urlopen)

    assert update_commands._latest_version_from_pypi() is None


def test_install_setup_listing_detects_safe_config_without_mutating_it(tmp_path: Path) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    config_path = context.home_dir / ".cursor" / "mcp.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_text = json.dumps({"mcpServers": {"local": {"command": "node"}}})
    config_path.write_text(config_text, encoding="utf-8")
    before_mtime = config_path.stat().st_mtime_ns

    items = list_harness_setup_items(context, store)

    cursor_item = next(item for item in items if item["harness"] == "cursor")
    assert cursor_item["status"] == "found"
    assert cursor_item["installed"] is False
    assert cursor_item["config_paths"] == [str(config_path)]
    assert config_path.read_text(encoding="utf-8") == config_text
    assert config_path.stat().st_mtime_ns == before_mtime


def test_doctor_reports_partial_setup_for_found_unprotected_harness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    config_path = context.home_dir / ".cursor" / "mcp.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps({"mcpServers": {"local": {"command": "node"}}}), encoding="utf-8")
    monkeypatch.setattr("codex_plugin_scanner.guard.adapters.cursor._command_available", lambda command: False)

    from codex_plugin_scanner.guard.adapters import get_adapter

    payload = get_adapter("cursor").diagnostics(context)

    assert payload["setup_status"] == "partial"
    assert payload["command_available"] is False
    assert payload["config_paths"] == [str(config_path)]
    assert any("config was found" in warning for warning in payload["warnings"])


def test_doctor_does_not_mark_harness_command_presence_as_guard_active(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    config_path = context.home_dir / ".cursor" / "mcp.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps({"mcpServers": {"local": {"command": "node"}}}), encoding="utf-8")
    monkeypatch.setattr("codex_plugin_scanner.guard.adapters.cursor._command_available", lambda command: True)

    from codex_plugin_scanner.guard.adapters import get_adapter

    payload = get_adapter("cursor").diagnostics(context)

    assert payload["setup_status"] == "partial"
    assert payload["installed"] is True
    assert payload["command_available"] is True
    assert any("Guard is not installed" in warning for warning in payload["warnings"])


def test_codex_doctor_marks_partial_native_hook_install_as_broken(tmp_path: Path) -> None:
    context = _context(tmp_path)
    config_path = context.workspace_dir / ".codex" / "config.toml"
    hooks_path = context.workspace_dir / ".codex" / "hooks.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text("[features]\ncodex_hooks = true\n", encoding="utf-8")
    hooks_path.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": (
                                        "python -m codex_plugin_scanner.cli guard hook "
                                        "--guard-home /tmp/guard --harness codex"
                                    ),
                                    "statusMessage": "HOL Guard checking tool action",
                                }
                            ]
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )

    from codex_plugin_scanner.guard.adapters import get_adapter

    payload = get_adapter("codex").diagnostics(context)

    assert payload["setup_status"] == "broken"
    assert payload["native_hook_state"]["managed_pre_tool_hook_installed"] is True
    assert payload["native_hook_state"]["managed_hook_installed"] is False
    assert any("managed Codex hooks are missing" in warning for warning in payload["warnings"])


def test_doctor_treats_guard_launcher_shim_as_active_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    monkeypatch.setattr("codex_plugin_scanner.guard.adapters.cursor._command_available", lambda command: True)

    install_payload = apply_managed_install(
        "install",
        "cursor",
        False,
        context,
        store,
        str(context.workspace_dir),
        "2026-05-13T00:00:00Z",
    )

    from codex_plugin_scanner.guard.adapters import get_adapter

    payload = get_adapter("cursor").diagnostics(context)

    assert Path(str(install_payload["managed_install"]["shim_path"])).is_file()
    assert payload["setup_status"] == "active"
    assert any(artifact["artifact_type"] == "guard_launcher_shim" for artifact in payload["artifacts"])
    assert not any("Guard is not installed" in warning for warning in payload["warnings"])


def test_doctor_ignores_non_utf8_guard_launcher_shim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    shim_path = context.guard_home / "bin" / "guard-cursor"
    shim_path.parent.mkdir(parents=True, exist_ok=True)
    shim_path.write_bytes(b"\xff\xfe\x00")
    monkeypatch.setattr("codex_plugin_scanner.guard.adapters.cursor._command_available", lambda command: False)

    from codex_plugin_scanner.guard.adapters import get_adapter

    payload = get_adapter("cursor").diagnostics(context)

    assert payload["setup_status"] == "not_found"


def test_doctor_recognizes_legacy_guard_launcher_shim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    shim_path = context.guard_home / "bin" / "guard-claude-code"
    shim_path.parent.mkdir(parents=True, exist_ok=True)
    shim_path.write_text(
        "\n".join(
            (
                "#!/usr/bin/env python",
                "base_command = ['python', '-m', 'codex_plugin_scanner.cli', 'guard', 'run', 'claude-code']",
            )
        ),
        encoding="utf-8",
    )
    from codex_plugin_scanner.guard.adapters import get_adapter
    from codex_plugin_scanner.guard.adapters.claude_code import ClaudeCodeHarnessAdapter

    monkeypatch.setattr(ClaudeCodeHarnessAdapter, "resolved_executable", lambda self, context: None)

    payload = get_adapter("claude-code").diagnostics(context)

    assert payload["setup_status"] == "active"
    assert any(artifact["name"] == "guard-claude-code" for artifact in payload["artifacts"])


def test_doctor_treats_guard_command_artifact_as_managed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    config_path = context.home_dir / ".cursor" / "mcp.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        json.dumps({"mcpServers": {"wrapped": {"command": "guard-cursor", "args": ["--flag"]}}}),
        encoding="utf-8",
    )
    monkeypatch.setattr("codex_plugin_scanner.guard.adapters.cursor._command_available", lambda command: True)

    from codex_plugin_scanner.guard.adapters import get_adapter

    payload = get_adapter("cursor").diagnostics(context)

    assert payload["setup_status"] == "active"
    assert not any("Guard is not installed" in warning for warning in payload["warnings"])


def test_doctor_keeps_active_setup_status_for_runtime_probe_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    apply_managed_install(
        "install",
        "cursor",
        False,
        context,
        store,
        str(context.workspace_dir),
        "2026-05-13T00:00:00Z",
    )
    monkeypatch.setattr("codex_plugin_scanner.guard.adapters.cursor._command_available", lambda command: False)

    from codex_plugin_scanner.guard.adapters import get_adapter
    from codex_plugin_scanner.guard.adapters.cursor import CursorHarnessAdapter

    def runtime_probe_timeout(self: CursorHarnessAdapter, context: HarnessContext) -> dict[str, object]:
        return {"timed_out": True}

    monkeypatch.setattr(CursorHarnessAdapter, "runtime_probe", runtime_probe_timeout)

    payload = get_adapter("cursor").diagnostics(context)

    assert payload["setup_status"] == "active"
    assert any("timed out" in warning for warning in payload["warnings"])


def test_install_native_contract_output_prefers_native_hooks_for_supported_harnesses(tmp_path: Path) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)

    payload = apply_managed_install(
        "install",
        "codex",
        False,
        context,
        store,
        str(context.workspace_dir),
        "2026-05-13T00:00:00Z",
    )

    managed_install = payload["managed_install"]
    assert managed_install["harness"] == "codex"
    assert managed_install["active"] is True
    assert managed_install["mode"] == "codex-mcp-proxy"
    assert managed_install["native_hooks"] is True
    assert managed_install["primary_integration"] == "native_hooks"
    assert managed_install["manifest"]["mode"] == "codex-mcp-proxy"


def test_connect_rejects_invalid_url_before_daemon_start(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon_calls: list[Path] = []

    def ensure_daemon(guard_home: Path) -> str:
        daemon_calls.append(guard_home)
        raise AssertionError("daemon must not start for invalid connect URL")

    monkeypatch.setattr("codex_plugin_scanner.guard.cli.connect_flow.ensure_guard_daemon", ensure_daemon)

    with pytest.raises(ValueError, match="absolute http"):
        run_guard_connect_command(
            guard_home=tmp_path / "guard-home",
            store=store,
            sync_url="https://hol.org/api/guard/receipts/sync",
            connect_url="not-a-url",
            opener=lambda url: True,
            wait_timeout_seconds=1,
        )

    assert daemon_calls == []


def test_connect_browser_url_keeps_pairing_secret_in_fragment_only() -> None:
    browser_url = build_guard_connect_browser_url(
        connect_url="https://hol.org/guard/connect?source=cli",
        daemon_url="http://127.0.0.1:4781",
        request_id="connect-123",
        pairing_secret="pairing-secret",
    )

    parsed = urllib.parse.urlparse(browser_url)
    query = urllib.parse.parse_qs(parsed.query)
    fragment = urllib.parse.parse_qs(parsed.fragment)

    assert query["source"] == ["cli"]
    assert query["guardPairRequest"] == ["connect-123"]
    assert query["guardDaemon"] == ["http://127.0.0.1:4781"]
    assert "pairing-secret" not in parsed.query
    assert fragment["guardPairSecret"] == ["pairing-secret"]
