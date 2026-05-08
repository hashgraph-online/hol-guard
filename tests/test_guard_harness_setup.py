"""Tests for guided Guard harness setup contracts and app aliases."""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import get_adapter, list_adapters
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.contracts import HarnessSetupContract
from codex_plugin_scanner.guard.cli.commands import add_guard_root_parser, run_guard_command
from codex_plugin_scanner.guard.cli.install_commands import list_harness_setup_items
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore

SUPPORTED_HARNESSES = (
    "codex",
    "claude-code",
    "opencode",
    "copilot",
    "gemini",
    "cursor",
    "hermes",
    "openclaw",
)


def _context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    workspace.mkdir(parents=True, exist_ok=True)
    return HarnessContext(home_dir=home, workspace_dir=workspace, guard_home=guard_home)


def _read_json_response(request: urllib.request.Request) -> tuple[int, dict[str, object]]:
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read().decode("utf-8"))


def _request(
    port: int,
    path: str,
    *,
    token: str | None = None,
    payload: dict[str, object] | None = None,
) -> urllib.request.Request:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["X-Guard-Token"] = token
    return urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=data,
        headers=headers,
        method="POST" if payload is not None else "GET",
    )


@pytest.mark.parametrize("harness", SUPPORTED_HARNESSES)
def test_adapter_exposes_guided_setup_contract(harness: str) -> None:
    adapter = get_adapter(harness)

    contract = adapter.setup_contract()

    assert isinstance(contract, HarnessSetupContract)
    assert contract.harness == adapter.harness
    assert contract.setup_steps
    assert contract.verify_steps
    assert contract.repair_steps
    assert contract.coverage.native_hooks in {True, False}
    assert contract.coverage.browser_fallback in {True, False}
    assert contract.coverage.mcp_proxy in {True, False}
    assert contract.coverage.prompt_hooks in {True, False}
    assert contract.coverage.blind_spots
    assert all(step.title and step.body for step in contract.setup_steps)
    assert all(step.command[0] == "hol-guard" for step in contract.verify_steps)


def test_every_adapter_has_setup_methods() -> None:
    for adapter in list_adapters():
        assert adapter.setup_steps()
        assert adapter.verify_steps()
        assert adapter.repair_steps()
        assert adapter.coverage_summary().blind_spots


def test_daemon_lists_harness_setup_contracts(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        status, payload = _read_json_response(_request(daemon.port, "/v1/harnesses"))
    finally:
        daemon.stop()

    assert status == 200
    items = payload["items"]
    assert isinstance(items, list)
    harnesses = {item["harness"] for item in items if isinstance(item, dict)}
    assert set(SUPPORTED_HARNESSES).issubset(harnesses)
    codex = next(item for item in items if isinstance(item, dict) and item["harness"] == "codex")
    assert codex["setup_steps"]
    assert codex["verify_steps"]
    assert codex["repair_steps"]
    assert codex["coverage"]["browser_fallback"] is True


def test_daemon_install_endpoint_defaults_to_dry_run(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/harnesses/codex/install",
                token=daemon._server.auth_token,
                payload={},
            )
        )
    finally:
        daemon.stop()

    assert status == 200
    assert payload["dry_run"] is True
    assert payload["action"] == "install"
    assert payload["contract"]["harness"] == "codex"
    assert store.get_managed_install("codex") is None


def test_daemon_verify_endpoint_runs_safe_local_detection(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/harnesses/codex/verify",
                token=daemon._server.auth_token,
                payload={},
            )
        )
    finally:
        daemon.stop()

    assert status == 200
    assert payload["harness"] == "codex"
    assert payload["safe"] is True
    assert payload["verification"]["checked"] is True
    assert payload["verification"]["writes_config"] is False


def test_daemon_uninstall_requires_confirmation_token(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/harnesses/codex/uninstall",
                token=daemon._server.auth_token,
                payload={},
            )
        )
    finally:
        daemon.stop()

    assert status == 400
    assert payload["error"] == "confirmation_required"
    assert payload["confirmation_phrase"] == "disconnect-codex"
    assert payload["confirm_command"] == "hol-guard apps disconnect codex --confirm disconnect-codex"


def test_apps_alias_lists_harnesses_as_plain_inventory(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    args = argparse.Namespace(
        guard_command="apps",
        apps_command=None,
        harness=None,
        home=str(tmp_path / "home"),
        guard_home=str(tmp_path / "guard-home"),
        workspace=str(tmp_path / "workspace"),
        json=True,
    )

    exit_code = run_guard_command(args)

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["items"]
    assert payload["items"][0]["setup_steps"]
    assert payload["items"][0]["coverage"]["blind_spots"]


def test_apps_test_alias_uses_safe_verification(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    args = argparse.Namespace(
        guard_command="apps",
        apps_command="test",
        harness="codex",
        home=str(tmp_path / "home"),
        guard_home=str(tmp_path / "guard-home"),
        workspace=str(tmp_path / "workspace"),
        json=True,
    )

    exit_code = run_guard_command(args)

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["harness"] == "codex"
    assert payload["safe"] is True
    assert payload["verification"]["writes_config"] is False


def test_apps_subcommand_preserves_parent_flags(tmp_path: Path) -> None:
    parser = argparse.ArgumentParser()
    add_guard_root_parser(parser)

    args = parser.parse_args(
        [
            "apps",
            "--home",
            str(tmp_path / "home"),
            "--guard-home",
            str(tmp_path / "guard-home"),
            "--workspace",
            str(tmp_path / "workspace"),
            "--json",
            "connect",
            "codex",
        ]
    )

    assert args.home == str(tmp_path / "home")
    assert args.guard_home == str(tmp_path / "guard-home")
    assert args.workspace == str(tmp_path / "workspace")
    assert args.json is True
    assert args.apps_command == "connect"


def test_apps_inventory_uses_adapter_command_resolution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    adapter = get_adapter("claude-code")

    def resolved_executable(_context: HarnessContext) -> str | None:
        return str(tmp_path / "home" / ".claude" / "local" / "claude")

    monkeypatch.setattr(adapter, "resolved_executable", resolved_executable)

    items = list_harness_setup_items(context, GuardStore(tmp_path / "guard-home"))

    claude = next(item for item in items if item["harness"] == "claude-code")
    assert claude["command_available"] is True


def test_apps_disconnect_confirmation_phrase_is_visible(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    args = argparse.Namespace(
        guard_command="apps",
        apps_command="disconnect",
        harness="codex",
        confirm=None,
        home=str(tmp_path / "home"),
        guard_home=str(tmp_path / "guard-home"),
        workspace=str(tmp_path / "workspace"),
        json=True,
    )

    exit_code = run_guard_command(args)

    assert exit_code == 2
    output = capsys.readouterr().out
    assert "disconnect-codex" in output
    payload = json.loads(output)
    assert payload["confirmation_phrase"] == "disconnect-codex"
    assert payload["confirm_command"] == "hol-guard apps disconnect codex --confirm disconnect-codex"


def test_apps_safe_setup_does_not_read_skill_env_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home = tmp_path / "home"
    skill_env = home / ".agents" / "skills" / "network-helper" / "references" / ".env"
    skill_env.parent.mkdir(parents=True, exist_ok=True)
    skill_env.write_text("API_TOKEN=secret\n", encoding="utf-8")
    original_read_text = Path.read_text

    def guarded_read_text(path: Path, *args: object, **kwargs: object) -> str:
        if path.name == ".env":
            raise AssertionError("safe setup flow must not read .env files")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded_read_text)
    list_args = argparse.Namespace(
        guard_command="apps",
        apps_command=None,
        harness=None,
        home=str(home),
        guard_home=str(tmp_path / "guard-home"),
        workspace=str(tmp_path / "workspace"),
        json=True,
    )
    test_args = argparse.Namespace(
        guard_command="apps",
        apps_command="test",
        harness="hermes",
        home=str(home),
        guard_home=str(tmp_path / "guard-home"),
        workspace=str(tmp_path / "workspace"),
        json=True,
    )

    assert run_guard_command(list_args) == 0
    list_payload = json.loads(capsys.readouterr().out)
    assert run_guard_command(test_args) == 0
    test_payload = json.loads(capsys.readouterr().out)
    assert list_payload["items"]
    assert test_payload["safe"] is True
