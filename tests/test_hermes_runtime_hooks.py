"""Hermes local runtime hook registration and native response tests."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest
import yaml as pyyaml

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge import _event_name
from codex_plugin_scanner.guard.adapters.hermes import HermesHarnessAdapter
from codex_plugin_scanner.guard.adapters.hermes_runtime_hooks import (
    apply_hermes_doctor_protection_label,
    guard_pretool_hook_registered,
    hermes_bridge_response,
    hermes_native_decision,
)
from codex_plugin_scanner.guard.runtime.actions import normalize_hermes_payload
from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command
from codex_plugin_scanner.guard.store import GuardStore


def _ctx(tmp_path: Path) -> HarnessContext:
    return HarnessContext(
        home_dir=tmp_path,
        workspace_dir=tmp_path / "workspace",
        guard_home=tmp_path / "guard-home",
    )


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _config(tmp_path: Path) -> dict[str, object]:
    _write(
        tmp_path / ".hermes" / "config.yaml",
        (
            "mcp_servers:\n"
            "  github:\n"
            "    command: npx\n"
            "hooks:\n"
            "  pre_tool_call:\n"
            "    - matcher: write_file\n"
            "      command: /usr/bin/true\n"
            "      fail_closed: false\n"
            "  outbound:\n"
            "    - name: ci\n"
            "      url: https://example.invalid/hooks\n"
        ),
    )
    (tmp_path / "workspace").mkdir(exist_ok=True)
    return pyyaml.safe_load((tmp_path / ".hermes" / "config.yaml").read_text(encoding="utf-8"))


def test_install_writes_fail_closed_pretool_hook(tmp_path: Path) -> None:
    _config(tmp_path)
    adapter = HermesHarnessAdapter()
    adapter.install(_ctx(tmp_path))

    config = pyyaml.safe_load((tmp_path / ".hermes" / "config.yaml").read_text(encoding="utf-8"))
    entries = config["hooks"]["pre_tool_call"]
    guard_entries = [entry for entry in entries if entry.get("id") == "hol-guard-pretool"]
    assert len(guard_entries) == 1
    assert guard_entries[0]["fail_closed"] is True
    assert guard_entries[0]["timeout"] == 5
    assert guard_entries[0]["matcher"] == ".*"
    assert "--workspace" not in str(guard_entries[0]["command"])
    assert any(entry.get("command") == "/usr/bin/true" for entry in entries)
    assert config["hooks"]["outbound"][0]["name"] == "ci"
    allowlist = json.loads((tmp_path / ".hermes" / "shell-hooks-allowlist.json").read_text(encoding="utf-8"))
    assert allowlist["approvals"][0]["event"] == "pre_tool_call"
    assert allowlist["approvals"][0]["command"] == guard_entries[0]["command"]
    probe = adapter.runtime_probe(_ctx(tmp_path))
    assert probe is not None
    assert probe["runtime_hook_registered"] is True
    assert probe["managed_install_ready"] is True


def test_install_is_idempotent_for_runtime_hooks(tmp_path: Path) -> None:
    _config(tmp_path)
    adapter = HermesHarnessAdapter()
    context = _ctx(tmp_path)
    adapter.install(context)
    adapter.install(context)
    config = pyyaml.safe_load((tmp_path / ".hermes" / "config.yaml").read_text(encoding="utf-8"))
    guard_entries = [entry for entry in config["hooks"]["pre_tool_call"] if entry.get("id") == "hol-guard-pretool"]
    assert len(guard_entries) == 1


def test_uninstall_removes_guard_hook_and_keeps_user_hooks(tmp_path: Path) -> None:
    _config(tmp_path)
    adapter = HermesHarnessAdapter()
    context = _ctx(tmp_path)
    adapter.install(context)
    adapter.uninstall(context)
    config = pyyaml.safe_load((tmp_path / ".hermes" / "config.yaml").read_text(encoding="utf-8"))
    entries = config["hooks"]["pre_tool_call"]
    assert entries == [
        {"matcher": "write_file", "command": "/usr/bin/true", "fail_closed": False},
    ]
    assert config["hooks"]["outbound"][0]["name"] == "ci"
    allowlist = json.loads((tmp_path / ".hermes" / "shell-hooks-allowlist.json").read_text(encoding="utf-8"))
    assert allowlist["approvals"] == []


def test_runtime_probe_is_not_ready_without_registered_hook(tmp_path: Path) -> None:
    _config(tmp_path)
    adapter = HermesHarnessAdapter()
    context = _ctx(tmp_path)
    adapter.install(context)
    config_path = tmp_path / ".hermes" / "config.yaml"
    payload = pyyaml.safe_load(config_path.read_text(encoding="utf-8"))
    payload["hooks"]["pre_tool_call"] = [
        {"matcher": "write_file", "command": "/usr/bin/true", "fail_closed": False},
    ]
    config_path.write_text(pyyaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    probe = adapter.runtime_probe(context)
    assert probe is not None
    assert probe["runtime_hook_registered"] is False
    assert probe["managed_install_ready"] is False
    warnings = adapter.diagnostic_warnings(adapter.detect(context), probe)
    assert any("launch-review only" in warning for warning in warnings)


def test_doctor_protection_label_is_launch_review_only_without_hook() -> None:
    payload: dict[str, object] = {
        "protection_label": "Protected",
        "runtime_probe": {"managed_install_present": True, "runtime_hook_registered": False},
    }
    apply_hermes_doctor_protection_label(payload)
    assert payload["runtime_protection_label"] == "launch-review only"


def test_pretool_call_payload_classifies_recursive_delete(tmp_path: Path) -> None:
    envelope = normalize_hermes_payload(
        {
            "hook_event_name": "pre_tool_call",
            "tool_name": "terminal",
            "tool_input": {"command": "rm -rf ./build"},
        },
        workspace=tmp_path,
        home_dir=tmp_path,
    )
    assert envelope.event_name == "PreToolUse"
    assert envelope.tool_name == "terminal"
    assert envelope.action_type == "shell_command"
    assert envelope.command is not None
    inspection = inspect_command(envelope.command, home_dir=tmp_path)
    assert inspection["controlling_rule_id"] == "command.filesystem.recursive-delete"


def test_pretool_call_args_payload_is_normalized(tmp_path: Path) -> None:
    envelope = normalize_hermes_payload(
        {
            "hook_event_name": "pre_tool_call",
            "tool_name": "terminal",
            "args": {"command": "rm -rf ./build"},
        },
        workspace=tmp_path,
        home_dir=tmp_path,
    )
    assert envelope.command is not None
    assert "rm -rf" in envelope.command


def test_event_name_maps_pre_tool_call() -> None:
    assert _event_name('{"hook_event_name":"pre_tool_call"}') == "PreToolUse"


def test_hermes_bridge_maps_review_to_block() -> None:
    stdout, stderr, code = hermes_bridge_response(
        {"policy_action": "review", "reason": "recursive delete"},
        event_name="PreToolUse",
    )
    payload = json.loads(stdout)
    assert payload == {"decision": "block", "reason": "recursive delete"}
    assert stderr == ""
    assert code == 2
    native_stdout, native_stderr, native_code = hermes_bridge_response(
        {"policy_action": "allow", "reason": "ok"},
        event_name="PreToolUse",
    )
    assert json.loads(native_stdout)["decision"] == "allow"
    assert native_stderr == ""
    assert native_code == 0


def test_hermes_native_decision_never_emits_deny() -> None:
    assert hermes_native_decision(policy_action="block", reason="no")["decision"] == "block"
    assert hermes_native_decision(policy_action="review", reason="ask")["decision"] == "block"
    assert hermes_native_decision(policy_action="allow", reason="ok")["decision"] == "allow"


def test_guard_pretool_hook_registered_requires_fail_closed() -> None:
    command = "python -c bounded_cli_hook_bridge"
    assert (
        guard_pretool_hook_registered(
            {
                "hooks": {
                    "pre_tool_call": [
                        {
                            "id": "hol-guard-pretool",
                            "matcher": ".*",
                            "command": command,
                            "fail_closed": False,
                        }
                    ]
                }
            }
        )
        is False
    )
    assert (
        guard_pretool_hook_registered(
            {
                "hooks": {
                    "pre_tool_call": [
                        {
                            "id": "hol-guard-pretool",
                            "matcher": ".*",
                            "command": command,
                            "fail_closed": True,
                        }
                    ]
                }
            }
        )
        is True
    )
    assert (
        guard_pretool_hook_registered(
            {
                "hooks": {
                    "pre_tool_call": [
                        {
                            "command": command,
                            "matcher": ".*",
                            "fail_closed": True,
                        }
                    ]
                }
            }
        )
        is False
    )


def test_pretool_call_records_runtime_receipt(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    home_dir.mkdir()
    workspace_dir.mkdir()
    _write(home_dir / "config.toml", "approval_wait_timeout_seconds = 0\n")
    _write(home_dir / ".hermes" / "config.yaml", "mcp_servers: {}\n")
    context = HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=home_dir)
    HermesHarnessAdapter().install(context)
    capsys.readouterr()
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(
            json.dumps(
                {
                    "hook_event_name": "pre_tool_call",
                    "tool_name": "terminal",
                    "tool_input": {"command": "rm -rf ./build"},
                }
            )
        ),
    )
    returncode = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--harness",
            "hermes",
            "--json",
        ]
    )
    captured = capsys.readouterr()
    receipts = GuardStore(home_dir).list_receipts()
    assert returncode == 2
    assert receipts
    assert receipts[0]["harness"] == "hermes"
    native = json.loads(captured.out.strip().splitlines()[-1])
    assert native["decision"] == "block"
    assert "hookSpecificOutput" not in native


def test_reinstall_retires_stale_allowlist_commands(tmp_path: Path) -> None:
    _config(tmp_path)
    adapter = HermesHarnessAdapter()
    context = _ctx(tmp_path)
    adapter.install(context)
    allowlist_path = tmp_path / ".hermes" / "shell-hooks-allowlist.json"
    stale = "python stale-guard-hook"
    payload = json.loads(allowlist_path.read_text(encoding="utf-8"))
    payload["approvals"].insert(0, {"event": "pre_tool_call", "command": stale})
    allowlist_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    config_path = tmp_path / ".hermes" / "config.yaml"
    config = pyyaml.safe_load(config_path.read_text(encoding="utf-8"))
    for entry in config["hooks"]["pre_tool_call"]:
        if entry.get("id") == "hol-guard-pretool":
            entry["command"] = stale
    config_path.write_text(pyyaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    adapter.install(context)
    allowlist = json.loads(allowlist_path.read_text(encoding="utf-8"))
    commands = [item["command"] for item in allowlist["approvals"]]
    assert stale not in commands
    assert len(commands) == 1


def test_malformed_allowlist_refuses_install(tmp_path: Path) -> None:
    _config(tmp_path)
    allowlist_path = tmp_path / ".hermes" / "shell-hooks-allowlist.json"
    allowlist_path.write_text('{"approvals": {}}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="malformed"):
        HermesHarnessAdapter().install(_ctx(tmp_path))


def test_user_hook_with_marker_substring_is_preserved(tmp_path: Path) -> None:
    _write(
        tmp_path / ".hermes" / "config.yaml",
        (
            "mcp_servers: {}\n"
            "hooks:\n"
            "  pre_tool_call:\n"
            "    - matcher: write_file\n"
            "      command: echo bounded_cli_hook_bridge\n"
            "      fail_closed: false\n"
        ),
    )
    (tmp_path / "workspace").mkdir(exist_ok=True)
    adapter = HermesHarnessAdapter()
    adapter.install(_ctx(tmp_path))
    adapter.uninstall(_ctx(tmp_path))
    config = pyyaml.safe_load((tmp_path / ".hermes" / "config.yaml").read_text(encoding="utf-8"))
    assert config["hooks"]["pre_tool_call"] == [
        {"matcher": "write_file", "command": "echo bounded_cli_hook_bridge", "fail_closed": False},
    ]


def test_registered_requires_allowlist_and_matcher(tmp_path: Path) -> None:
    command = "python hol-guard-hook"
    allowlist_path = tmp_path / "shell-hooks-allowlist.json"
    allowlist_path.write_text(
        json.dumps({"approvals": [{"event": "pre_tool_call", "command": command}]}) + "\n",
        encoding="utf-8",
    )
    config = {
        "hooks": {
            "pre_tool_call": [
                {
                    "id": "hol-guard-pretool",
                    "matcher": "write_file",
                    "command": command,
                    "fail_closed": True,
                }
            ]
        }
    }
    assert guard_pretool_hook_registered(config, allowlist_path=allowlist_path) is False
    config["hooks"]["pre_tool_call"][0]["matcher"] = ".*"
    assert guard_pretool_hook_registered(config, allowlist_path=allowlist_path) is True
    allowlist_path.write_text('{"approvals": []}\n', encoding="utf-8")
    assert guard_pretool_hook_registered(config, allowlist_path=allowlist_path) is False


def test_protection_display_name_skips_blank_runtime_label() -> None:
    from codex_plugin_scanner.guard.cli.render import _protection_display_name

    assert _protection_display_name(
        {"runtime_protection_label": "   ", "protection_label": "Protected"},
        "watch",
    ) == "Protected"
