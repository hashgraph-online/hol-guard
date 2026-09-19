from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import (
    ExtensionControlRuntimeSnapshot,
    use_extension_control_snapshot,
)
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    build_tool_action_request_artifact,
    extract_sensitive_tool_action_request,
)


def test_command_cli_emits_stable_json_without_creating_guard_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))

    exit_code = main(["guard", "command", "explain", "git clean -fdx", "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["mode"] == "explain"
    assert payload["status"] == "review"
    assert payload["extensions"][0]["extension_id"] == "command.git"
    assert payload["rules"][0]["rule_id"] == "command.git.force-clean"
    assert [item["step"] for item in payload["trace"]][-1] == "risk-signal-derivation"
    assert list(tmp_path.iterdir()) == []


def test_command_extensions_cli_remains_stateless(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))

    exit_code = main(["guard", "command", "extensions", "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["count"] == len(BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions)
    assert list(tmp_path.iterdir()) == []


def test_command_cli_lists_one_extension_and_rejects_unknown_ids(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["guard", "command", "extensions", "command.data-protection", "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["count"] == 1
    assert payload["extensions"][0]["extension_id"] == "command.data-protection"

    unknown_exit_code = main(["guard", "command", "extensions", "command.unknown", "--json"])
    captured = capsys.readouterr()
    assert unknown_exit_code == 2
    assert "Unknown command safety extension" in captured.err


def test_inspection_does_not_classify_literal_heredoc_data(tmp_path: Path) -> None:
    body = "r" + "m -rf ./build"
    data = inspect_command(f"cat <<'EOF'\n{body}\nEOF", cwd=tmp_path, home_dir=tmp_path)
    expanded = inspect_command(f"cat <<EOF\n$({body})\nEOF", cwd=tmp_path, home_dir=tmp_path)
    script = inspect_command(f"bash <<'EOF'\n{body}\nEOF", cwd=tmp_path, home_dir=tmp_path)

    assert data["status"] == "no_match"
    assert expanded["status"] == "review"
    assert "command.filesystem.recursive-delete" in {rule["rule_id"] for rule in expanded["rules"]}
    assert script["status"] == "review"
    assert "command.filesystem.recursive-delete" in {rule["rule_id"] for rule in script["rules"]}


def test_runtime_artifact_preserves_composite_rule_and_risk_evidence(tmp_path: Path) -> None:
    hidden_execution = "base" + "64 -d payload.txt | sh"
    mutation = "r" + "m -rf ./build"
    command = f"{hidden_execution} && {mutation}"
    request = extract_sensitive_tool_action_request(
        "Shell",
        {"command": command},
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    assert request is not None
    artifact = build_tool_action_request_artifact(
        "codex",
        request,
        config_path="config.toml",
        source_scope="project",
    )

    assert artifact.command == command
    assert artifact.metadata["command_security_identity"].startswith("command-security-v2:")
    assert {match["rule_id"] for match in artifact.metadata["command_rule_matches"]} == {
        "command.filesystem.recursive-delete",
        "command.encoded-execution.decode-and-execute",
    }
    assert set(artifact.metadata["risk_classes"]) == {"destructive_shell", "encoded_" + "execution"}


def test_runtime_artifact_applies_global_extension_lockdown(tmp_path: Path) -> None:
    command = "rm -rf ./build"
    request = extract_sensitive_tool_action_request(
        "Shell",
        {"command": command},
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    layer = ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=True,
        controls=(),
    )

    assert request is not None
    artifact = build_tool_action_request_artifact(
        "codex",
        request,
        config_path="config.toml",
        source_scope="project",
        extension_control_layers=(layer,),
    )

    assert artifact.metadata["command_action_floor"] == "block"
    assert artifact.metadata["extension_control_resolution"] == {
        "blocked": True,
        "failures": [],
    }
    decision_plane = artifact.metadata["command_decision_plane"]
    assert isinstance(decision_plane, dict)
    assert decision_plane["action"] == "block"
    assert any(reason["source"] == "control" for reason in decision_plane["reasons"] if isinstance(reason, dict))


def test_runtime_artifact_uses_active_extension_control_authority(tmp_path: Path) -> None:
    command = "rm -rf ./build"
    request = extract_sensitive_tool_action_request(
        "Shell",
        {"command": command},
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    layer = ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=True,
        controls=(),
    )
    snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(
        ExtensionControlAuthorityView(
            health=AuthorityHealth.PROTECTED,
            revision=1,
            catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
            layers=(layer,),
        )
    )

    assert request is not None
    with use_extension_control_snapshot(snapshot):
        artifact = build_tool_action_request_artifact(
            "codex",
            request,
            config_path="config.toml",
            source_scope="project",
        )

    assert artifact.metadata["command_action_floor"] == "block"
    assert artifact.metadata["extension_control_resolution"] == {
        "blocked": True,
        "failures": [],
    }
