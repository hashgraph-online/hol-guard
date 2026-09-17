from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiError, LocalCliApiService
from codex_plugin_scanner.guard.local_cli_trust import matching_local_mcp_grant, utc_now
from codex_plugin_scanner.guard.mcp_tool_calls import (
    build_tool_call_artifact,
    build_tool_call_hash,
    evaluate_tool_call,
)
from codex_plugin_scanner.guard.runtime.local_cli_commands import LocalCliCommand
from codex_plugin_scanner.guard.runtime.local_mcp_probe import McpProbeResult
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity
from codex_plugin_scanner.guard.store import GuardStore


def _clean_npx() -> str | None:
    path_value = os.environ.get("PATH", "")
    parts = [
        part
        for part in path_value.split(os.pathsep)
        if part
        and not (
            Path(part).as_posix().rstrip("/").endswith("/package-shims/bin")
            or "/.hol-guard/package-shims/" in Path(part).as_posix()
        )
    ]
    return shutil.which("npx", path=os.pathsep.join(parts)) if parts else shutil.which("npx")


def _identity():
    return build_mcp_server_identity(
        config_path="",
        command="npx",
        args=("-y", "@modelcontextprotocol/server-filesystem"),
        transport="stdio",
    )


def _artifact(identity, tool_name: str):
    return build_tool_call_artifact(
        harness="codex",
        server_name="filesystem",
        tool_name=tool_name,
        source_scope="project",
        config_path=".mcp.json",
        transport="stdio",
        server_identity=identity,
    )


def _config(tmp_path: Path) -> GuardConfig:
    return GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
        mode="prompt",
    )


def _enroll(
    store: GuardStore,
    identity,
    *,
    states: dict[str, str],
    grant_state: str = "allowed",
    example_label: str | None = None,
    commands: tuple[LocalCliCommand, ...] | None = None,
) -> None:
    from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity

    cli_identity = UnlistedCliIdentity(
        cli_id=f"local-cli.mcp-{identity.identity_hash[:8]}",
        name=identity.package_name or "mcp-server",
        kind="executable",
        identity_hash=identity.identity_hash,
        example_label=example_label or "npx -y @modelcontextprotocol/server-filesystem",
    )
    store.record_local_cli_observation(
        cli_identity,
        seen_at=utc_now(),
        surface="mcp",
        server_identity_hash=identity.identity_hash,
        server_command=identity.command,
        server_args_hash=identity.args_hash,
        help_status="ok",
    )
    store.replace_local_cli_commands(
        cli_identity.cli_id,
        commands
        or (
            LocalCliCommand("read_file", "read_file", "read_file", "Read a file"),
            LocalCliCommand("write_file", "write_file", "write_file", "Write a file"),
            LocalCliCommand("other", "Other tools", "server …", "other"),
        ),
    )
    store.upsert_local_cli_grant(
        identity=cli_identity,
        state=grant_state,
        expected_revision=0,
        updated_at=utc_now(),
        command_states=states,
    )


def test_allowed_tool_overrides_review(tmp_path: Path) -> None:
    identity = _identity()
    store = GuardStore(tmp_path / "guard-home")
    _enroll(store, identity, states={"read_file": "allow", "write_file": "inherit"})
    artifact = _artifact(identity, "read_file")
    arguments = {"path": "notes.txt"}
    decision = evaluate_tool_call(
        store=store,
        config=_config(tmp_path),
        artifact=artifact,
        artifact_hash=build_tool_call_hash(artifact, arguments, workspace=tmp_path, config=_config(tmp_path)),
        arguments=arguments,
        claim_saved_approval=False,
    )
    assert decision.action == "allow"
    assert decision.source == "local-mcp-extension"


def test_recommended_tool_stays_on_review(tmp_path: Path) -> None:
    identity = _identity()
    store = GuardStore(tmp_path / "guard-home")
    _enroll(store, identity, states={"read_file": "allow", "write_file": "inherit"})
    artifact = _artifact(identity, "write_file")
    arguments = {"path": "notes.txt", "contents": "hi"}
    decision = evaluate_tool_call(
        store=store,
        config=_config(tmp_path),
        artifact=artifact,
        artifact_hash=build_tool_call_hash(artifact, arguments, workspace=tmp_path, config=_config(tmp_path)),
        arguments=arguments,
        claim_saved_approval=False,
    )
    assert decision.action == "review"
    assert decision.source != "local-mcp-extension"


def test_blocked_tool_overrides_review(tmp_path: Path) -> None:
    identity = _identity()
    store = GuardStore(tmp_path / "guard-home")
    _enroll(store, identity, states={"write_file": "block"})
    artifact = _artifact(identity, "write_file")
    arguments = {"path": "notes.txt", "contents": "hi"}
    decision = evaluate_tool_call(
        store=store,
        config=_config(tmp_path),
        artifact=artifact,
        artifact_hash=build_tool_call_hash(artifact, arguments, workspace=tmp_path, config=_config(tmp_path)),
        arguments=arguments,
        claim_saved_approval=False,
    )
    assert decision.action == "block"
    assert decision.source == "local-mcp-extension"


def test_blocked_server_blocks_every_tool(tmp_path: Path) -> None:
    identity = _identity()
    store = GuardStore(tmp_path / "guard-home")
    _enroll(store, identity, states={"read_file": "allow"}, grant_state="blocked")
    artifact = _artifact(identity, "read_file")
    assert matching_local_mcp_grant(store=store, artifact=artifact, current_action="review") == "blocked"
    arguments = {"path": "notes.txt"}
    decision = evaluate_tool_call(
        store=store,
        config=_config(tmp_path),
        artifact=artifact,
        artifact_hash=build_tool_call_hash(artifact, arguments, workspace=tmp_path, config=_config(tmp_path)),
        arguments=arguments,
        claim_saved_approval=False,
    )
    assert decision.action == "block"
    assert decision.source == "local-mcp-extension"


def test_allow_does_not_override_block(tmp_path: Path) -> None:
    identity = _identity()
    store = GuardStore(tmp_path / "guard-home")
    _enroll(store, identity, states={"read_file": "allow"})
    artifact = _artifact(identity, "read_file")
    assert matching_local_mcp_grant(store=store, artifact=artifact, current_action="block") is None


def test_env_drift_still_matches_command_and_args(tmp_path: Path) -> None:
    identity = _identity()
    store = GuardStore(tmp_path / "guard-home")
    _enroll(store, identity, states={"read_file": "allow"})
    runtime = build_mcp_server_identity(
        config_path="",
        command="npx",
        args=("-y", "@modelcontextprotocol/server-filesystem"),
        transport="stdio",
        env={"GITHUB_TOKEN": "secret"},
        env_keys=("GITHUB_TOKEN",),
    )
    assert runtime.identity_hash != identity.identity_hash
    artifact = _artifact(runtime, "read_file")
    assert matching_local_mcp_grant(store=store, artifact=artifact, current_action="review") == "allowed"


def test_npx_absolute_path_still_matches_command_and_args(tmp_path: Path) -> None:
    npx = _clean_npx()
    if npx is None:
        pytest.skip("npx is not on PATH")
    identity = _identity()
    store = GuardStore(tmp_path / "guard-home")
    _enroll(store, identity, states={"read_file": "allow"})
    runtime = build_mcp_server_identity(
        config_path="",
        command=npx,
        args=("-y", "@modelcontextprotocol/server-filesystem"),
        transport="stdio",
    )
    assert runtime.identity_hash != identity.identity_hash
    assert runtime.args_hash == identity.args_hash
    artifact = _artifact(runtime, "read_file")
    assert matching_local_mcp_grant(store=store, artifact=artifact, current_action="review") == "allowed"
    arguments = {"path": "notes.txt"}
    decision = evaluate_tool_call(
        store=store,
        config=_config(tmp_path),
        artifact=artifact,
        artifact_hash=build_tool_call_hash(artifact, arguments, workspace=tmp_path, config=_config(tmp_path)),
        arguments=arguments,
        claim_saved_approval=False,
    )
    assert decision.action == "allow"
    assert decision.source == "local-mcp-extension"


def test_same_basename_different_executable_does_not_inherit_npx_grant(tmp_path: Path) -> None:
    impostor = tmp_path / "npx"
    impostor.write_text("#!/bin/sh\nexit 0\n")
    impostor.chmod(0o755)
    identity = _identity()
    store = GuardStore(tmp_path / "guard-home")
    _enroll(store, identity, states={"read_file": "allow"})
    runtime = build_mcp_server_identity(
        config_path="",
        command=str(impostor),
        args=("-y", "@modelcontextprotocol/server-filesystem"),
        transport="stdio",
    )
    artifact = _artifact(runtime, "read_file")
    assert matching_local_mcp_grant(store=store, artifact=artifact, current_action="review") is None


def test_same_package_extra_npx_flags_still_match_allow_all(tmp_path: Path) -> None:
    npx = _clean_npx()
    if npx is None:
        pytest.skip("npx is not on PATH")
    enrolled = build_mcp_server_identity(
        config_path="",
        command="npx",
        args=("-y", "chrome-devtools-mcp@latest"),
        transport="stdio",
    )
    runtime = build_mcp_server_identity(
        config_path="",
        command=npx,
        args=(
            "--yes",
            "chrome-devtools-mcp@latest",
            "--isolated",
            "--executablePath",
            "/usr/bin/true",
        ),
        transport="stdio",
    )
    assert runtime.identity_hash != enrolled.identity_hash
    assert runtime.args_hash != enrolled.args_hash
    assert runtime.package_name == enrolled.package_name == "chrome-devtools-mcp"
    store = GuardStore(tmp_path / "guard-home")
    _enroll(
        store,
        enrolled,
        states={"click": "allow", "evaluate_script": "allow", "other": "allow"},
        example_label="npx -y chrome-devtools-mcp@latest",
        commands=(
            LocalCliCommand("click", "click", "click", "Click a page element"),
            LocalCliCommand("evaluate_script", "evaluate_script", "evaluate_script", "Run page script"),
            LocalCliCommand("other", "Other tools", "server …", "other"),
        ),
    )
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="chrome-devtools",
        tool_name="click",
        source_scope="global",
        config_path=".mcp.json",
        transport="stdio",
        server_identity=runtime,
    )
    assert matching_local_mcp_grant(store=store, artifact=artifact, current_action="review") == "allowed"
    arguments = {"uid": "1_2"}
    decision = evaluate_tool_call(
        store=store,
        config=_config(tmp_path),
        artifact=artifact,
        artifact_hash=build_tool_call_hash(artifact, arguments, workspace=tmp_path, config=_config(tmp_path)),
        arguments=arguments,
        claim_saved_approval=False,
    )
    assert decision.action == "allow"
    assert decision.source == "local-mcp-extension"


def test_registry_override_does_not_inherit_npx_grant(tmp_path: Path) -> None:
    npx = _clean_npx()
    if npx is None:
        pytest.skip("npx is not on PATH")
    enrolled = build_mcp_server_identity(
        config_path="",
        command="npx",
        args=("-y", "chrome-devtools-mcp@latest"),
        transport="stdio",
    )
    runtime = build_mcp_server_identity(
        config_path="",
        command=npx,
        args=("-y", "--registry", "https://example.invalid/npm", "chrome-devtools-mcp@latest"),
        transport="stdio",
    )
    assert runtime.package_source != enrolled.package_source
    store = GuardStore(tmp_path / "guard-home")
    _enroll(
        store,
        enrolled,
        states={"click": "allow", "other": "allow"},
        example_label="npx -y chrome-devtools-mcp@latest",
        commands=(
            LocalCliCommand("click", "click", "click", "Click a page element"),
            LocalCliCommand("other", "Other tools", "server …", "other"),
        ),
    )
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="chrome-devtools",
        tool_name="click",
        source_scope="global",
        config_path=".mcp.json",
        transport="stdio",
        server_identity=runtime,
    )
    assert matching_local_mcp_grant(store=store, artifact=artifact, current_action="review") is None


def test_explicit_package_version_change_does_not_inherit_grant(tmp_path: Path) -> None:
    npx = _clean_npx()
    if npx is None:
        pytest.skip("npx is not on PATH")
    enrolled = build_mcp_server_identity(
        config_path="",
        command="npx",
        args=("-y", "chrome-devtools-mcp@1.0.0"),
        transport="stdio",
    )
    runtime = build_mcp_server_identity(
        config_path="",
        command=npx,
        args=("-y", "chrome-devtools-mcp@2.0.0"),
        transport="stdio",
    )
    store = GuardStore(tmp_path / "guard-home")
    _enroll(
        store,
        enrolled,
        states={"click": "allow", "other": "allow"},
        example_label="npx -y chrome-devtools-mcp@1.0.0",
        commands=(
            LocalCliCommand("click", "click", "click", "Click a page element"),
            LocalCliCommand("other", "Other tools", "server …", "other"),
        ),
    )
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="chrome-devtools",
        tool_name="click",
        source_scope="global",
        config_path=".mcp.json",
        transport="stdio",
        server_identity=runtime,
    )
    assert matching_local_mcp_grant(store=store, artifact=artifact, current_action="review") is None


def test_shim_only_path_does_not_resolve_package_launcher(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.runtime.mcp_protection import resolved_package_launcher_executable

    shim_bin = tmp_path / ".hol-guard" / "package-shims" / "bin"
    shim_bin.mkdir(parents=True)
    impostor = shim_bin / "npx"
    impostor.write_text("#!/bin/sh\nexit 0\n")
    impostor.chmod(0o755)
    monkeypatch.setenv("PATH", str(shim_bin))
    assert resolved_package_launcher_executable("npx") is None


def test_different_package_does_not_inherit_npx_grant(tmp_path: Path) -> None:
    npx = _clean_npx()
    if npx is None:
        pytest.skip("npx is not on PATH")
    enrolled = _identity()
    runtime = build_mcp_server_identity(
        config_path="",
        command=npx,
        args=("-y", "chrome-devtools-mcp@latest"),
        transport="stdio",
    )
    store = GuardStore(tmp_path / "guard-home")
    _enroll(store, enrolled, states={"read_file": "allow", "other": "allow"})
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="chrome-devtools",
        tool_name="click",
        source_scope="global",
        config_path=".mcp.json",
        transport="stdio",
        server_identity=runtime,
    )
    assert matching_local_mcp_grant(store=store, artifact=artifact, current_action="review") is None


def test_non_launcher_path_does_not_inherit_npx_grant(tmp_path: Path) -> None:
    identity = _identity()
    store = GuardStore(tmp_path / "guard-home")
    _enroll(store, identity, states={"read_file": "allow"})
    runtime = build_mcp_server_identity(
        config_path="",
        command="/usr/bin/node",
        args=("-y", "@modelcontextprotocol/server-filesystem"),
        transport="stdio",
    )
    artifact = _artifact(runtime, "read_file")
    assert matching_local_mcp_grant(store=store, artifact=artifact, current_action="review") is None


def test_identity_mismatch_does_not_apply(tmp_path: Path) -> None:
    identity = _identity()
    other = build_mcp_server_identity(
        config_path="",
        command="npx",
        args=("-y", "@modelcontextprotocol/server-github"),
        transport="stdio",
    )
    store = GuardStore(tmp_path / "guard-home")
    _enroll(store, identity, states={"read_file": "allow"})
    artifact = _artifact(other, "read_file")
    assert matching_local_mcp_grant(store=store, artifact=artifact, current_action="review") is None


def test_recognize_mcp_package_persists_tools(tmp_path: Path, monkeypatch) -> None:
    from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.Path.home",
        staticmethod(lambda: home),
    )
    identity = _identity()

    def _probe(command: str, **_kwargs):
        return McpProbeResult(
            identity=UnlistedCliIdentity(
                cli_id=f"local-cli.mcp-{identity.identity_hash[:8]}",
                name="@modelcontextprotocol/server-filesystem",
                kind="executable",
                identity_hash=identity.identity_hash,
                example_label=command,
            ),
            server_identity=identity,
            tools=(
                LocalCliCommand("read_file", "read_file", "read_file", "Read a file"),
                LocalCliCommand("other", "Other tools", "server …", "other"),
            ),
            status="ok",
            argv=("npx", "-y", "@modelcontextprotocol/server-filesystem"),
        )

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.probe_stdio_mcp_server",
        _probe,
    )
    service = LocalCliApiService(store=GuardStore(home))
    result = service.recognize({"command": "npx -y @modelcontextprotocol/server-filesystem"})
    item = result["item"]
    assert isinstance(item, dict)
    assert item["surface"] == "mcp"
    assert item["server_identity_hash"] == identity.identity_hash
    ids = [entry["command_id"] for entry in item["commands"]]
    assert "read_file" in ids
    assert "other" in ids
    assert "MCP server" in str(result["summary"]) or "tools" in str(result["summary"]).lower()


def test_recognize_failed_package_mcp_stays_built_in(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.Path.home",
        staticmethod(lambda: home),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.probe_stdio_mcp_server",
        lambda *args, **kwargs: None,
    )
    service = LocalCliApiService(store=GuardStore(home))
    try:
        service.recognize({"command": "npx -y cowsay"})
    except LocalCliApiError as exc:
        assert exc.code == "already_built_in"
        assert "MCP tools" in str(exc)
    else:
        raise AssertionError("expected package launcher without MCP tools to be rejected")
