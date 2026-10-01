from __future__ import annotations

from pathlib import Path

import pytest

import codex_plugin_scanner.guard.adapters as adapters_module
import codex_plugin_scanner.guard.daemon.local_cli_api as local_cli_api_module
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.harness_mcp_discovery import (
    MAX_DISCOVERED_MCP_SERVERS,
    _safe_detections,
    apply_source_labels,
    discover_harness_mcp_servers,
    discovered_server_for_observation,
    persist_discovered_harness_mcp_servers,
)
from codex_plugin_scanner.guard.adapters.mcp_servers import managed_stdio_servers
from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiService
from codex_plugin_scanner.guard.local_cli_trust import matching_local_mcp_grant, utc_now
from codex_plugin_scanner.guard.mcp_tool_calls import build_tool_call_artifact
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.runtime.local_cli_commands import LocalCliCommand
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.runtime.local_mcp_probe import McpProbeResult
from codex_plugin_scanner.guard.runtime.local_mcp_stdio import McpCatalogResult
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity
from codex_plugin_scanner.guard.store import GuardStore


def _artifact(
    *,
    harness: str,
    name: str,
    command: str,
    args: tuple[str, ...],
    env: dict[str, str] | None = None,
    metadata: dict[str, object] | None = None,
) -> GuardArtifact:
    payload: dict[str, object] = dict(metadata or {})
    if env is not None:
        payload["env"] = env
    return GuardArtifact(
        artifact_id=f"{harness}:mcp:{name}",
        name=name,
        harness=harness,
        artifact_type="mcp_server",
        source_scope="user",
        config_path=f"{harness}/mcp.json",
        command=command,
        args=args,
        transport="stdio",
        metadata=payload,
    )


def _detection(harness: str, *artifacts: GuardArtifact) -> HarnessDetection:
    return HarnessDetection(
        harness=harness,
        installed=True,
        command_available=True,
        config_paths=(f"{harness}/mcp.json",),
        artifacts=artifacts,
    )


def test_packaged_native_proxies_are_not_offered_as_servers(tmp_path: Path) -> None:
    detections = (
        _detection(
            "opencode",
            _artifact(
                harness="opencode",
                name="hol-guard::browser",
                command="hol-guard",
                args=("opencode-mcp-proxy", "--command", "node"),
            ),
            _artifact(
                harness="opencode",
                name="hol-guard::unverified",
                command="node",
                args=("server.js",),
            ),
        ),
    )
    servers = discover_harness_mcp_servers(
        home_dir=tmp_path,
        guard_home=tmp_path / "guard-home",
        detections=detections,
    )
    assert [server.identity.name for server in servers] == ["hol-guard::unverified"]


def test_installed_guard_proxy_server_remains_discoverable_without_rewrapping(tmp_path: Path) -> None:
    wrapped = _artifact(
        harness="codex",
        name="guard_canary",
        command="/usr/local/bin/mcp-server-filesystem",
        args=(str(tmp_path / "allowed"),),
        metadata={"guard_managed_proxy": True},
    )
    detection = _detection("codex", wrapped)

    assert managed_stdio_servers(detection) == ()
    servers = discover_harness_mcp_servers(
        home_dir=tmp_path,
        guard_home=tmp_path / "guard-home",
        detections=(detection,),
    )

    assert len(servers) == 1
    assert servers[0].identity.name == "guard_canary"
    assert servers[0].server_identity.command == "/usr/local/bin/mcp-server-filesystem"


def test_discovery_uses_managed_codex_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store.set_managed_install("codex", True, str(workspace), {}, utc_now())
    observed: list[Path | None] = []

    def discover(**kwargs: object) -> tuple[()]:
        observed.append(kwargs.get("workspace_dir"))
        return ()

    monkeypatch.setattr(local_cli_api_module, "discover_harness_mcp_servers", discover)

    LocalCliApiService(store=store)._discovered_servers()

    assert observed == [workspace]


def test_managed_codex_discovery_authenticates_default_home_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed: list[tuple[bool, bool]] = []

    class CodexAdapter:
        harness = "codex"

        def detect(self, context: HarnessContext) -> HarnessDetection:
            home_explicit = context.home_override_explicit
            workspace_explicit = context.workspace_override_explicit
            observed.append((home_explicit, workspace_explicit))
            if home_explicit:
                raise RuntimeError("manifest belongs to default home context")
            return _detection("codex")

    monkeypatch.setattr(adapters_module, "list_adapters", lambda: (CodexAdapter(),))

    detections = _safe_detections(tmp_path, tmp_path / "guard-home", tmp_path / "workspace")

    assert len(detections) == 1
    assert observed == [(True, True), (False, True)]


def test_identical_launches_keep_distinct_host_connections() -> None:
    detections = (
        _detection(
            "codex",
            _artifact(
                harness="codex",
                name="github",
                command="npx",
                args=("-y", "@modelcontextprotocol/server-github"),
                env={"GITHUB_TOKEN": "secret"},
            ),
        ),
        _detection(
            "claude-code",
            _artifact(
                harness="claude-code",
                name="github",
                command="npx",
                args=("-y", "@modelcontextprotocol/server-github"),
                env={"GITHUB_TOKEN": "secret"},
            ),
        ),
    )
    discovered = discover_harness_mcp_servers(
        home_dir=Path("."),
        guard_home=Path("."),
        detections=detections,
    )
    assert len(discovered) == 2
    assert discovered[0].identity.name == "github"
    assert {server.source_label for server in discovered} == {"Codex", "Claude Code"}
    assert discovered[0].identity.identity_hash != discovered[1].identity.identity_hash
    assert discovered[0].server_identity.env_keys == ("GITHUB_TOKEN",)
    assert "secret" not in discovered[0].identity.example_label
    server_hash = discovered[0].server_identity.identity_hash
    assert discovered_server_for_observation(
        discovered, cli_id=f"local-cli.mcp-{server_hash[:8]}", server_identity_hash=server_hash,
        server_command=discovered[0].server_identity.command,
        args_hash=discovered[0].server_identity.args_hash,
        source_label="Codex, Claude Code",
    ) is None
    assert discovered_server_for_observation(
        discovered, cli_id=f"local-cli.mcp-{server_hash[:8]}", server_identity_hash=server_hash,
        server_command=discovered[0].server_identity.command,
        args_hash=discovered[0].server_identity.args_hash,
        source_label="Codex",
    ) == next(server for server in discovered if server.source_label == "Codex")


def test_distinct_configured_environments_do_not_merge(tmp_path: Path) -> None:
    artifacts = tuple(
        _artifact(
            harness="codex",
            name=name,
            command="npx",
            args=("-y", "pkg"),
            env={"ACCOUNT": name},
        )
        for name in ("personal", "work")
    )
    servers = discover_harness_mcp_servers(
        home_dir=tmp_path,
        guard_home=tmp_path,
        detections=(_detection("codex", *artifacts),),
    )
    assert len(servers) == 2
    store = GuardStore(tmp_path / "guard")
    labels = persist_discovered_harness_mcp_servers(store, servers, seen_at=utc_now())
    assert len(labels) == 2
    for server in servers:
        found = store.find_local_mcp_observation(
            server_identity_hash=server.identity.identity_hash,
            command=server.server_identity.command,
            args_hash=server.server_identity.args_hash,
        )
        assert found is not None
        assert found["identity_hash"] == server.identity.identity_hash
    assert (
        store.find_local_mcp_observation(
            command=servers[0].server_identity.command,
            args_hash=servers[0].server_identity.args_hash,
        )
        is None
    )


@pytest.mark.parametrize(("legacy_state", "expected_new_state"), [
    ("blocked", "blocked"), ("allowed", None), ("allowed_with_block", "blocked"),
    ("late_block", "blocked"),
])
def test_legacy_authority_split_carries_deny_without_migrating_allow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, legacy_state: str, expected_new_state: str | None
) -> None:
    servers = discover_harness_mcp_servers(
        home_dir=tmp_path,
        guard_home=tmp_path / "guard",
        detections=(_detection("codex", _artifact(
            harness="codex", name="legacy", command="uvx", args=("legacy-mcp",),
        )),),
    )
    assert len(servers) == 1
    server = servers[0]
    old_hash = server.server_identity.identity_hash
    legacy = UnlistedCliIdentity(
        cli_id=f"local-cli.mcp-{old_hash[:8]}", name="legacy", kind="executable",
        identity_hash=old_hash, example_label="uvx legacy-mcp",
    )
    store = GuardStore(tmp_path / "guard")
    store.ensure_local_mcp_observation(
        legacy, seen_at=utc_now(), server_identity_hash=old_hash,
        server_command=server.server_identity.command,
        server_args_hash=server.server_identity.args_hash,
        source_label=server.source_label,
    )
    if legacy_state == "allowed_with_block":
        store.replace_local_cli_commands(
            legacy.cli_id, (LocalCliCommand("read", "read", "read", "Read"),),
        )
    if legacy_state == "late_block":
        injected = False

        def add_denial_before_transaction(_guard_home: Path) -> None:
            nonlocal injected
            if injected:
                return
            injected = True
            store.upsert_local_cli_grant(
                identity=legacy, state="blocked", expected_revision=store.read_local_cli_revision(),
                updated_at=utc_now(),
            )

        monkeypatch.setattr(
            "codex_plugin_scanner.guard.native_policy_snapshot.notify_native_policy_mutation",
            add_denial_before_transaction,
        )
    else:
        store.upsert_local_cli_grant(
            identity=legacy, state="allowed" if legacy_state == "allowed_with_block" else legacy_state,
            expected_revision=store.read_local_cli_revision(),
            updated_at=utc_now(),
            command_states={"read": "block"} if legacy_state == "allowed_with_block" else None,
        )
    labels = persist_discovered_harness_mcp_servers(store, servers, seen_at=utc_now())
    assert server.identity.cli_id in labels
    grant = store.read_local_mcp_grant(
        old_hash, command=server.server_identity.command,
        args_hash=server.server_identity.args_hash,
        connection_identity_hash=server.identity.identity_hash,
    )
    assert (grant["state"] if grant is not None else None) == expected_new_state
    listed = LocalCliApiService(store=store).list_items()["items"]
    assert [item["cli_id"] for item in listed] == [server.identity.cli_id]
    assert listed[0]["state"] == ("blocked" if expected_new_state == "blocked" else "unset")
    assert discovered_server_for_observation(
        servers, cli_id=legacy.cli_id, server_identity_hash=old_hash,
        server_command=server.server_identity.command, args_hash=server.server_identity.args_hash,
        source_label=server.source_label,
    ) == server


def test_configured_grants_follow_exact_host_and_configuration(tmp_path: Path) -> None:
    servers = discover_harness_mcp_servers(
        home_dir=tmp_path,
        guard_home=tmp_path,
        detections=tuple(
            _detection(host, _artifact(harness=host, name="github", command="npx", args=("-y", "pkg")))
            for host in ("codex", "claude-code")
        ),
    )
    assert len(servers) == 2
    assert servers[0].server_identity.identity_hash == servers[1].server_identity.identity_hash
    store = GuardStore(tmp_path / "guard")
    persist_discovered_harness_mcp_servers(store, servers, seen_at=utc_now())
    for server in servers:
        connection = server.connection_identity
        assert connection is not None
        choice = "allow" if connection.host == "codex" else "block"
        store.replace_local_cli_commands(
            server.identity.cli_id,
            (LocalCliCommand("read_file", "read_file", "read_file", "Read a file"),),
            mcp_catalog=McpCatalogResult(
                tools=({"name": "read_file", "inputSchema": {"type": "object"}},),
                complete=True,
            ),
            identity_hash=server.identity.identity_hash,
            seen_at=utc_now(),
        )
        store.upsert_local_cli_grant(
            identity=server.identity,
            state="allowed",
            expected_revision=store.read_local_cli_revision(),
            updated_at=utc_now(),
            command_states={"read_file": choice},
        )
    for server in servers:
        connection = server.connection_identity
        assert connection is not None
        artifact = build_tool_call_artifact(
            harness=connection.host,
            server_name="github",
            tool_name="read_file",
            source_scope="user",
            config_path=f"{connection.host}/mcp.json",
            transport="stdio",
            server_identity=server.server_identity,
            tool_definition={"name": "read_file", "inputSchema": {"type": "object"}},
        )
        assert matching_local_mcp_grant(store=store, artifact=artifact, current_action="review") == (
            "allowed" if connection.host == "codex" else "blocked"
        )
        changed_config = build_tool_call_artifact(
            harness=connection.host,
            server_name="github",
            tool_name="read_file",
            source_scope="user",
            config_path="different/mcp.json",
            transport="stdio",
            server_identity=server.server_identity,
        )
        assert matching_local_mcp_grant(store=store, artifact=changed_config, current_action="review") is None
        changed_schema = build_tool_call_artifact(
            harness=connection.host,
            server_name="github",
            tool_name="read_file",
            source_scope="user",
            config_path=f"{connection.host}/mcp.json",
            transport="stdio",
            server_identity=server.server_identity,
            tool_definition={"name": "read_file", "inputSchema": {"type": "object", "required": ["destination"]}},
        )
        assert matching_local_mcp_grant(store=store, artifact=changed_schema, current_action="review") == (
            "review" if connection.host == "codex" else "blocked"
        )
    assert (
        store.find_local_mcp_observation(
            server_identity_hash="0" * 64,
            command=servers[0].server_identity.command,
            args_hash=servers[0].server_identity.args_hash,
        )
        is None
    )
    assert (
        discovered_server_for_observation(
            servers,
            server_command=servers[0].server_identity.command,
            args_hash=servers[0].server_identity.args_hash,
        )
        is None
    )
    assert (
        discovered_server_for_observation(
            servers,
            cli_id=servers[1].identity.cli_id,
            server_command=servers[0].server_identity.command,
            args_hash=servers[0].server_identity.args_hash,
        )
        == servers[1]
    )
    assert (
        discovered_server_for_observation(
            servers,
            cli_id="local-cli.mcp-missing",
            server_command=servers[0].server_identity.command,
            args_hash=servers[0].server_identity.args_hash,
        )
        is None
    )


def test_discover_redacts_secret_argv_tokens() -> None:
    detections = (
        _detection(
            "codex",
            _artifact(
                harness="codex",
                name="github",
                command="npx",
                args=("-y", "@modelcontextprotocol/server-github", "--token", "sk-live-secret"),
            ),
        ),
    )
    discovered = discover_harness_mcp_servers(
        home_dir=Path("."),
        guard_home=Path("."),
        detections=detections,
    )
    assert len(discovered) == 1
    assert "sk-live-secret" not in discovered[0].identity.example_label
    assert "--token" in discovered[0].identity.example_label
    assert "*****" in discovered[0].identity.example_label
    assert "sk-live-secret" in discovered[0].launch_command


def test_discover_skips_guard_proxy_and_caps_results() -> None:
    skipped = (
        _artifact(
            harness="codex",
            name="hol-guard::companion",
            command="hol-guard",
            args=("guard", "codex-mcp-proxy"),
        ),
        _artifact(
            harness="codex",
            name="wrapped",
            command="npx",
            args=("-y", "@modelcontextprotocol/server-filesystem"),
            metadata={"guard_managed_proxy": True},
        ),
        GuardArtifact(
            artifact_id="codex:mcp:remote",
            name="remote",
            harness="codex",
            artifact_type="mcp_server",
            source_scope="user",
            config_path="codex/mcp.json",
            command="npx",
            args=("-y", "remote"),
            transport="http",
        ),
    )
    extras = tuple(
        _artifact(
            harness="codex",
            name=f"server-{index:02d}",
            command="npx",
            args=("-y", f"pkg-{index}"),
        )
        for index in range(MAX_DISCOVERED_MCP_SERVERS + 5)
    )
    discovered = discover_harness_mcp_servers(
        home_dir=Path("."),
        guard_home=Path("."),
        detections=(_detection("codex", *skipped, *extras),),
    )
    names = {item.identity.name for item in discovered}
    assert "hol-guard::companion" not in names
    assert "wrapped" not in names
    assert "remote" not in names
    assert len(discovered) == MAX_DISCOVERED_MCP_SERVERS


def test_list_items_observes_without_probing_or_incrementing(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.Path.home",
        staticmethod(lambda: home),
    )
    detection = _detection(
        "cursor",
        _artifact(
            harness="cursor",
            name="filesystem",
            command="npx",
            args=("-y", "@modelcontextprotocol/server-filesystem"),
            env={"TOKEN": "redacted"},
        ),
    )

    def _discover(**_kwargs):
        return discover_harness_mcp_servers(
            home_dir=home,
            guard_home=home,
            detections=(detection,),
        )

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.discover_harness_mcp_servers",
        _discover,
    )
    service = LocalCliApiService(store=GuardStore(home))
    unread = service.list_items()
    assert unread["items"] == []
    _ = service._observe_harness_mcp_servers()
    first = service.list_items()
    restarted = LocalCliApiService(store=GuardStore(home)).list_items()
    second = service.list_items()
    items = first["items"]
    assert isinstance(items, list)
    assert len(items) == 1
    item = items[0]
    assert isinstance(item, dict)
    assert item["name"] == "filesystem"
    assert item["surface"] == "mcp"
    assert item["state"] == "unset"
    assert item["source_label"] == "Cursor"
    assert item["observed_count"] == 1
    assert item["help_status"] is None
    assert item["commands"] == []
    second_items = second["items"]
    assert isinstance(second_items, list)
    second_item = second_items[0]
    assert isinstance(second_item, dict)
    assert second_item["observed_count"] == 1
    assert second_item["source_label"] == "Cursor"
    restarted_items = restarted["items"]
    assert isinstance(restarted_items, list)
    restarted_item = restarted_items[0]
    assert isinstance(restarted_item, dict)
    assert restarted_item["source_label"] == "Cursor"


def test_recognize_reuses_harness_identity(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.Path.home",
        staticmethod(lambda: home),
    )
    args = ("-y", "@modelcontextprotocol/server-github")
    harness_identity = build_mcp_server_identity(
        config_path="",
        command="npx",
        args=args,
        transport="stdio",
        env={"GITHUB_TOKEN": "secret"},
    )
    probed_identity = build_mcp_server_identity(
        config_path="",
        command="npx",
        args=args,
        transport="stdio",
    )
    assert harness_identity.identity_hash != probed_identity.identity_hash
    detection = _detection(
        "codex",
        _artifact(
            harness="codex",
            name="github",
            command="npx",
            args=args,
            env={"GITHUB_TOKEN": "secret"},
        ),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.discover_harness_mcp_servers",
        lambda **_kwargs: discover_harness_mcp_servers(
            home_dir=home,
            guard_home=home,
            detections=(detection,),
        ),
    )

    def _probe(command: str, **_kwargs):
        from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity

        return McpProbeResult(
            identity=UnlistedCliIdentity(
                cli_id=f"local-cli.mcp-{probed_identity.identity_hash[:8]}",
                name="@modelcontextprotocol/server-github",
                kind="executable",
                identity_hash=probed_identity.identity_hash,
                example_label=command,
            ),
            server_identity=probed_identity,
            tools=(
                LocalCliCommand("get_file", "get_file", "get_file", "Get a file"),
                LocalCliCommand("other", "Other tools", "server …", "other"),
            ),
            status="ok",
            argv=("npx", *args),
        )

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.probe_stdio_mcp_server",
        _probe,
    )
    store = GuardStore(home)
    service = LocalCliApiService(store=store)
    _ = service._observe_harness_mcp_servers()
    listed = service.list_items()
    listed_items = listed["items"]
    assert isinstance(listed_items, list)
    listed_item = listed_items[0]
    assert isinstance(listed_item, dict)
    result = service.recognize(
        {
            "command": str(listed_item["example_label"]),
            "cli_id": str(listed_item["cli_id"]),
        }
    )
    item = result["item"]
    assert isinstance(item, dict)
    assert item["cli_id"] == listed_item["cli_id"]
    assert item["identity_hash"] == listed_item["identity_hash"]
    assert item["identity_hash"] != harness_identity.identity_hash
    assert item["identity_hash"] != probed_identity.identity_hash
    assert item["name"] == "github"
    ids = [entry["command_id"] for entry in item["commands"]]
    assert "get_file" in ids
    assert len(store.list_local_cli_items()) == 1


def test_recognize_cli_id_uses_live_launch_command(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.Path.home",
        staticmethod(lambda: home),
    )
    args = ("-y", "pkg", "--token", "sk-live-secret")
    detection = _detection(
        "codex",
        _artifact(harness="codex", name="secret-server", command="npx", args=args),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.discover_harness_mcp_servers",
        lambda **_kwargs: discover_harness_mcp_servers(
            home_dir=home,
            guard_home=home,
            detections=(detection,),
        ),
    )
    captured: dict[str, str] = {}

    def _probe(command: str, **_kwargs):
        captured["command"] = command
        identity = build_mcp_server_identity(config_path="", command="npx", args=args, transport="stdio")
        return McpProbeResult(
            identity=UnlistedCliIdentity(
                cli_id=f"local-cli.mcp-{identity.identity_hash[:8]}",
                name="secret-server",
                kind="executable",
                identity_hash=identity.identity_hash,
                example_label=command,
            ),
            server_identity=identity,
            tools=(LocalCliCommand("other", "Other tools", "server …", "other"),),
            status="ok",
            argv=("npx", *args),
        )

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.probe_stdio_mcp_server",
        _probe,
    )
    service = LocalCliApiService(store=GuardStore(home))
    _ = service._observe_harness_mcp_servers()
    listed = service.list_items()
    listed_item = listed["items"][0]
    assert isinstance(listed_item, dict)
    assert "sk-live-secret" not in str(listed_item["example_label"])
    recognized = service.recognize({"command": str(listed_item["example_label"]), "cli_id": str(listed_item["cli_id"])})
    assert "sk-live-secret" in captured["command"]
    item = recognized["item"]
    assert isinstance(item, dict)
    assert "sk-live-secret" not in str(item["example_label"])


def test_persist_and_overlay_labels(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    detections = (
        _detection(
            "gemini",
            _artifact(
                harness="gemini",
                name="notes",
                command="uvx",
                args=("mcp-server-git",),
            ),
        ),
    )
    servers = discover_harness_mcp_servers(
        home_dir=tmp_path,
        guard_home=tmp_path,
        detections=detections,
    )
    labels = persist_discovered_harness_mcp_servers(store, servers, seen_at=utc_now())
    stored = store.list_local_cli_items()
    assert len(stored) == 1
    assert stored[0]["source_label"] == "Gemini"
    items = apply_source_labels(stored, labels)
    assert len(items) == 1
    assert items[0]["source_label"] == "Gemini"
    assert items[0]["surface"] == "mcp"
    listed = LocalCliApiService(store=store).list_items()["items"]
    assert isinstance(listed, list)
    assert listed[0]["source_label"] == "Gemini"
