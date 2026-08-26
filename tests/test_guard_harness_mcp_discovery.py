from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.adapters.harness_mcp_discovery import (
    MAX_DISCOVERED_MCP_SERVERS,
    apply_source_labels,
    discover_harness_mcp_servers,
    persist_discovered_harness_mcp_servers,
)
from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiError, LocalCliApiService
from codex_plugin_scanner.guard.local_cli_trust import utc_now
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.runtime.local_cli_commands import LocalCliCommand
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.runtime.local_mcp_probe import McpProbeResult
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


def test_discover_groups_same_launch_across_harnesses() -> None:
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
            ),
        ),
    )
    discovered = discover_harness_mcp_servers(
        home_dir=Path("."),
        guard_home=Path("."),
        detections=detections,
    )
    assert len(discovered) == 1
    assert discovered[0].identity.name == "github"
    assert discovered[0].source_label == "Codex, Claude Code"
    assert discovered[0].server_identity.env_keys == ("GITHUB_TOKEN",)
    assert "secret" not in discovered[0].identity.example_label


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
    assert item["identity_hash"] == harness_identity.identity_hash
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


def test_recognize_cli_id_survives_discovery_failure(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.Path.home",
        staticmethod(lambda: home),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.discover_harness_mcp_servers",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("detect failed")),
    )
    service = LocalCliApiService(store=GuardStore(home))
    try:
        service.recognize({"command": "python3 missing.py", "cli_id": "local-cli.mcp-aaaaaaaa"})
    except LocalCliApiError as exc:
        assert exc.code
    else:
        raise AssertionError("expected recognition to fail closed without crashing")


def test_list_items_survives_discovery_failure(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.Path.home",
        staticmethod(lambda: home),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.discover_harness_mcp_servers",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("detect failed")),
    )
    service = LocalCliApiService(store=GuardStore(home))
    payload = service.list_items()
    assert payload["items"] == []


def test_cli_id_collision_keeps_both_servers(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    first = UnlistedCliIdentity(
        cli_id="local-cli.mcp-aaaaaaaa",
        name="one",
        kind="executable",
        identity_hash="a" * 64,
        example_label="npx one",
    )
    second = UnlistedCliIdentity(
        cli_id="local-cli.mcp-aaaaaaaa",
        name="two",
        kind="executable",
        identity_hash="b" * 64,
        example_label="npx two",
    )
    first_id = store.ensure_local_mcp_observation(
        first,
        seen_at=utc_now(),
        server_identity_hash="a" * 64,
        server_command="npx",
        server_args_hash="1" * 64,
    )
    second_id = store.ensure_local_mcp_observation(
        second,
        seen_at=utc_now(),
        server_identity_hash="b" * 64,
        server_command="uvx",
        server_args_hash="2" * 64,
    )
    assert first_id == "local-cli.mcp-aaaaaaaa"
    assert second_id != first_id
    assert second_id.startswith("local-cli.mcp-")
    names = {item["name"] for item in store.list_local_cli_items()}
    assert names == {"one", "two"}


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
    items = apply_source_labels(store.list_local_cli_items(), labels)
    assert len(items) == 1
    assert items[0]["source_label"] == "Gemini"
    assert items[0]["surface"] == "mcp"
