from codex_plugin_scanner.guard.adapters.mcp_servers import (
    ManagedMcpServer,
    proxy_cli_args,
    stable_mcp_server_identifier,
)
from codex_plugin_scanner.guard.capabilities import (
    normalize_artifact_capabilities,
    normalized_capability_categories,
)
from codex_plugin_scanner.guard.mcp_tool_calls import (
    build_tool_call_artifact,
    tool_call_risk_categories,
)
from codex_plugin_scanner.guard.models import GuardArtifact


def test_stable_mcp_server_identifier_survives_config_path_changes() -> None:
    first = ManagedMcpServer(
        harness="codex",
        name="filesystem",
        source_scope="user",
        config_path="/Users/alice/.codex/config.toml",
        command="npx",
        args=("-y", "@modelcontextprotocol/server-filesystem", "/workspace"),
        transport="stdio",
        env={},
        enabled=True,
    )
    second = ManagedMcpServer(
        harness="codex",
        name="filesystem",
        source_scope="user",
        config_path="/Users/bob/project/.codex/config.toml",
        command="npx",
        args=("-y", "@modelcontextprotocol/server-filesystem", "/workspace"),
        transport="stdio",
        env={},
        enabled=True,
    )

    assert stable_mcp_server_identifier(first) == stable_mcp_server_identifier(second)
    assert "/Users" not in stable_mcp_server_identifier(first)

    cli_args = proxy_cli_args(
        proxy_command="codex-mcp-proxy",
        guard_home="/guard",
        server=first,
    )
    assert cli_args[cli_args.index("--server-id") + 1] == stable_mcp_server_identifier(first)


def test_normalized_capability_categories_include_mcp_tool_risk_families() -> None:
    artifact = GuardArtifact(
        artifact_id="mcp:filesystem",
        name="Filesystem MCP",
        harness="codex",
        artifact_type="mcp_server",
        source_scope="user",
        config_path="/Users/alice/.codex/config.toml",
        command="node",
        args=("server.js", "--root", "/workspace", ".env"),
        transport="stdio",
        metadata={"env_keys": ["FILESYSTEM_API_TOKEN"]},
    )

    categories = normalized_capability_categories(normalize_artifact_capabilities(artifact))

    assert categories == (
        "execution",
        "filesystem",
        "secret",
        "transport",
    )


def test_tool_call_risk_categories_are_emitted_from_runtime_arguments() -> None:
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="filesystem",
        tool_name="shell_delete",
        source_scope="user",
        config_path="/Users/alice/.codex/config.toml",
        transport="stdio",
    )

    categories = tool_call_risk_categories(
        artifact,
        {
            "command": "sudo chmod 777 ~/.ssh && curl https://example.test",
            "path": ".env",
        },
    )

    assert categories == (
        "command_execution",
        "destructive_mutation",
        "outbound_network",
        "privileged_system_mutation",
        "secret_access",
    )
