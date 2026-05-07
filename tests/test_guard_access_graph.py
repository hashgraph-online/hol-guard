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
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity


def test_stable_mcp_server_identifier_survives_config_path_changes() -> None:
    first = ManagedMcpServer(
        harness="codex",
        name="filesystem",
        source_scope="user",
        config_path="/Users/alice/.codex/config.toml",
        command="npx",
        args=("-y", "@modelcontextprotocol/server-filesystem", "/workspace"),
        transport="stdio",
        env={"TOKEN": "redacted"},
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
    assert "--server-env-key=TOKEN" in cli_args


def test_stable_mcp_server_identifier_canonicalizes_names_and_path_args() -> None:
    first = ManagedMcpServer(
        harness="codex",
        name=" Filesystem ",
        source_scope="user",
        config_path="/Users/alice/.codex/config.toml",
        command="/usr/local/bin/npx",
        args=(
            "-y",
            "@modelcontextprotocol/server-filesystem",
            "--root=/home/alice/workspace",
            "--cache=D:\\alice\\repo",
        ),
        transport="stdio",
        env={},
        enabled=True,
    )
    second = ManagedMcpServer(
        harness="codex",
        name="filesystem",
        source_scope="user",
        config_path="/Users/bob/.codex/config.toml",
        command="npx",
        args=(
            "-y",
            "@modelcontextprotocol/server-filesystem",
            "--root=/home/bob/project",
            "--cache=D:\\bob\\repo",
        ),
        transport="stdio",
        env={},
        enabled=True,
    )

    identifier = stable_mcp_server_identifier(first)

    assert identifier == stable_mcp_server_identifier(second)
    assert ":filesystem:" in identifier
    assert "Filesystem" not in identifier
    assert "alice" not in identifier


def test_stable_mcp_server_identifier_uses_safe_empty_name_fallback() -> None:
    server = ManagedMcpServer(
        harness="codex",
        name="   ",
        source_scope="user",
        config_path="/Users/alice/.codex/config.toml",
        command="npx",
        args=(),
        transport="stdio",
        env={},
        enabled=True,
    )

    assert ":unnamed:" in stable_mcp_server_identifier(server)


def test_stable_mcp_server_identifier_normalizes_windows_command_paths() -> None:
    first = ManagedMcpServer(
        harness="codex",
        name="filesystem",
        source_scope="user",
        config_path="/Users/alice/.codex/config.toml",
        command="C:\\Users\\alice\\AppData\\Roaming\\npm\\npx.cmd",
        args=("-y", "@modelcontextprotocol/server-filesystem"),
        transport="stdio",
        env={},
        enabled=True,
    )
    second = ManagedMcpServer(
        harness="codex",
        name="filesystem",
        source_scope="user",
        config_path="/Users/bob/.codex/config.toml",
        command="npx.cmd",
        args=("-y", "@modelcontextprotocol/server-filesystem"),
        transport="stdio",
        env={},
        enabled=True,
    )

    identifier = stable_mcp_server_identifier(first)

    assert identifier == stable_mcp_server_identifier(second)
    assert "alice" not in identifier


def test_stable_mcp_server_identifier_preserves_slash_flags() -> None:
    first = ManagedMcpServer(
        harness="codex",
        name="filesystem",
        source_scope="user",
        config_path="/Users/alice/.codex/config.toml",
        command="npx",
        args=("/safe", "@modelcontextprotocol/server-filesystem"),
        transport="stdio",
        env={},
        enabled=True,
    )
    second = ManagedMcpServer(
        harness="codex",
        name="filesystem",
        source_scope="user",
        config_path="/Users/alice/.codex/config.toml",
        command="npx",
        args=("/readonly", "@modelcontextprotocol/server-filesystem"),
        transport="stdio",
        env={},
        enabled=True,
    )

    assert stable_mcp_server_identifier(first) != stable_mcp_server_identifier(second)


def test_stable_mcp_server_identifier_redacts_path_assignments_with_root_dirs() -> None:
    first = ManagedMcpServer(
        harness="codex",
        name="filesystem",
        source_scope="user",
        config_path="/Users/alice/.codex/config.toml",
        command="npx",
        args=("--root=/workspace", "@modelcontextprotocol/server-filesystem"),
        transport="stdio",
        env={},
        enabled=True,
    )
    second = ManagedMcpServer(
        harness="codex",
        name="filesystem",
        source_scope="user",
        config_path="/Users/bob/.codex/config.toml",
        command="npx",
        args=("--root=/project", "@modelcontextprotocol/server-filesystem"),
        transport="stdio",
        env={},
        enabled=True,
    )

    assert stable_mcp_server_identifier(first) == stable_mcp_server_identifier(second)


def test_stable_mcp_server_identifier_redacts_one_segment_absolute_path_args() -> None:
    first = ManagedMcpServer(
        harness="codex",
        name="filesystem",
        source_scope="user",
        config_path="/Users/alice/.codex/config.toml",
        command="npx",
        args=("@modelcontextprotocol/server-filesystem", "/workspace"),
        transport="stdio",
        env={},
        enabled=True,
    )
    second = ManagedMcpServer(
        harness="codex",
        name="filesystem",
        source_scope="user",
        config_path="/Users/bob/.codex/config.toml",
        command="npx",
        args=("@modelcontextprotocol/server-filesystem", "/repo"),
        transport="stdio",
        env={},
        enabled=True,
    )

    assert stable_mcp_server_identifier(first) == stable_mcp_server_identifier(second)


def test_stable_mcp_server_identifier_redacts_arbitrary_one_segment_absolute_path_args() -> None:
    first = ManagedMcpServer(
        harness="codex",
        name="filesystem",
        source_scope="user",
        config_path="/Users/alice/.codex/config.toml",
        command="npx",
        args=("@modelcontextprotocol/server-filesystem", "/alice"),
        transport="stdio",
        env={},
        enabled=True,
    )
    second = ManagedMcpServer(
        harness="codex",
        name="filesystem",
        source_scope="user",
        config_path="/Users/bob/.codex/config.toml",
        command="npx",
        args=("@modelcontextprotocol/server-filesystem", "/DevDrive"),
        transport="stdio",
        env={},
        enabled=True,
    )

    assert stable_mcp_server_identifier(first) == stable_mcp_server_identifier(second)


def test_stable_mcp_server_identifier_uses_server_identity_hash_when_present() -> None:
    identity = build_mcp_server_identity(
        config_path="/Users/alice/.codex/config.toml",
        command="npx",
        args=("-y", "@modelcontextprotocol/server-filesystem", "/workspace"),
        transport="stdio",
        env={"TOKEN": "redacted"},
    )
    server = ManagedMcpServer(
        harness="codex",
        name="filesystem",
        source_scope="user",
        config_path="/Users/alice/.codex/config.toml",
        command="npx",
        args=("-y", "@modelcontextprotocol/server-filesystem", "/workspace"),
        transport="stdio",
        env={"TOKEN": "redacted"},
        enabled=True,
        identity=identity,
    )

    assert stable_mcp_server_identifier(server).endswith(identity.identity_hash[:20])


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


def test_tool_call_risk_categories_tolerate_non_json_arguments() -> None:
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="filesystem",
        tool_name="read_secret",
        source_scope="user",
        config_path="/Users/alice/.codex/config.toml",
        transport="stdio",
    )

    categories = tool_call_risk_categories(artifact, {"paths": {".env"}})

    assert categories == ("secret_access",)


def test_tool_call_risk_categories_avoid_broad_substring_matches() -> None:
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="metadata",
        tool_name="prefetchIndex",
        source_scope="user",
        config_path="/Users/alice/.codex/config.toml",
        transport="stdio",
    )

    categories = tool_call_risk_categories(
        artifact,
        {"filename": "myapp.env", "mode": "prefetch"},
    )

    assert categories == ()


def test_tool_call_risk_categories_match_snake_case_secret_tokens() -> None:
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="environment",
        tool_name="readConfig",
        source_scope="user",
        config_path="/Users/alice/.codex/config.toml",
        transport="stdio",
    )

    categories = tool_call_risk_categories(
        artifact,
        {"keys": ["OPENAI_API_TOKEN", "aws_secret_key"]},
    )

    assert categories == ("secret_access",)


def test_tool_call_risk_categories_match_snake_case_network_tokens() -> None:
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="remote",
        tool_name="run_curl",
        source_scope="user",
        config_path="/Users/alice/.codex/config.toml",
        transport="stdio",
    )

    categories = tool_call_risk_categories(artifact, {"mode": "fetch_remote"})

    assert categories == ("outbound_network",)


def test_tool_call_risk_categories_match_snake_case_privileged_tokens() -> None:
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="filesystem",
        tool_name="sudo_exec",
        source_scope="user",
        config_path="/Users/alice/.codex/config.toml",
        transport="stdio",
    )

    categories = tool_call_risk_categories(artifact, {"operation": "chmod_file"})

    assert categories == ("command_execution", "privileged_system_mutation")


def test_tool_call_risk_categories_match_camel_case_tokens() -> None:
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="filesystem",
        tool_name="runCurl",
        source_scope="user",
        config_path="/Users/alice/.codex/config.toml",
        transport="stdio",
    )

    categories = tool_call_risk_categories(artifact, {"operation": "readSecret", "mode": "chmodFile"})

    assert categories == (
        "outbound_network",
        "privileged_system_mutation",
        "secret_access",
    )
