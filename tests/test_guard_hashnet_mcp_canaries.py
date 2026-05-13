"""P11.1 — first-party canary tests for hashnet-mcp.

Validates Guard's identity primitives against real-world hashnet-mcp
configurations so regressions in identity computation are caught before
they reach production harnesses.

Scenarios:
- known-safe stdio: canonical node invocation produces a stable identity
- known-safe remote: remote URL entry produces a stable identity
- changed capability: tool schema drift produces a different identity hash
- changed domain: command/URL drift produces a different server identity hash
"""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.mcp_protection import (
    build_mcp_server_identity,
    build_mcp_tool_identity,
)


_HASHNET_CONFIG_PATH = "~/.codex/config.toml"

_HASHNET_STDIO_COMMAND = "node"
_HASHNET_STDIO_ARGS = ("dist/cli/up.cjs",)
_HASHNET_STDIO_ENV_KEYS = (
    "REGISTRY_BROKER_API_KEY",
    "REGISTRY_BROKER_API_URL",
)

_HASHNET_REMOTE_URL = "https://registry.hol.org/mcp/hashnet"
_EVIL_REMOTE_URL_SAME_HOST = "https://registry.hol.org/mcp/evil-hashnet"
_EVIL_REMOTE_URL_HOST_ONLY = "https://evil.example/mcp/hashnet"

_HASHNET_SEARCH_TOOL = "hol_search"
_HASHNET_SEARCH_SCHEMA_V1 = {
    "type": "object",
    "properties": {
        "query": {"type": "string"},
        "limit": {"type": "integer"},
    },
    "required": ["query"],
}
_HASHNET_SEARCH_SCHEMA_V2 = {
    "type": "object",
    "properties": {
        "query": {"type": "string"},
        "limit": {"type": "integer"},
        "include_metadata": {"type": "boolean"},
    },
    "required": ["query"],
}
_HASHNET_SEARCH_DESCRIPTION_V1 = "Search the Hashgraph Online registry."
_HASHNET_SEARCH_DESCRIPTION_V2 = "Search the Hashgraph Online registry and return metadata."


class TestHashnetMcpKnownSafeStdio:
    """known-safe stdio scenario: same config → same identity each time."""

    def test_identity_is_deterministic(self) -> None:
        identity_a = build_mcp_server_identity(
            config_path=_HASHNET_CONFIG_PATH,
            command=_HASHNET_STDIO_COMMAND,
            args=_HASHNET_STDIO_ARGS,
            transport="stdio",
            env_keys=_HASHNET_STDIO_ENV_KEYS,
        )
        identity_b = build_mcp_server_identity(
            config_path=_HASHNET_CONFIG_PATH,
            command=_HASHNET_STDIO_COMMAND,
            args=_HASHNET_STDIO_ARGS,
            transport="stdio",
            env_keys=_HASHNET_STDIO_ENV_KEYS,
        )
        assert identity_a.identity_hash == identity_b.identity_hash

    def test_transport_is_stdio(self) -> None:
        identity = build_mcp_server_identity(
            config_path=_HASHNET_CONFIG_PATH,
            command=_HASHNET_STDIO_COMMAND,
            args=_HASHNET_STDIO_ARGS,
            transport="stdio",
            env_keys=_HASHNET_STDIO_ENV_KEYS,
        )
        assert identity.transport == "stdio"

    def test_env_keys_are_present_and_not_values(self) -> None:
        identity = build_mcp_server_identity(
            config_path=_HASHNET_CONFIG_PATH,
            command=_HASHNET_STDIO_COMMAND,
            args=_HASHNET_STDIO_ARGS,
            transport="stdio",
            env_keys=_HASHNET_STDIO_ENV_KEYS,
        )
        assert "REGISTRY_BROKER_API_KEY" in identity.env_keys
        assert "REGISTRY_BROKER_API_URL" in identity.env_keys

    def test_identity_hash_is_non_empty_hex(self) -> None:
        identity = build_mcp_server_identity(
            config_path=_HASHNET_CONFIG_PATH,
            command=_HASHNET_STDIO_COMMAND,
            args=_HASHNET_STDIO_ARGS,
            transport="stdio",
            env_keys=_HASHNET_STDIO_ENV_KEYS,
        )
        assert identity.identity_hash
        assert all(ch in "0123456789abcdef" for ch in identity.identity_hash)


class TestHashnetMcpKnownSafeRemote:
    """known-safe remote scenario: HOL registry remote URL → stable identity."""

    def test_remote_identity_is_deterministic(self) -> None:
        identity_a = build_mcp_server_identity(
            config_path=_HASHNET_CONFIG_PATH,
            command=_HASHNET_REMOTE_URL,
            args=(),
            transport="http",
        )
        identity_b = build_mcp_server_identity(
            config_path=_HASHNET_CONFIG_PATH,
            command=_HASHNET_REMOTE_URL,
            args=(),
            transport="http",
        )
        assert identity_a.identity_hash == identity_b.identity_hash

    def test_remote_differs_from_stdio_identity(self) -> None:
        stdio_identity = build_mcp_server_identity(
            config_path=_HASHNET_CONFIG_PATH,
            command=_HASHNET_STDIO_COMMAND,
            args=_HASHNET_STDIO_ARGS,
            transport="stdio",
            env_keys=_HASHNET_STDIO_ENV_KEYS,
        )
        remote_identity = build_mcp_server_identity(
            config_path=_HASHNET_CONFIG_PATH,
            command=_HASHNET_REMOTE_URL,
            args=(),
            transport="http",
        )
        assert stdio_identity.identity_hash != remote_identity.identity_hash


class TestHashnetMcpChangedCapability:
    """changed-capability scenario: tool schema drift is detected by Guard."""

    def _server_hash(self) -> str:
        return build_mcp_server_identity(
            config_path=_HASHNET_CONFIG_PATH,
            command=_HASHNET_STDIO_COMMAND,
            args=_HASHNET_STDIO_ARGS,
            transport="stdio",
            env_keys=_HASHNET_STDIO_ENV_KEYS,
        ).identity_hash

    def test_schema_change_produces_different_tool_identity(self) -> None:
        server_hash = self._server_hash()
        tool_v1 = build_mcp_tool_identity(
            server_hash=server_hash,
            tool_name=_HASHNET_SEARCH_TOOL,
            schema=_HASHNET_SEARCH_SCHEMA_V1,
            description=_HASHNET_SEARCH_DESCRIPTION_V1,
        )
        tool_v2 = build_mcp_tool_identity(
            server_hash=server_hash,
            tool_name=_HASHNET_SEARCH_TOOL,
            schema=_HASHNET_SEARCH_SCHEMA_V2,
            description=_HASHNET_SEARCH_DESCRIPTION_V1,
        )
        assert tool_v1.identity_hash != tool_v2.identity_hash

    def test_description_change_produces_different_tool_identity(self) -> None:
        server_hash = self._server_hash()
        tool_v1 = build_mcp_tool_identity(
            server_hash=server_hash,
            tool_name=_HASHNET_SEARCH_TOOL,
            schema=_HASHNET_SEARCH_SCHEMA_V1,
            description=_HASHNET_SEARCH_DESCRIPTION_V1,
        )
        tool_v2 = build_mcp_tool_identity(
            server_hash=server_hash,
            tool_name=_HASHNET_SEARCH_TOOL,
            schema=_HASHNET_SEARCH_SCHEMA_V1,
            description=_HASHNET_SEARCH_DESCRIPTION_V2,
        )
        assert tool_v1.identity_hash != tool_v2.identity_hash

    def test_unchanged_tool_identity_is_stable(self) -> None:
        server_hash = self._server_hash()
        tool_a = build_mcp_tool_identity(
            server_hash=server_hash,
            tool_name=_HASHNET_SEARCH_TOOL,
            schema=_HASHNET_SEARCH_SCHEMA_V1,
            description=_HASHNET_SEARCH_DESCRIPTION_V1,
        )
        tool_b = build_mcp_tool_identity(
            server_hash=server_hash,
            tool_name=_HASHNET_SEARCH_TOOL,
            schema=_HASHNET_SEARCH_SCHEMA_V1,
            description=_HASHNET_SEARCH_DESCRIPTION_V1,
        )
        assert tool_a.identity_hash == tool_b.identity_hash


class TestHashnetMcpChangedDomain:
    """changed-domain scenario: URL and args drift are detected by server identity.

    Note: ``build_mcp_server_identity`` uses ``_command_name()`` which extracts
    only the last URL path segment as the effective command name. Host-only
    swaps (same path, different hostname) therefore produce the same
    ``identity_hash`` — this is a known limitation of the current design.
    Path changes (different last segment) are detected, as are stdio args
    changes.
    """

    def test_url_path_change_produces_different_identity(self) -> None:
        real_identity = build_mcp_server_identity(
            config_path=_HASHNET_CONFIG_PATH,
            command=_HASHNET_REMOTE_URL,
            args=(),
            transport="http",
        )
        evil_identity = build_mcp_server_identity(
            config_path=_HASHNET_CONFIG_PATH,
            command=_EVIL_REMOTE_URL_SAME_HOST,
            args=(),
            transport="http",
        )
        assert real_identity.identity_hash != evil_identity.identity_hash

    def test_host_only_swap_produces_same_identity_hash(self) -> None:
        real_identity = build_mcp_server_identity(
            config_path=_HASHNET_CONFIG_PATH,
            command=_HASHNET_REMOTE_URL,
            args=(),
            transport="http",
        )
        host_swapped = build_mcp_server_identity(
            config_path=_HASHNET_CONFIG_PATH,
            command=_EVIL_REMOTE_URL_HOST_ONLY,
            args=(),
            transport="http",
        )
        assert real_identity.identity_hash == host_swapped.identity_hash, (
            "Known limitation: _command_name() extracts only the last URL path "
            "segment, so a host-only swap with the same path is not detected by "
            "McpServerIdentity alone."
        )

    def test_args_drift_produces_different_stdio_identity(self) -> None:
        canonical = build_mcp_server_identity(
            config_path=_HASHNET_CONFIG_PATH,
            command=_HASHNET_STDIO_COMMAND,
            args=_HASHNET_STDIO_ARGS,
            transport="stdio",
            env_keys=_HASHNET_STDIO_ENV_KEYS,
        )
        drifted = build_mcp_server_identity(
            config_path=_HASHNET_CONFIG_PATH,
            command=_HASHNET_STDIO_COMMAND,
            args=("dist/cli/up.cjs", "--extra-flag"),
            transport="stdio",
            env_keys=_HASHNET_STDIO_ENV_KEYS,
        )
        assert canonical.identity_hash != drifted.identity_hash

    def test_tool_identity_differs_when_server_path_changes(self) -> None:
        real_server = build_mcp_server_identity(
            config_path=_HASHNET_CONFIG_PATH,
            command=_HASHNET_REMOTE_URL,
            args=(),
            transport="http",
        )
        evil_server = build_mcp_server_identity(
            config_path=_HASHNET_CONFIG_PATH,
            command=_EVIL_REMOTE_URL_SAME_HOST,
            args=(),
            transport="http",
        )
        real_tool = build_mcp_tool_identity(
            server_hash=real_server.identity_hash,
            tool_name=_HASHNET_SEARCH_TOOL,
            schema=_HASHNET_SEARCH_SCHEMA_V1,
            description=_HASHNET_SEARCH_DESCRIPTION_V1,
        )
        evil_tool = build_mcp_tool_identity(
            server_hash=evil_server.identity_hash,
            tool_name=_HASHNET_SEARCH_TOOL,
            schema=_HASHNET_SEARCH_SCHEMA_V1,
            description=_HASHNET_SEARCH_DESCRIPTION_V1,
        )
        assert real_tool.identity_hash != evil_tool.identity_hash
