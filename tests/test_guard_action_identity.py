"""Tests for action identity normalization (T700-T718)."""

from __future__ import annotations

import pytest

action_identity_mod = pytest.importorskip(
    "codex_plugin_scanner.guard.runtime.action_identity",
    reason="action_identity module not yet implemented",
)

normalize_command_identity = action_identity_mod.normalize_command_identity
normalize_prompt_identity = action_identity_mod.normalize_prompt_identity
normalize_mcp_identity = action_identity_mod.normalize_mcp_identity


class TestCommandIdentityNormalization:
    """T700-T705: Command identity normalizer."""

    def test_same_command_with_different_request_ids_maps_to_same_identity(self) -> None:
        """T703: Different approval request IDs in command must not change identity."""
        cmd_a = "hol-guard approvals approve req-abc-001 --scope artifact"
        cmd_b = "hol-guard approvals approve req-xyz-999 --scope artifact"
        assert normalize_command_identity(cmd_a) == normalize_command_identity(cmd_b)

    def test_ansi_codes_removed_before_normalization(self) -> None:
        """T701: ANSI escape codes must be stripped before normalization."""
        cmd_with_ansi = "\x1b[32mnode\x1b[0m server.js"
        cmd_clean = "node server.js"
        assert normalize_command_identity(cmd_with_ansi) == normalize_command_identity(cmd_clean)

    def test_daemon_port_numbers_removed(self) -> None:
        """T701: Ephemeral port numbers (like approval center ports) must not affect identity."""
        cmd_a = "hol-guard approvals --port 6174"
        cmd_b = "hol-guard approvals --port 7890"
        assert normalize_command_identity(cmd_a) == normalize_command_identity(cmd_b)

    def test_timestamps_removed(self) -> None:
        """T701: Timestamps in commands must not affect identity."""
        cmd_a = "backup.sh --at 2026-01-01T00:00:00Z"
        cmd_b = "backup.sh --at 2026-06-15T12:30:00Z"
        assert normalize_command_identity(cmd_a) == normalize_command_identity(cmd_b)

    def test_different_network_hosts_produce_different_identity(self) -> None:
        """T704: Commands targeting different network hosts must have different identity."""
        cmd_internal = "curl http://internal.corp/api/data"
        cmd_external = "curl http://evil.example.com/api/data"
        assert normalize_command_identity(cmd_internal) != normalize_command_identity(cmd_external)

    def test_different_secret_paths_produce_different_identity(self) -> None:
        """T705: Commands targeting different secret paths must have different identity."""
        cmd_npmrc = "cat /Users/me/.npmrc"
        cmd_env = "cat /Users/me/.env"
        assert normalize_command_identity(cmd_npmrc) != normalize_command_identity(cmd_env)

    def test_meaningful_command_preserved(self) -> None:
        """T702: Core command and meaningful args must be preserved in normalized identity."""
        id_a = normalize_command_identity("node server.js --port 3000")
        id_b = normalize_command_identity("python server.py --port 3000")
        assert id_a != id_b, "Different commands must produce different identities"

    def test_whitespace_normalized(self) -> None:
        """T701: Extra whitespace must not affect identity."""
        cmd_a = "node   server.js  --port  3000"
        cmd_b = "node server.js --port 3000"
        assert normalize_command_identity(cmd_a) == normalize_command_identity(cmd_b)


class TestPromptIdentityNormalization:
    """T706-T708: Prompt identity normalizer."""

    def test_repeated_read_npmrc_prompt_maps_to_same_identity(self) -> None:
        """T707: Same prompt repeated with minor formatting differences maps to same identity."""
        prompt_a = "Read the **`.npmrc`** file and tell me the registry config."
        prompt_b = "Read the `.npmrc` file and tell me the registry config."
        assert normalize_prompt_identity(prompt_a) == normalize_prompt_identity(prompt_b)

    def test_npmrc_vs_env_prompt_maps_to_different_identity(self) -> None:
        """T708: Prompts targeting different secrets must have different identity."""
        prompt_npmrc = "Read the .npmrc file."
        prompt_env = "Read the .env file."
        assert normalize_prompt_identity(prompt_npmrc) != normalize_prompt_identity(prompt_env)

    def test_model_formatting_tokens_removed(self) -> None:
        """T706: Transient model formatting (bold, markdown etc.) must not affect identity."""
        prompt_formatted = "**Read** the `.npmrc` file and extract the _auth token_."
        prompt_plain = "Read the .npmrc file and extract the auth token."
        assert normalize_prompt_identity(prompt_formatted) == normalize_prompt_identity(prompt_plain)

    def test_underscores_in_identifiers_preserved(self) -> None:
        """T706b: Underscores inside identifiers must not be stripped."""
        prompt_key = "Send OPENAI_API_KEY to the server."
        prompt_file = "Read my_secret_file from disk."
        normalized_key = normalize_prompt_identity(prompt_key)
        normalized_file = normalize_prompt_identity(prompt_file)
        assert "openai_api_key" in normalized_key, "Internal underscores in env var names must be preserved"
        assert "my_secret_file" in normalized_file, "Internal underscores in file names must be preserved"


class TestMcpIdentityNormalization:
    """T709-T711: MCP identity normalizer."""

    def test_same_tool_and_target_maps_to_same_identity(self) -> None:
        """T710: Same MCP server, tool, and target must produce same identity."""
        call_a = {
            "server_id": "github-mcp",
            "tool_name": "read_file",
            "arguments": {"path": "/Users/me/.npmrc"},
        }
        call_b = {
            "server_id": "github-mcp",
            "tool_name": "read_file",
            "arguments": {"path": "/Users/me/.npmrc"},
        }
        assert normalize_mcp_identity(call_a) == normalize_mcp_identity(call_b)

    def test_different_mcp_target_produces_different_identity(self) -> None:
        """T710: Same MCP tool with different target must produce different identity."""
        call_npmrc = {
            "server_id": "github-mcp",
            "tool_name": "read_file",
            "arguments": {"path": "/Users/me/.npmrc"},
        }
        call_env = {
            "server_id": "github-mcp",
            "tool_name": "read_file",
            "arguments": {"path": "/Users/me/.env"},
        }
        assert normalize_mcp_identity(call_npmrc) != normalize_mcp_identity(call_env)

    def test_mcp_schema_change_produces_different_identity(self) -> None:
        """T711: Change in MCP tool schema hash must invalidate previous approval identity."""
        call_v1 = {
            "server_id": "custom-mcp",
            "tool_name": "execute",
            "arguments": {"cmd": "ls"},
            "schema_hash": "v1-abc123",
        }
        call_v2 = {
            "server_id": "custom-mcp",
            "tool_name": "execute",
            "arguments": {"cmd": "ls"},
            "schema_hash": "v2-def456",
        }
        assert normalize_mcp_identity(call_v1) != normalize_mcp_identity(call_v2)

    def test_mcp_identity_is_deterministic(self) -> None:
        """T709: normalize_mcp_identity must return same hash on repeated calls."""
        call = {
            "server_id": "test-mcp",
            "tool_name": "read_file",
            "arguments": {"path": "/tmp/test"},
            "schema_hash": "hash-001",
        }
        assert normalize_mcp_identity(call) == normalize_mcp_identity(call)


class TestBrowserMcpIdentityNormalization:
    """HGBM049-HGBM051: Browser MCP identity normalizer."""

    def test_drops_volatile_fields(self) -> None:
        """HGBM050: Two calls with different timeout/page ID hash equal."""
        from codex_plugin_scanner.guard.runtime.action_identity import (
            normalize_browser_mcp_identity,
        )

        call_a = {
            "server_id": "chrome-devtools-hash",
            "tool_name": "navigate_page",
            "intent": "browser.navigation",
            "operation": "navigate_page",
            "target_origin": "https://hol.org",
            "target_path_prefix": "/guard/integrations/slack",
            "profile_mode": "unknown",
            "schema_hash": "abc123",
            "sensitive_surface_flags": (),
        }
        call_b = dict(call_a)
        call_b["timeout"] = 30000
        call_b["pageId"] = "tab2"
        assert normalize_browser_mcp_identity(call_a) == normalize_browser_mcp_identity(call_b)

    def test_different_origin_hashes_differently(self) -> None:
        """HGBM051: Different origin produces different identity."""
        from codex_plugin_scanner.guard.runtime.action_identity import (
            normalize_browser_mcp_identity,
        )

        call_a = {
            "server_id": "chrome-devtools",
            "tool_name": "navigate_page",
            "intent": "browser.navigation",
            "operation": "navigate_page",
            "target_origin": "https://hol.org",
            "target_path_prefix": "/guard",
            "profile_mode": "unknown",
            "schema_hash": "abc",
            "sensitive_surface_flags": (),
        }
        call_b = dict(call_a)
        call_b["target_origin"] = "https://example.com"
        assert normalize_browser_mcp_identity(call_a) != normalize_browser_mcp_identity(call_b)

    def test_different_intent_hashes_differently(self) -> None:
        """HGBM051: Different intent on same URL produces different identity."""
        from codex_plugin_scanner.guard.runtime.action_identity import (
            normalize_browser_mcp_identity,
        )

        base = {
            "server_id": "chrome-devtools",
            "tool_name": "navigate_page",
            "intent": "browser.navigation",
            "operation": "navigate_page",
            "target_origin": "https://hol.org",
            "target_path_prefix": "/guard",
            "profile_mode": "unknown",
            "schema_hash": "abc",
            "sensitive_surface_flags": (),
        }
        interact = dict(base)
        interact["intent"] = "browser.interact"
        interact["operation"] = "click"
        assert normalize_browser_mcp_identity(base) != normalize_browser_mcp_identity(interact)

    def test_different_path_prefix_hashes_differently(self) -> None:
        """HGBM059: Path prefix /guard/* does not hash same as /account/*."""
        from codex_plugin_scanner.guard.runtime.action_identity import (
            normalize_browser_mcp_identity,
        )

        base = {
            "server_id": "chrome-devtools",
            "tool_name": "navigate_page",
            "intent": "browser.navigation",
            "operation": "navigate_page",
            "target_origin": "https://hol.org",
            "target_path_prefix": "/guard",
            "profile_mode": "unknown",
            "schema_hash": "abc",
            "sensitive_surface_flags": (),
        }
        account = dict(base)
        account["target_path_prefix"] = "/account"
        assert normalize_browser_mcp_identity(base) != normalize_browser_mcp_identity(account)

    def test_different_sensitive_flags_hashes_differently(self) -> None:
        """HGBM051: Different sensitive surface flags produce different identity."""
        from codex_plugin_scanner.guard.runtime.action_identity import (
            normalize_browser_mcp_identity,
        )

        base = {
            "server_id": "chrome-devtools",
            "tool_name": "evaluate_script",
            "intent": "browser.privileged",
            "operation": "evaluate_script",
            "target_origin": "https://hol.org",
            "target_path_prefix": "/guard",
            "profile_mode": "unknown",
            "schema_hash": "abc",
            "sensitive_surface_flags": ("script_eval",),
        }
        cookies = dict(base)
        cookies["sensitive_surface_flags"] = ("cookies",)
        assert normalize_browser_mcp_identity(base) != normalize_browser_mcp_identity(cookies)

    def test_different_server_hashes_differently(self) -> None:
        """HGBM058: Chrome DevTools approval does not cover Playwright MCP."""
        from codex_plugin_scanner.guard.runtime.action_identity import (
            normalize_browser_mcp_identity,
        )

        base = {
            "server_id": "chrome-devtools-hash",
            "tool_name": "navigate_page",
            "intent": "browser.navigation",
            "operation": "navigate_page",
            "target_origin": "https://hol.org",
            "target_path_prefix": "/guard",
            "profile_mode": "unknown",
            "schema_hash": "abc",
            "sensitive_surface_flags": (),
        }
        playwright = dict(base)
        playwright["server_id"] = "playwright-mcp-hash"
        playwright["tool_name"] = "browser_navigate"
        playwright["operation"] = "browser_navigate"
        assert normalize_browser_mcp_identity(base) != normalize_browser_mcp_identity(playwright)

    def test_localhost_not_global(self) -> None:
        """HGBM060: Localhost workspace approval does not become global internet approval."""
        from codex_plugin_scanner.guard.runtime.action_identity import (
            normalize_browser_mcp_identity,
        )

        localhost = {
            "server_id": "chrome-devtools",
            "tool_name": "navigate_page",
            "intent": "browser.navigation",
            "operation": "navigate_page",
            "target_origin": "http://127.0.0.1:3000",
            "target_path_prefix": "/guard",
            "profile_mode": "unknown",
            "schema_hash": "abc",
            "sensitive_surface_flags": (),
        }
        external = dict(localhost)
        external["target_origin"] = "https://example.com"
        assert normalize_browser_mcp_identity(localhost) != normalize_browser_mcp_identity(external)
