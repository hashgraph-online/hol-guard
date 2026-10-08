"""Characterization tests for browser MCP intent extraction (HGBM005-HGBM032)."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.browser_mcp_intent import normalize_browser_mcp_intent

pytestmark = pytest.mark.usefixtures("native_context_digest")


def _normalized_url(url: str):
    artifact, arguments = _browser_artifact(arguments={"url": url})
    return normalize_browser_mcp_intent(artifact, arguments)


from codex_plugin_scanner.guard.mcp_tool_calls import (
    build_tool_call_artifact,
    tool_call_risk_categories,
    tool_call_risk_signals,
    tool_call_risk_summary,
)
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity


def _browser_artifact(
    *,
    server_name: str = "chrome-devtools",
    tool_name: str = "navigate_page",
    arguments: object | None = None,
    server_identity=None,
) -> tuple[object, object]:
    """Build a browser MCP artifact + arguments pair for testing."""
    if server_identity is None:
        server_identity = build_mcp_server_identity(
            config_path=".mcp.json",
            command="npx",
            args=("-y", "@modelcontextprotocol/server-chrome-devtools"),
            transport="stdio",
        )
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name=server_name,
        tool_name=tool_name,
        source_scope="project",
        config_path=".mcp.json",
        transport="stdio",
        server_identity=server_identity,
    )
    return artifact, arguments


# ─── HGBM005: Characterize current behavior for navigate_page with https URL ──


class TestBrowserMcpCurrentBehavior:
    """HGBM005-HGBM007: Current classifier behavior before browser intent changes."""

    def test_navigate_page_with_https_url_records_current_categories(self) -> None:
        """HGBM005: After browser intent integration, navigate_page to hol.org
        no longer triggers outbound_network — it gets browser_navigation instead.
        """
        artifact, arguments = _browser_artifact(
            arguments={"type": "url", "url": "https://hol.org/guard/integrations/slack", "timeout": 30000},
        )
        categories = tool_call_risk_categories(artifact, arguments)
        # Browser navigation suppresses outbound_network
        assert "outbound_network" not in categories
        assert "browser_navigation" in categories
        assert "browser_external_domain" in categories

    def test_non_browser_mcp_with_https_still_triggers_outbound_network(self) -> None:
        """HGBM006: Non-browser MCP with URL still returns outbound_network."""
        artifact, arguments = _browser_artifact(
            server_name="slack-mcp",
            tool_name="post_message",
            arguments={"webhook": "https://example.com/webhook"},
        )
        categories = tool_call_risk_categories(artifact, arguments)
        assert "outbound_network" in categories

    def test_navigate_page_with_env_path_triggers_secret_access(self) -> None:
        """HGBM007: navigate_page with .env in path triggers secret_access."""
        artifact, arguments = _browser_artifact(
            arguments={"type": "url", "url": "file:///home/user/.env"},
        )
        categories = tool_call_risk_categories(artifact, arguments)
        assert "secret_access" in categories

    def test_navigate_page_with_npmrc_triggers_secret_access(self) -> None:
        """HGBM007: navigate_page with .npmrc path triggers secret_access."""
        artifact, arguments = _browser_artifact(
            arguments={"type": "url", "url": "file:///project/.npmrc"},
        )
        categories = tool_call_risk_categories(artifact, arguments)
        assert "secret_access" in categories

    def test_navigate_page_to_localhost_does_not_trigger_outbound_network(self) -> None:
        """After browser intent integration, localhost navigation gets browser_navigation
        and does not trigger outbound_network."""
        artifact, arguments = _browser_artifact(
            arguments={"type": "url", "url": "http://127.0.0.1:3000/guard"},
        )
        categories = tool_call_risk_categories(artifact, arguments)
        assert "outbound_network" not in categories
        assert "browser_navigation" in categories

    def test_navigate_page_risk_signals_mention_outbound_network(self) -> None:
        """HGBM045 prep: current risk signals for browser navigation."""
        artifact, arguments = _browser_artifact(
            arguments={"type": "url", "url": "https://hol.org/guard/integrations/slack"},
        )
        signals = tool_call_risk_signals(artifact, arguments)
        assert len(signals) > 0

    def test_navigate_page_risk_summary_is_non_empty(self) -> None:
        """HGBM046 prep: current risk summary for browser navigation."""
        artifact, arguments = _browser_artifact(
            arguments={"type": "url", "url": "https://hol.org/guard/integrations/slack"},
        )
        summary = tool_call_risk_summary(artifact, arguments)
        assert isinstance(summary, str)
        assert len(summary) > 0


# ─── HGBM012+: Browser intent module tests (filled in as module is built) ──────


class TestBrowserIntentLiterals:
    """HGBM012: BrowserIntent literal type exists."""

    def test_browser_intent_literals_importable(self) -> None:
        """HGBM012: BrowserIntent type can be imported."""
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import BrowserIntent

        assert "browser.navigation" in BrowserIntent.__args__  # type: ignore[attr-defined]
        assert "browser.inspect" in BrowserIntent.__args__  # type: ignore[attr-defined]
        assert "browser.interact" in BrowserIntent.__args__  # type: ignore[attr-defined]
        assert "browser.transfer" in BrowserIntent.__args__  # type: ignore[attr-defined]
        assert "browser.privileged" in BrowserIntent.__args__  # type: ignore[attr-defined]


class TestNormalizeBrowserMcpIntent:
    """HGBM014: normalize_browser_mcp_intent function."""

    def test_returns_none_for_unrelated_mcp_tool(self) -> None:
        """HGBM014: Returns None for non-browser MCP tool."""
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            normalize_browser_mcp_intent,
        )
        from codex_plugin_scanner.guard.runtime.mcp_protection import (
            build_mcp_server_identity,
        )

        server_identity = build_mcp_server_identity(
            config_path=".mcp.json",
            command="npx",
            args=("-y", "@slack/mcp-server"),
            transport="stdio",
        )
        artifact, arguments = _browser_artifact(
            server_name="slack-mcp",
            tool_name="post_message",
            arguments={"channel": "#general", "text": "hello"},
            server_identity=server_identity,
        )
        result = normalize_browser_mcp_intent(artifact, arguments)
        assert result is None

    def test_returns_intent_for_browser_navigation(self) -> None:
        """HGBM014: Returns intent for browser navigation."""
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            normalize_browser_mcp_intent,
        )

        artifact, arguments = _browser_artifact(
            arguments={"type": "url", "url": "https://hol.org/guard/integrations/slack"},
        )
        result = normalize_browser_mcp_intent(artifact, arguments)
        assert result is not None
        assert result.intent == "browser.navigation"
        assert result.operation == "navigate_page"


class TestIsBrowserMcpServer:
    """HGBM015: is_browser_mcp_server function."""

    def test_chrome_devtools_is_browser(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            is_browser_mcp_server,
        )

        artifact, _ = _browser_artifact(server_name="chrome-devtools")
        assert is_browser_mcp_server(artifact) is True

    def test_playwright_is_browser(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            is_browser_mcp_server,
        )

        artifact, _ = _browser_artifact(
            server_name="@playwright/mcp",
            tool_name="browser_navigate",
        )
        assert is_browser_mcp_server(artifact) is True

    def test_browser_tools_is_browser(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            is_browser_mcp_server,
        )

        artifact, _ = _browser_artifact(server_name="browser-tools")
        assert is_browser_mcp_server(artifact) is True

    def test_slack_mcp_is_not_browser(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            is_browser_mcp_server,
        )
        from codex_plugin_scanner.guard.runtime.mcp_protection import (
            build_mcp_server_identity,
        )

        # Use a non-browser server identity (slack MCP package)
        server_identity = build_mcp_server_identity(
            config_path=".mcp.json",
            command="npx",
            args=("-y", "@slack/mcp-server"),
            transport="stdio",
        )
        artifact, _ = _browser_artifact(
            server_name="slack-mcp",
            tool_name="post_message",
            server_identity=server_identity,
        )
        assert is_browser_mcp_server(artifact) is False


class TestBrowserArgumentShapes:
    @pytest.mark.parametrize(
        "arguments",
        [
            {"url": "https://example.com"},
            '{"url": "https://example.com"}',
            {"href": "https://example.com"},
            {"target": "https://example.com"},
            {"uri": "https://example.com"},
            {"pageUrl": "https://example.com"},
            {"arguments": {"url": "https://example.com"}},
        ],
    )
    def test_argument_target(self, arguments) -> None:
        artifact, _ = _browser_artifact()
        assert normalize_browser_mcp_intent(artifact, arguments).target_url == "https://example.com"

    @pytest.mark.parametrize("arguments", [[1, 2, 3], "{not valid json", '"just a string"', "42", {"text": "hello"}])
    def test_without_target(self, arguments) -> None:
        artifact, _ = _browser_artifact()
        assert normalize_browser_mcp_intent(artifact, arguments).target_url is None


class TestBrowserTargets:
    @pytest.mark.parametrize(
        ("url", "origin", "domain", "path"),
        [
            ("http://127.0.0.1:3000/a", "http://127.0.0.1:3000", "127.0.0.1", "/a"),
            ("http://[::1]:3000/a", "http://[::1]:3000", "::1", "/a"),
            ("https://hol.org/a", "https://hol.org", "hol.org", "/a"),
            ("https://app.hol.org/a", "https://app.hol.org", "app.hol.org", "/a"),
            ("http://localhost:3000/a", "http://localhost:3000", "localhost", "/a"),
            (
                "https://hol.org/guard/integrations/slack?token=x#y",
                "https://hol.org",
                "hol.org",
                "/guard/integrations/slack",
            ),
            ("https://hol.org/", "https://hol.org", "hol.org", "/"),
            ("https://hol.org", "https://hol.org", "hol.org", ""),
        ],
    )
    def test_target_identity(self, url, origin, domain, path) -> None:
        intent = _normalized_url(url)
        assert (intent.target_origin, intent.target_domain, intent.target_path_prefix) == (origin, domain, path)

    @pytest.mark.parametrize(("key", "secret"), [("token", "secret123"), ("session", "abc456")])
    def test_redacts_sensitive_query(self, key, secret) -> None:
        result = _normalized_url(f"https://hol.org/callback?{key}={secret}").target_url
        assert secret not in result
        assert "%5Bredacted%5D" in result

    def test_preserves_non_sensitive_values(self) -> None:
        assert _normalized_url("https://hol.org/guard?id=123").target_url == "https://hol.org/guard?id=123"


class TestOperationMaps:
    """HGBM023-HGBM029: Operation maps for browser MCP tools."""

    def test_chrome_devtools_navigation_operations(self) -> None:
        """HGBM023: Chrome DevTools navigation operation map."""
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            classify_browser_operation,
        )

        for op in ("navigate_page", "new_page", "select_page", "list_pages", "close_page", "wait_for"):
            intent = classify_browser_operation(op, "chrome-devtools")
            assert intent == "browser.navigation", f"{op} should be navigation, got {intent}"

    def test_chrome_devtools_inspect_operations(self) -> None:
        """HGBM024: Chrome DevTools inspect/read operation map."""
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            classify_browser_operation,
        )

        for op in ("take_screenshot", "take_snapshot", "read_console", "read_network", "performance_trace"):
            intent = classify_browser_operation(op, "chrome-devtools")
            assert intent == "browser.inspect", f"{op} should be inspect, got {intent}"

    def test_chrome_devtools_interact_operations(self) -> None:
        """HGBM025: Chrome DevTools interact operation map."""
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            classify_browser_operation,
        )

        for op in ("click", "hover", "press_key", "type_text", "fill_form", "handle_dialog"):
            intent = classify_browser_operation(op, "chrome-devtools")
            assert intent == "browser.interact", f"{op} should be interact, got {intent}"

    def test_chrome_devtools_privileged_operations(self) -> None:
        """HGBM026: Chrome DevTools privileged operation map."""
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            classify_browser_operation,
        )

        for op in ("evaluate_script", "raw_cdp", "read_cookies", "read_storage", "network_intercept"):
            intent = classify_browser_operation(op, "chrome-devtools")
            assert intent == "browser.privileged", f"{op} should be privileged, got {intent}"

    def test_playwright_navigation_and_inspect(self) -> None:
        """HGBM027: Playwright navigation and inspect maps."""
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            classify_browser_operation,
        )

        assert classify_browser_operation("browser_navigate", "@playwright/mcp") == "browser.navigation"
        assert classify_browser_operation("browser_snapshot", "@playwright/mcp") == "browser.inspect"
        assert classify_browser_operation("browser_screenshot", "@playwright/mcp") == "browser.inspect"

    def test_playwright_interact_transfer_privileged(self) -> None:
        """HGBM028: Playwright interact, transfer, privileged maps."""
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            classify_browser_operation,
        )

        assert classify_browser_operation("browser_click", "@playwright/mcp") == "browser.interact"
        assert classify_browser_operation("browser_type", "@playwright/mcp") == "browser.interact"
        assert classify_browser_operation("browser_file_upload", "@playwright/mcp") == "browser.transfer"
        assert classify_browser_operation("browser_pdf_save", "@playwright/mcp") == "browser.transfer"
        assert classify_browser_operation("browser_evaluate", "@playwright/mcp") == "browser.privileged"

    def test_generic_fallback_requires_browser_server(self) -> None:
        """HGBM029: Non-browser server 'navigate' does not classify as browser."""
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            classify_browser_operation,
        )

        # For a non-browser server, unknown operations should not return a browser intent
        assert classify_browser_operation("navigate", "slack-mcp") is None


class TestVolatileFields:
    """HGBM030: Volatile field detection."""

    def test_detects_volatile_fields_in_arguments(self) -> None:
        artifact, arguments = _browser_artifact(
            arguments={"url": "https://example.com", "timeout": 30000, "pageId": "tab1"}
        )
        assert normalize_browser_mcp_intent(artifact, arguments).volatile_fields_dropped == ("timeout", "pageId")


class TestSensitiveSurfaces:
    @pytest.mark.parametrize(
        ("operation", "arguments", "schema", "flag"),
        [
            ("read_cookies", {}, {}, "cookies"),
            ("read_storage", {}, {}, "storage"),
            ("evaluate_script", {}, {}, "script_eval"),
            ("raw_cdp", {}, {}, "cdp"),
            ("upload_file", {"filePath": "/tmp/file.txt"}, {}, "upload"),
            ("save_file", {"downloadPath": "/tmp/file.txt"}, {}, "download"),
            ("fill_form", {}, {"properties": {"password": {"type": "string"}}}, "password_field"),
            ("network_intercept", {}, {}, "network_intercept"),
        ],
    )
    def test_sensitive_surface(self, operation, arguments, schema, flag) -> None:
        artifact, _ = _browser_artifact(tool_name=operation)
        artifact.metadata["tool_schema"] = schema
        assert flag in normalize_browser_mcp_intent(artifact, arguments).sensitive_surface_flags


class TestProfileMode:
    @pytest.mark.parametrize(
        ("args", "mode"),
        [
            (["--isolated"], "isolated"),
            (["--user-data-dir=/tmp/profile"], "dedicated"),
            (["--remote-debugging-port=9222"], "remote-debugging"),
            ([], "unknown"),
        ],
    )
    def test_profile_mode(self, args, mode) -> None:
        artifact, arguments = _browser_artifact(arguments={})
        artifact.metadata["args"] = args
        assert normalize_browser_mcp_intent(artifact, arguments).profile_mode == mode


class TestFullIntentNormalization:
    """Integration: full normalize_browser_mcp_intent across scenarios."""

    def test_navigate_to_localhost(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            normalize_browser_mcp_intent,
        )

        artifact, arguments = _browser_artifact(
            arguments={"type": "url", "url": "http://127.0.0.1:3000/guard", "timeout": 30000},
        )
        result = normalize_browser_mcp_intent(artifact, arguments)
        assert result is not None
        assert result.intent == "browser.navigation"
        assert result.target_origin == "http://127.0.0.1:3000"
        assert result.target_domain == "127.0.0.1"
        assert result.target_path_prefix == "/guard"
        assert result.profile_mode == "unknown"
        assert "timeout" in result.volatile_fields_dropped

    def test_screenshot_classification(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            normalize_browser_mcp_intent,
        )

        artifact, arguments = _browser_artifact(
            tool_name="take_screenshot",
            arguments={"pageId": "tab1"},
        )
        result = normalize_browser_mcp_intent(artifact, arguments)
        assert result is not None
        assert result.intent == "browser.inspect"
        assert "pageId" in result.volatile_fields_dropped

    def test_evaluate_script_is_privileged(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            normalize_browser_mcp_intent,
        )

        artifact, arguments = _browser_artifact(
            tool_name="evaluate_script",
            arguments={"expression": "document.title"},
        )
        result = normalize_browser_mcp_intent(artifact, arguments)
        assert result is not None
        assert result.intent == "browser.privileged"
        assert "script_eval" in result.sensitive_surface_flags

    def test_fill_form_is_interact(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            normalize_browser_mcp_intent,
        )

        artifact, arguments = _browser_artifact(
            tool_name="fill_form",
            arguments={"selector": "#email", "value": "test@example.com"},
        )
        result = normalize_browser_mcp_intent(artifact, arguments)
        assert result is not None
        assert result.intent == "browser.interact"

    def test_upload_file_is_transfer(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            normalize_browser_mcp_intent,
        )

        artifact, arguments = _browser_artifact(
            tool_name="upload_file",
            arguments={"filePath": "/tmp/test.txt"},
        )
        result = normalize_browser_mcp_intent(artifact, arguments)
        assert result is not None
        assert result.intent == "browser.transfer"
        assert "upload" in result.sensitive_surface_flags


# ─── HGBM033-HGBM048: Classifier integration tests ────────────────────────────


class TestBrowserRiskClassifierIntegration:
    """HGBM033-HGBM048: Browser intent integration into mcp_tool_calls classifier."""

    def test_browser_navigation_excludes_outbound_network(self) -> None:
        """HGBM035: navigate_page with https:// no longer triggers outbound_network."""
        artifact, arguments = _browser_artifact(
            arguments={"type": "url", "url": "https://hol.org/guard/integrations/slack"},
        )
        categories = tool_call_risk_categories(artifact, arguments)
        assert "outbound_network" not in categories, (
            f"Browser navigation should not trigger outbound_network, got {categories}"
        )
        assert "browser_navigation" in categories

    def test_browser_navigation_to_localhost(self) -> None:
        """HGBM037: Localhost navigation has browser_navigation category."""
        artifact, arguments = _browser_artifact(
            arguments={"type": "url", "url": "http://127.0.0.1:3000/guard"},
        )
        categories = tool_call_risk_categories(artifact, arguments)
        assert "browser_navigation" in categories
        assert "outbound_network" not in categories

    def test_browser_external_domain_navigation(self) -> None:
        """HGBM038: Public external domain navigation has browser_external_domain."""
        artifact, arguments = _browser_artifact(
            arguments={"type": "url", "url": "https://example.com/page"},
        )
        categories = tool_call_risk_categories(artifact, arguments)
        assert "browser_navigation" in categories
        assert "browser_external_domain" in categories

    def test_browser_inspection_category(self) -> None:
        """HGBM034: Screenshot has browser_inspection category."""
        artifact, arguments = _browser_artifact(
            tool_name="take_screenshot",
            arguments={"pageId": "tab1"},
        )
        categories = tool_call_risk_categories(artifact, arguments)
        assert "browser_inspection" in categories

    def test_browser_interaction_category(self) -> None:
        """HGBM039: Click/type has browser_interaction category."""
        artifact, arguments = _browser_artifact(
            tool_name="click",
            arguments={"selector": "#button"},
        )
        categories = tool_call_risk_categories(artifact, arguments)
        assert "browser_interaction" in categories

    def test_browser_transfer_category(self) -> None:
        """HGBM040: Upload/download has browser_transfer category."""
        artifact, arguments = _browser_artifact(
            tool_name="upload_file",
            arguments={"filePath": "/tmp/test.txt"},
        )
        categories = tool_call_risk_categories(artifact, arguments)
        assert "browser_transfer" in categories

    def test_browser_privileged_category(self) -> None:
        """HGBM041: Cookie/storage/CDP/script eval has browser_privileged category."""
        artifact, arguments = _browser_artifact(
            tool_name="read_cookies",
            arguments={},
        )
        categories = tool_call_risk_categories(artifact, arguments)
        assert "browser_privileged" in categories

    def test_browser_sensitive_surface_category(self) -> None:
        """HGBM043: Sensitive surface flags produce browser_sensitive_surface."""
        artifact, arguments = _browser_artifact(
            tool_name="evaluate_script",
            arguments={"expression": "document.title"},
        )
        categories = tool_call_risk_categories(artifact, arguments)
        assert "browser_sensitive_surface" in categories

    def test_evaluate_script_optional_filepath_schema_is_not_filesystem_access(self) -> None:
        server_identity = build_mcp_server_identity(
            config_path=".mcp.json",
            command="npx",
            args=("-y", "chrome-devtools-mcp@latest"),
            transport="stdio",
        )
        artifact = build_tool_call_artifact(
            harness="codex",
            server_name="chrome-devtools",
            tool_name="evaluate_script",
            source_scope="project",
            config_path=".mcp.json",
            transport="stdio",
            server_identity=server_identity,
            tool_schema={
                "type": "object",
                "properties": {
                    "function": {"type": "string"},
                    "filePath": {"type": "string"},
                },
            },
        )
        categories = tool_call_risk_categories(artifact, {"function": "() => document.title"})
        assert "filesystem_access" not in categories
        assert "browser_privileged" in categories
        with_file = tool_call_risk_categories(artifact, {"function": "() => 1", "filePath": "out.json"})
        assert "filesystem_access" in with_file

    def test_browser_shared_profile_category(self) -> None:
        """HGBM042: Shared/remote-debugging profile produces browser_shared_profile."""
        from codex_plugin_scanner.guard.runtime.mcp_protection import (
            build_mcp_server_identity,
        )

        server_identity = build_mcp_server_identity(
            config_path=".mcp.json",
            command="npx",
            args=("-y", "@modelcontextprotocol/server-chrome-devtools", "--remote-debugging-port=9222"),
            transport="stdio",
        )
        artifact, arguments = _browser_artifact(
            arguments={"type": "url", "url": "http://127.0.0.1:3000/guard"},
            server_identity=server_identity,
        )
        # Add server_args metadata so profile mode can be detected
        artifact = artifact.__class__(
            artifact_id=artifact.artifact_id,
            name=artifact.name,
            harness=artifact.harness,
            artifact_type=artifact.artifact_type,
            source_scope=artifact.source_scope,
            config_path=artifact.config_path,
            command=artifact.command,
            args=artifact.args,
            url=artifact.url,
            transport=artifact.transport,
            publisher=artifact.publisher,
            metadata={**artifact.metadata, "server_args": ["--remote-debugging-port=9222"]},
        )
        categories = tool_call_risk_categories(artifact, arguments)
        assert "browser_shared_profile" in categories

    def test_secret_access_overrides_browser_safe_handling(self) -> None:
        """HGBM044: .env path still triggers secret_access even through browser MCP."""
        artifact, arguments = _browser_artifact(
            arguments={"type": "url", "url": "file:///home/user/.env"},
        )
        categories = tool_call_risk_categories(artifact, arguments)
        assert "secret_access" in categories

    def test_npmrc_overrides_browser_safe_handling(self) -> None:
        """HGBM044: .npmrc path still triggers secret_access through browser MCP."""
        artifact, arguments = _browser_artifact(
            arguments={"type": "url", "url": "file:///project/.npmrc"},
        )
        categories = tool_call_risk_categories(artifact, arguments)
        assert "secret_access" in categories

    def test_non_browser_mcp_still_gets_outbound_network(self) -> None:
        """HGBM036: Non-browser MCP with URL still returns outbound_network."""
        from codex_plugin_scanner.guard.runtime.mcp_protection import (
            build_mcp_server_identity,
        )

        server_identity = build_mcp_server_identity(
            config_path=".mcp.json",
            command="npx",
            args=("-y", "@slack/mcp-server"),
            transport="stdio",
        )
        artifact, arguments = _browser_artifact(
            server_name="slack-mcp",
            tool_name="post_message",
            arguments={"webhook": "https://example.com/webhook"},
            server_identity=server_identity,
        )
        categories = tool_call_risk_categories(artifact, arguments)
        assert "outbound_network" in categories

    def test_browser_risk_signals_mention_intent(self) -> None:
        """HGBM045: Browser-specific signal text names intent and target."""
        artifact, arguments = _browser_artifact(
            arguments={"type": "url", "url": "https://hol.org/guard/integrations/slack"},
        )
        signals = tool_call_risk_signals(artifact, arguments)
        assert len(signals) > 0
        # At least one signal should mention browser or navigation
        combined = " ".join(signals).lower()
        assert "browser" in combined or "navigation" in combined

    def test_browser_risk_summary_is_informative(self) -> None:
        """HGBM046: Browser-specific risk summary."""
        artifact, arguments = _browser_artifact(
            arguments={"type": "url", "url": "https://example.com/page"},
        )
        summary = tool_call_risk_summary(artifact, arguments)
        assert isinstance(summary, str)
        assert len(summary) > 0

    def test_browser_privileged_risk_summary(self) -> None:
        """HGBM046: Privileged browser action has informative summary."""
        artifact, arguments = _browser_artifact(
            tool_name="read_cookies",
            arguments={},
        )
        summary = tool_call_risk_summary(artifact, arguments)
        assert isinstance(summary, str)
        assert len(summary) > 0

    def test_category_ordering(self) -> None:
        """HGBM034: Browser categories are in deterministic order."""
        artifact, arguments = _browser_artifact(
            tool_name="evaluate_script",
            arguments={"expression": "document.cookie"},
        )
        categories = tool_call_risk_categories(artifact, arguments)
        # browser_privileged should come before browser_sensitive_surface
        if "browser_privileged" in categories and "browser_sensitive_surface" in categories:
            assert categories.index("browser_privileged") < categories.index("browser_sensitive_surface")


# ─── HGBM063-HGBM071: Proxy metadata tests ────────────────────────────────────


class TestProxyBrowserIntentMetadata:
    """HGBM063-HGBM065: Proxy includes browser intent metadata."""

    def test_build_artifact_payload_includes_browser_intent(self) -> None:
        """HGBM063: _build_artifact_payload includes browser_intent for browser MCP."""
        from codex_plugin_scanner.guard.proxy.runtime_mcp import RuntimeMcpGuardProxy

        artifact, arguments = _browser_artifact(
            arguments={"type": "url", "url": "https://hol.org/guard/integrations/slack"},
        )

        # Create a minimal proxy-like object to test the payload builder
        class _FakeProxy:
            _launch_target = staticmethod(lambda tool, args: f"{tool} {args}")

        # Test _build_artifact_payload directly (it's a method but doesn't use self)
        # We'll call it as an unbound function with a mock
        payload = RuntimeMcpGuardProxy._build_artifact_payload(
            _FakeProxy(),
            artifact=artifact,
            artifact_hash="test-hash",
            tool_name="navigate_page",
            params={"arguments": arguments},
            signals=("browser navigation to hol.org",),
        )
        assert "browser_intent" in payload
        assert payload["browser_intent"]["intent"] == "browser.navigation"
        assert payload["browser_intent"]["target_domain"] == "hol.org"
        assert "runtime_browser_tool_call" in payload["changed_fields"]
        assert "runtime_tool_call" in payload["changed_fields"]

    def test_build_artifact_payload_no_browser_intent_for_non_browser(self) -> None:
        """HGBM063: Non-browser MCP does not include browser_intent."""
        from codex_plugin_scanner.guard.proxy.runtime_mcp import RuntimeMcpGuardProxy
        from codex_plugin_scanner.guard.runtime.mcp_protection import (
            build_mcp_server_identity,
        )

        server_identity = build_mcp_server_identity(
            config_path=".mcp.json",
            command="npx",
            args=("-y", "@slack/mcp-server"),
            transport="stdio",
        )
        artifact, arguments = _browser_artifact(
            server_name="slack-mcp",
            tool_name="post_message",
            arguments={"channel": "#general", "text": "hello"},
            server_identity=server_identity,
        )

        class _FakeProxy:
            _launch_target = staticmethod(lambda tool, args: f"{tool} {args}")

        payload = RuntimeMcpGuardProxy._build_artifact_payload(
            _FakeProxy(),
            artifact=artifact,
            artifact_hash="test-hash",
            tool_name="post_message",
            params={"arguments": arguments},
            signals=(),
        )
        assert "browser_intent" not in payload
        assert payload["changed_fields"] == ["runtime_tool_call"]

    def test_launch_target_prefers_browser_label(self) -> None:
        """HGBM065: launch_target is safe browser label when browser intent exists."""
        from codex_plugin_scanner.guard.proxy.runtime_mcp import RuntimeMcpGuardProxy

        artifact, arguments = _browser_artifact(
            arguments={"type": "url", "url": "https://hol.org/guard/integrations/slack"},
        )

        class _FakeProxy:
            _launch_target = staticmethod(lambda tool, args: f"{tool} {args}")

        payload = RuntimeMcpGuardProxy._build_artifact_payload(
            _FakeProxy(),
            artifact=artifact,
            artifact_hash="test-hash",
            tool_name="navigate_page",
            params={"arguments": arguments},
            signals=(),
        )
        assert payload["launch_target"] == "chrome-devtools navigate_page hol.org"
