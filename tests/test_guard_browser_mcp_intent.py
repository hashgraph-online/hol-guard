"""Characterization tests for browser MCP intent extraction (HGBM005-HGBM032)."""

from __future__ import annotations

import json

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


class TestBrowserAutomationIntentV1:
    """HGBM013: GuardBrowserAutomationIntentV1 dataclass."""

    def test_dataclass_is_frozen_and_serializable(self) -> None:
        """HGBM013: Dataclass is frozen and can serialize to JSON."""
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            GuardBrowserAutomationIntentV1,
        )

        intent = GuardBrowserAutomationIntentV1(
            version=1,
            intent="browser.navigation",
            operation="navigate_page",
            target_url="https://hol.org/guard/integrations/slack",
            target_origin="https://hol.org",
            target_domain="hol.org",
            target_path_prefix="/guard/integrations/slack",
            method="navigate",
            profile_mode="unknown",
            mcp_server_name="chrome-devtools",
            mcp_server_identity_hash=None,
            mcp_tool_name="navigate_page",
            mcp_tool_identity_hash=None,
            mcp_schema_hash=None,
            sensitive_surface_flags=(),
            volatile_fields_dropped=("timeout",),
        )
        assert intent.version == 1
        assert intent.intent == "browser.navigation"
        # Should be serializable
        from dataclasses import asdict
        payload = json.dumps(asdict(intent), sort_keys=True)
        assert "browser.navigation" in payload


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


class TestExtractToolOperation:
    """HGBM016: _extract_tool_operation function."""

    def test_uses_artifact_command_first(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _extract_tool_operation,
        )

        artifact, _ = _browser_artifact(tool_name="navigate_page")
        assert _extract_tool_operation(artifact) == "navigate_page"

    def test_uses_browser_navigate(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _extract_tool_operation,
        )

        artifact, _ = _browser_artifact(tool_name="browser_navigate")
        assert _extract_tool_operation(artifact) == "browser_navigate"


class TestExtractMapping:
    """HGBM017: _extract_mapping function."""

    def test_accepts_dict(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _extract_mapping,
        )

        result = _extract_mapping({"url": "https://example.com"})
        assert result == {"url": "https://example.com"}

    def test_accepts_json_string(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _extract_mapping,
        )

        result = _extract_mapping('{"url": "https://example.com"}')
        assert result == {"url": "https://example.com"}

    def test_rejects_list(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _extract_mapping,
        )

        assert _extract_mapping([1, 2, 3]) is None

    def test_rejects_malformed_json(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _extract_mapping,
        )

        assert _extract_mapping("{not valid json") is None

    def test_rejects_non_object_json(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _extract_mapping,
        )

        assert _extract_mapping('"just a string"') is None
        assert _extract_mapping("42") is None


class TestUrlExtraction:
    """HGBM018: URL extraction from various argument shapes."""

    def test_extract_from_url_key(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _extract_target_url,
        )

        assert _extract_target_url({"url": "https://example.com"}) == "https://example.com"

    def test_extract_from_href_key(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _extract_target_url,
        )

        assert _extract_target_url({"href": "https://example.com"}) == "https://example.com"

    def test_extract_from_target_key(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _extract_target_url,
        )

        assert _extract_target_url({"target": "https://example.com"}) == "https://example.com"

    def test_extract_from_uri_key(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _extract_target_url,
        )

        assert _extract_target_url({"uri": "https://example.com"}) == "https://example.com"

    def test_extract_from_page_url_key(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _extract_target_url,
        )

        assert _extract_target_url({"pageUrl": "https://example.com"}) == "https://example.com"

    def test_extract_from_nested_arguments_url(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _extract_target_url,
        )

        assert _extract_target_url({"arguments": {"url": "https://example.com"}}) == "https://example.com"

    def test_returns_none_when_no_url(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _extract_target_url,
        )

        assert _extract_target_url({"text": "hello"}) is None


class TestUrlNormalization:
    """HGBM019: URL normalization preserving scheme, host, port."""

    def test_http_localhost_with_port(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _normalize_target_origin,
        )

        origin = _normalize_target_origin("http://127.0.0.1:3000/a")
        assert origin == "http://127.0.0.1:3000"

    def test_ipv6_localhost(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _normalize_target_origin,
        )

        origin = _normalize_target_origin("http://[::1]:3000/a")
        assert origin == "http://[::1]:3000"

    def test_https_with_domain(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _normalize_target_origin,
        )

        origin = _normalize_target_origin("https://hol.org/a")
        assert origin == "https://hol.org"


class TestTargetDomainNormalization:
    """HGBM020: target_domain normalization."""

    def test_hol_org(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _normalize_target_domain,
        )

        assert _normalize_target_domain("https://hol.org/a") == "hol.org"

    def test_app_hol_org(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _normalize_target_domain,
        )

        assert _normalize_target_domain("https://app.hol.org/a") == "app.hol.org"

    def test_localhost(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _normalize_target_domain,
        )

        assert _normalize_target_domain("http://localhost:3000/a") == "localhost"

    def test_ipv4_localhost(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _normalize_target_domain,
        )

        assert _normalize_target_domain("http://127.0.0.1:3000/a") == "127.0.0.1"

    def test_ipv6_localhost(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _normalize_target_domain,
        )

        assert _normalize_target_domain("http://[::1]:3000/a") == "::1"


class TestPathPrefixNormalization:
    """HGBM021: target_path_prefix strips query/fragment."""

    def test_strips_query_and_fragment(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _normalize_path_prefix,
        )

        result = _normalize_path_prefix("https://hol.org/guard/integrations/slack?token=x#y")
        assert result == "/guard/integrations/slack"

    def test_root_path(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _normalize_path_prefix,
        )

        assert _normalize_path_prefix("https://hol.org/") == "/"

    def test_empty_path(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _normalize_path_prefix,
        )

        assert _normalize_path_prefix("https://hol.org") == ""


class TestRedactedTargetUrl:
    """HGBM022: redacted_target_url redacts sensitive query values."""

    def test_redacts_token(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _redacted_target_url,
        )

        result = _redacted_target_url("https://hol.org/callback?token=secret123")
        assert "secret123" not in result
        assert "[redacted]" in result

    def test_redacts_session(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _redacted_target_url,
        )

        result = _redacted_target_url("https://hol.org/cb?session=abc456")
        assert "abc456" not in result

    def test_preserves_non_sensitive_values(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _redacted_target_url,
        )

        result = _redacted_target_url("https://hol.org/guard?id=123")
        assert "123" in result


class TestOperationMaps:
    """HGBM023-HGBM029: Operation maps for browser MCP tools."""

    def test_chrome_devtools_navigation_operations(self) -> None:
        """HGBM023: Chrome DevTools navigation operation map."""
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _classify_operation,
        )

        for op in ("navigate_page", "new_page", "select_page", "list_pages", "close_page", "wait_for"):
            intent = _classify_operation(op, "chrome-devtools")
            assert intent == "browser.navigation", f"{op} should be navigation, got {intent}"

    def test_chrome_devtools_inspect_operations(self) -> None:
        """HGBM024: Chrome DevTools inspect/read operation map."""
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _classify_operation,
        )

        for op in ("take_screenshot", "take_snapshot", "read_console", "read_network", "performance_trace"):
            intent = _classify_operation(op, "chrome-devtools")
            assert intent == "browser.inspect", f"{op} should be inspect, got {intent}"

    def test_chrome_devtools_interact_operations(self) -> None:
        """HGBM025: Chrome DevTools interact operation map."""
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _classify_operation,
        )

        for op in ("click", "hover", "press_key", "type_text", "fill_form", "handle_dialog"):
            intent = _classify_operation(op, "chrome-devtools")
            assert intent == "browser.interact", f"{op} should be interact, got {intent}"

    def test_chrome_devtools_privileged_operations(self) -> None:
        """HGBM026: Chrome DevTools privileged operation map."""
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _classify_operation,
        )

        for op in ("evaluate_script", "raw_cdp", "read_cookies", "read_storage", "network_intercept"):
            intent = _classify_operation(op, "chrome-devtools")
            assert intent == "browser.privileged", f"{op} should be privileged, got {intent}"

    def test_playwright_navigation_and_inspect(self) -> None:
        """HGBM027: Playwright navigation and inspect maps."""
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _classify_operation,
        )

        assert _classify_operation("browser_navigate", "@playwright/mcp") == "browser.navigation"
        assert _classify_operation("browser_snapshot", "@playwright/mcp") == "browser.inspect"
        assert _classify_operation("browser_screenshot", "@playwright/mcp") == "browser.inspect"

    def test_playwright_interact_transfer_privileged(self) -> None:
        """HGBM028: Playwright interact, transfer, privileged maps."""
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _classify_operation,
        )

        assert _classify_operation("browser_click", "@playwright/mcp") == "browser.interact"
        assert _classify_operation("browser_type", "@playwright/mcp") == "browser.interact"
        assert _classify_operation("browser_file_upload", "@playwright/mcp") == "browser.transfer"
        assert _classify_operation("browser_pdf_save", "@playwright/mcp") == "browser.transfer"
        assert _classify_operation("browser_evaluate", "@playwright/mcp") == "browser.privileged"

    def test_generic_fallback_requires_browser_server(self) -> None:
        """HGBM029: Non-browser server 'navigate' does not classify as browser."""
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _classify_operation,
        )

        # For a non-browser server, unknown operations should not return a browser intent
        assert _classify_operation("navigate", "slack-mcp") is None


class TestVolatileFields:
    """HGBM030: Volatile field detection."""

    def test_known_volatile_fields(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _VOLATILE_FIELDS,
        )

        expected = {"timeout", "pageId", "tabId", "traceId", "width", "height", "viewport", "waitUntil", "duration", "requestId"}
        assert expected.issubset(_VOLATILE_FIELDS)

    def test_detects_volatile_fields_in_arguments(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _collect_volatile_fields,
        )

        dropped = _collect_volatile_fields({"url": "https://example.com", "timeout": 30000, "pageId": "tab1"})
        assert "timeout" in dropped
        assert "pageId" in dropped
        assert "url" not in dropped


class TestSensitiveSurfaces:
    """HGBM031: Sensitive surface detection."""

    def test_cookies_detected(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _detect_sensitive_surfaces,
        )

        surfaces = _detect_sensitive_surfaces("read_cookies", {}, {}, {})
        assert "cookies" in surfaces

    def test_storage_detected(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _detect_sensitive_surfaces,
        )

        surfaces = _detect_sensitive_surfaces("read_storage", {}, {}, {})
        assert "storage" in surfaces

    def test_script_eval_detected(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _detect_sensitive_surfaces,
        )

        surfaces = _detect_sensitive_surfaces("evaluate_script", {}, {}, {})
        assert "script_eval" in surfaces

    def test_cdp_detected(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _detect_sensitive_surfaces,
        )

        surfaces = _detect_sensitive_surfaces("raw_cdp", {}, {}, {})
        assert "cdp" in surfaces

    def test_upload_detected_from_args(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _detect_sensitive_surfaces,
        )

        surfaces = _detect_sensitive_surfaces("upload_file", {"filePath": "/tmp/file.txt"}, {}, {})
        assert "upload" in surfaces

    def test_download_detected_from_args(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _detect_sensitive_surfaces,
        )

        surfaces = _detect_sensitive_surfaces("save_file", {"downloadPath": "/tmp/file.txt"}, {}, {})
        assert "download" in surfaces

    def test_password_field_detected_from_schema(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _detect_sensitive_surfaces,
        )

        surfaces = _detect_sensitive_surfaces("fill_form", {}, {"properties": {"password": {"type": "string"}}}, {})
        assert "password_field" in surfaces

    def test_network_intercept_detected(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _detect_sensitive_surfaces,
        )

        surfaces = _detect_sensitive_surfaces("network_intercept", {}, {}, {})
        assert "network_intercept" in surfaces


class TestProfileMode:
    """HGBM032: Browser profile mode detection."""

    def test_isolated_playwright(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _detect_profile_mode,
        )

        assert _detect_profile_mode("@playwright/mcp", {"args": ["--isolated"]}) == "isolated"

    def test_persistent_profile_dir(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _detect_profile_mode,
        )

        assert _detect_profile_mode("chrome-devtools", {"args": ["--user-data-dir=/tmp/profile"]}) == "dedicated"

    def test_remote_debugging_port(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _detect_profile_mode,
        )

        assert _detect_profile_mode("chrome-devtools", {"args": ["--remote-debugging-port=9222"]}) == "remote-debugging"

    def test_unknown_default(self) -> None:
        from codex_plugin_scanner.guard.runtime.browser_mcp_intent import (
            _detect_profile_mode,
        )

        assert _detect_profile_mode("chrome-devtools", {}) == "unknown"


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
        assert "hol.org" in payload["launch_target"]
        assert "navigate_page" not in payload["launch_target"] or "chrome" in payload["launch_target"].lower()
