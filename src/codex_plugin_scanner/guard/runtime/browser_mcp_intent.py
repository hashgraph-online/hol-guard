"""Browser MCP intent extraction and normalization.

Classifies browser automation MCP tool calls into stable intent models:
- browser.navigation: open URL, new tab, go back/forward, reload, select/list/close page
- browser.inspect: screenshot, DOM snapshot, console read, network read, perf trace
- browser.interact: click, hover, press key, type text, fill input, submit form, dialog
- browser.transfer: upload, download, clipboard, drag/drop file
- browser.privileged: cookies, storage, auth headers, raw CDP, script eval, intercept

The intent model strips volatile fields (timeout, pageId, tabId, etc.) from
stable identity while preserving security boundaries (origin, path, intent,
sensitive surfaces, profile mode).
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlparse, urlunparse

from ..models import GuardArtifact

BrowserIntent = Literal[
    "browser.navigation",
    "browser.inspect",
    "browser.interact",
    "browser.transfer",
    "browser.privileged",
]

BrowserProfileMode = Literal[
    "isolated",
    "dedicated",
    "shared",
    "remote-debugging",
    "unknown",
]

BrowserMethod = Literal[
    "navigate",
    "read",
    "interact",
    "submit",
    "upload",
    "download",
    "privileged",
]

# ─── Operation classification tables ──────────────────────────────────────────

# Chrome DevTools MCP tool names by intent
_CHROME_DEVTOOLS_NAVIGATION: frozenset[str] = frozenset(
    {
        "navigate_page",
        "new_page",
        "select_page",
        "list_pages",
        "close_page",
        "wait_for",
        "reload_page",
        "go_back",
        "go_forward",
    }
)

_CHROME_DEVTOOLS_INSPECT: frozenset[str] = frozenset(
    {
        "take_screenshot",
        "take_snapshot",
        "get_snapshot",
        "accessibility_snapshot",
        "read_console",
        "get_console",
        "read_network",
        "get_network",
        "performance_trace",
        "get_performance",
        "list_resources",
        "get_dom",
        "get_html",
    }
)

_CHROME_DEVTOOLS_INTERACT: frozenset[str] = frozenset(
    {
        "click",
        "hover",
        "press_key",
        "type_text",
        "fill_form",
        "fill_input",
        "select_dropdown",
        "submit_form",
        "handle_dialog",
        "accept_dialog",
        "dismiss_dialog",
        "scroll",
        "focus_element",
    }
)

_CHROME_DEVTOOLS_TRANSFER: frozenset[str] = frozenset(
    {
        "upload_file",
        "download_file",
        "save_file",
        "read_clipboard",
        "write_clipboard",
        "drag_drop_file",
    }
)

_CHROME_DEVTOOLS_PRIVILEGED: frozenset[str] = frozenset(
    {
        "evaluate_script",
        "raw_cdp",
        "read_cookies",
        "get_cookies",
        "set_cookies",
        "read_storage",
        "get_storage",
        "set_storage",
        "clear_storage",
        "get_auth_headers",
        "network_intercept",
        "set_network_intercept",
        "mock_network",
        "manage_extension",
        "manage_profile",
        "manage_session",
    }
)

# Playwright MCP tool names (prefixed with browser_)
_PLAYWRIGHT_NAVIGATION: frozenset[str] = frozenset(
    {
        "browser_navigate",
        "browser_navigate_back",
        "browser_navigate_forward",
        "browser_reload",
        "browser_new_page",
        "browser_new_context",
        "browser_close_page",
        "browser_close_context",
        "browser_close",
        "browser_select_page",
        "browser_list_pages",
        "browser_wait_for_url",
        "browser_wait_for_load_state",
    }
)

_PLAYWRIGHT_INSPECT: frozenset[str] = frozenset(
    {
        "browser_snapshot",
        "browser_screenshot",
        "browser_accessibility_snapshot",
        "browser_console_messages",
        "browser_network_requests",
        "browser_performance",
        "browser_get_html",
        "browser_get_dom",
    }
)

_PLAYWRIGHT_INTERACT: frozenset[str] = frozenset(
    {
        "browser_click",
        "browser_hover",
        "browser_press_key",
        "browser_type",
        "browser_fill",
        "browser_select_option",
        "browser_submit_form",
        "browser_dialog_accept",
        "browser_dialog_dismiss",
        "browser_scroll",
        "browser_focus",
        "browser_drag",
        "browser_select_text",
    }
)

_PLAYWRIGHT_TRANSFER: frozenset[str] = frozenset(
    {
        "browser_file_upload",
        "browser_download",
        "browser_clipboard_read",
        "browser_clipboard_write",
        "browser_drag_and_drop_file",
        "browser_pdf_save",
    }
)

_PLAYWRIGHT_PRIVILEGED: frozenset[str] = frozenset(
    {
        "browser_evaluate",
        "browser_execute_script",
        "browser_raw_cdp",
        "browser_cookies_get",
        "browser_cookies_set",
        "browser_cookies_clear",
        "browser_storage_get",
        "browser_storage_set",
        "browser_storage_clear",
        "browser_auth_headers",
        "browser_network_intercept",
        "browser_route_intercept",
        "browser_context_manage",
        "browser_profile_manage",
        "browser_session_manage",
    }
)

# Generic browser tool name patterns (used only when server is browser-confirmed)
_NAVIGATION_PATTERNS: tuple[str, ...] = (
    r"^navigate_",
    r"^new_page$",
    r"^select_page$",
    r"^list_pages$",
    r"^close_page$",
    r"^wait_for",
    r"^reload",
    r"^go_back$",
    r"^go_forward$",
    r"^browser_navigate",
)

_INSPECT_PATTERNS: tuple[str, ...] = (
    r"screenshot",
    r"snapshot",
    r"console",
    r"network",
    r"performance",
    r"trace",
    r"^list_resources$",
    r"^get_dom$",
    r"^get_html$",
)

_INTERACT_PATTERNS: tuple[str, ...] = (
    r"^click$",
    r"^hover$",
    r"^press_",
    r"^type_",
    r"^fill_",
    r"^select_",
    r"^submit_",
    r"^handle_dialog$",
    r"^accept_dialog$",
    r"^dismiss_dialog$",
    r"^scroll$",
    r"^focus_",
    r"browser_click",
    r"browser_type",
    r"browser_fill",
    r"browser_hover",
    r"browser_press",
)

_TRANSFER_PATTERNS: tuple[str, ...] = (
    r"upload",
    r"download",
    r"save_file",
    r"clipboard",
    r"drag_drop",
    r"drag_and_drop",
)

_PRIVILEGED_PATTERNS: tuple[str, ...] = (
    r"evaluate_script",
    r"execute_script",
    r"raw_cdp",
    r"cdp_",
    r"cookies",
    r"storage",
    r"auth_header",
    r"intercept",
    r"mock_network",
    r"manage_extension",
    r"manage_profile",
    r"manage_session",
    r"browser_evaluate",
    r"browser_cookies",
    r"browser_storage",
)

# ─── Volatile fields ──────────────────────────────────────────────────────────

_VOLATILE_FIELDS: frozenset[str] = frozenset(
    {
        "timeout",
        "pageId",
        "tabId",
        "traceId",
        "width",
        "height",
        "viewport",
        "waitUntil",
        "duration",
        "requestId",
        "selector",
        "cursor",
        "offsetX",
        "offsetY",
        "scrollX",
        "scrollY",
    }
)

# ─── Sensitive surface detection patterns ─────────────────────────────────────

_SENSITIVE_COOKIE_PATTERNS: tuple[str, ...] = ("cookie", "cookies")
_SENSITIVE_STORAGE_PATTERNS: tuple[str, ...] = (
    "storage",
    "local_storage",
    "session_storage",
    "localstorage",
    "sessionstorage",
)
_SENSITIVE_AUTH_PATTERNS: tuple[str, ...] = ("auth_header", "authorization", "auth_token", "authtoken")
_SENSITIVE_CDP_PATTERNS: tuple[str, ...] = ("cdp", "chrome_devtools_protocol", "raw_cdp")
_SENSITIVE_SCRIPT_EVAL_PATTERNS: tuple[str, ...] = ("eval", "script", "javascript", "expression")
_SENSITIVE_UPLOAD_PATTERNS: tuple[str, ...] = ("upload", "file_path", "filepath", "file_input")
_SENSITIVE_DOWNLOAD_PATTERNS: tuple[str, ...] = ("download", "save_path", "savepath", "download_path", "downloadpath")
_SENSITIVE_CLIPBOARD_PATTERNS: tuple[str, ...] = ("clipboard",)
_SENSITIVE_PASSWORD_PATTERNS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "credential",
    "api_key",
    "apikey",
    "access_token",
    "accesstoken",
)
_SENSITIVE_INTERCEPT_PATTERNS: tuple[str, ...] = ("intercept", "mock_network", "route_intercept")

# ─── URL extraction keys ──────────────────────────────────────────────────────

_URL_ARGUMENT_KEYS: tuple[str, ...] = ("url", "href", "target", "uri", "pageUrl", "page_url", "website")

# ─── Redaction patterns for query values ──────────────────────────────────────

_REDACT_QUERY_KEYS: frozenset[str] = frozenset(
    {
        "token",
        "key",
        "secret",
        "session",
        "code",
        "access_token",
        "refresh_token",
        "auth",
        "authorization",
        "password",
        "passwd",
        "credential",
        "api_key",
        "apikey",
    }
)

# ─── Server name detection ────────────────────────────────────────────────────

_BROWSER_SERVER_NAME_PATTERNS: tuple[str, ...] = (
    r"chrome[\-_\s]?devtools",
    r"@playwright/mcp",
    r"playwright[\-_\s]?mcp",
    r"browser[\-_\s]?tools",
    r"browser[\-_\s]?mcp",
    r"puppeteer[\-_\s]?mcp",
    r"web[\-_\s]?browser",
)

_BROWSER_PACKAGE_PATTERNS: tuple[str, ...] = (
    r"@modelcontextprotocol/server-chrome-devtools",
    r"@playwright/mcp",
    r"puppeteer",
    r"playwright",
)

# ─── Profile mode detection ───────────────────────────────────────────────────

_ISOLATED_FLAGS: tuple[str, ...] = ("--isolated", "--isolated-context")
_PROFILE_DIR_FLAGS: tuple[str, ...] = ("--user-data-dir", "--persistent", "--profile-dir", "--storage-state")
_REMOTE_DEBUG_FLAGS: tuple[str, ...] = ("--remote-debugging-port", "--remote-debugging-pipe", "--ws-endpoint")

# ─── Dataclass ────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class GuardBrowserAutomationIntentV1:
    """Normalized browser automation intent from a browser MCP tool call.

    Strips volatile fields (timeout, pageId, etc.) from stable identity
    while preserving security boundaries: origin, path prefix, intent,
    sensitive surfaces, and profile mode.
    """

    version: int
    intent: BrowserIntent
    operation: str
    target_url: str | None = None
    target_origin: str | None = None
    target_domain: str | None = None
    target_path_prefix: str | None = None
    method: BrowserMethod | None = None
    profile_mode: BrowserProfileMode = "unknown"
    mcp_server_name: str = ""
    mcp_server_identity_hash: str | None = None
    mcp_tool_name: str = ""
    mcp_tool_identity_hash: str | None = None
    mcp_schema_hash: str | None = None
    sensitive_surface_flags: tuple[str, ...] = ()
    volatile_fields_dropped: tuple[str, ...] = ()


# ─── Public API ────────────────────────────────────────────────────────────────


def is_browser_mcp_server(artifact: GuardArtifact) -> bool:
    """Determine if an MCP artifact belongs to a browser automation server.

    Checks server name, package metadata, tool identity metadata, and
    schema/description text for browser-related markers.
    """
    server_name = str(artifact.metadata.get("server_name", "")).lower()
    combined = f"{server_name} {artifact.name}".lower()

    # Check server name patterns
    for pattern in _BROWSER_SERVER_NAME_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            return True

    # Check package name from server identity metadata
    server_identity = artifact.metadata.get("mcp_server_identity")
    if isinstance(server_identity, Mapping):
        package_name = str(server_identity.get("package_name", "")).lower()
        for pattern in _BROWSER_PACKAGE_PATTERNS:
            if re.search(pattern, package_name, re.IGNORECASE):
                return True

    # Check tool identity metadata for browser hints
    tool_identity = artifact.metadata.get("mcp_tool_identity")
    if isinstance(tool_identity, Mapping):
        # If the tool name itself contains browser markers, still require
        # some server-level signal to avoid false positives.
        tool_name = str(artifact.command or artifact.name).lower()
        if any(marker in tool_name for marker in ("browser_", "navigate", "screenshot", "snapshot", "page")) and any(
            pattern in combined for pattern in ("browser", "chrome", "playwright", "devtools", "puppeteer")
        ):
            return True

    return False


def normalize_browser_mcp_intent(
    artifact: GuardArtifact,
    arguments: object,
) -> GuardBrowserAutomationIntentV1 | None:
    """Extract a normalized browser automation intent from an MCP tool call.

    Returns None if the artifact is not from a browser MCP server.
    """
    if not is_browser_mcp_server(artifact):
        return None

    server_name = str(artifact.metadata.get("server_name", ""))
    operation = _extract_tool_operation(artifact)
    mapping = _extract_mapping(arguments)

    intent = _classify_operation(operation, server_name)
    if intent is None:
        return None

    target_url = _extract_target_url(mapping) if mapping else None
    target_origin = _normalize_target_origin(target_url) if target_url else None
    target_domain = _normalize_target_domain(target_url) if target_url else None
    target_path_prefix = _normalize_path_prefix(target_url) if target_url else None

    profile_mode = _detect_profile_mode(server_name, artifact.metadata)

    # Extract identity hashes from metadata
    server_identity = artifact.metadata.get("mcp_server_identity")
    server_hash = None
    if isinstance(server_identity, Mapping):
        server_hash = _optional_str(server_identity.get("identity_hash"))

    tool_identity = artifact.metadata.get("mcp_tool_identity")
    tool_hash = None
    schema_hash = None
    if isinstance(tool_identity, Mapping):
        tool_hash = _optional_str(tool_identity.get("identity_hash"))
        schema_hash = _optional_str(tool_identity.get("schema_hash"))

    raw_schema = artifact.metadata.get("tool_schema")
    schema_arg: Mapping[str, object] = raw_schema if isinstance(raw_schema, dict) else {}
    raw_desc = artifact.metadata.get("tool_description")
    desc_arg: str = raw_desc if isinstance(raw_desc, str) else ""

    sensitive_flags = _detect_sensitive_surfaces(
        operation,
        mapping or {},
        schema_arg,
        desc_arg,
    )

    volatile_dropped = _collect_volatile_fields(mapping) if mapping else ()

    method = _intent_to_method(intent)

    return GuardBrowserAutomationIntentV1(
        version=1,
        intent=intent,
        operation=operation,
        target_url=_redacted_target_url(target_url) if target_url else None,
        target_origin=target_origin,
        target_domain=target_domain,
        target_path_prefix=target_path_prefix,
        method=method,
        profile_mode=profile_mode,
        mcp_server_name=server_name,
        mcp_server_identity_hash=server_hash,
        mcp_tool_name=operation,
        mcp_tool_identity_hash=tool_hash,
        mcp_schema_hash=schema_hash,
        sensitive_surface_flags=sensitive_flags,
        volatile_fields_dropped=volatile_dropped,
    )


# ─── Internal helpers ──────────────────────────────────────────────────────────


def _extract_tool_operation(artifact: GuardArtifact) -> str:
    """Extract the tool operation name from the artifact.

    Uses artifact.command first, then metadata tool identity name.
    """
    if artifact.command:
        return artifact.command
    tool_identity = artifact.metadata.get("mcp_tool_identity")
    if isinstance(tool_identity, Mapping):
        name = _optional_str(tool_identity.get("tool_name"))
        if name:
            return name
    return artifact.name.rsplit(":", 1)[-1] if ":" in artifact.name else artifact.name


def _extract_mapping(arguments: object) -> dict[str, object] | None:
    """Extract a mapping from arguments.

    Accepts dicts and JSON strings. Rejects lists, non-object JSON, and
    malformed JSON.
    """
    if isinstance(arguments, Mapping):
        return dict(arguments)
    if isinstance(arguments, str):
        try:
            parsed = json.loads(arguments)
        except (json.JSONDecodeError, ValueError):
            return None
        if isinstance(parsed, dict):
            return parsed
        return None
    return None


def _extract_target_url(mapping: dict[str, object] | None) -> str | None:
    """Extract a target URL from various argument shapes.

    Checks url, href, target, uri, pageUrl, nested arguments.url.
    """
    if mapping is None:
        return None

    # Direct keys
    for key in _URL_ARGUMENT_KEYS:
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    # Playwright-style locator/url shapes
    locator = mapping.get("locator")
    if isinstance(locator, Mapping):
        url = locator.get("url")
        if isinstance(url, str) and url.strip():
            return url.strip()

    # Nested arguments.url
    nested = mapping.get("arguments")
    if isinstance(nested, Mapping):
        url = nested.get("url")
        if isinstance(url, str) and url.strip():
            return url.strip()

    return None


def _normalize_target_origin(url: str | None) -> str | None:
    """Normalize a URL to its origin (scheme://host:port)."""
    if url is None:
        return None
    try:
        parsed = urlparse(url)
    except (ValueError, TypeError):
        return None
    if not parsed.scheme or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


def _normalize_target_domain(url: str | None) -> str | None:
    """Extract the target domain/hostname from a URL."""
    if url is None:
        return None
    try:
        parsed = urlparse(url)
    except (ValueError, TypeError):
        return None
    if not parsed.hostname:
        return None
    return parsed.hostname


def _normalize_path_prefix(url: str | None) -> str | None:
    """Normalize the URL path, stripping query and fragment."""
    if url is None:
        return None
    try:
        parsed = urlparse(url)
    except (ValueError, TypeError):
        return None
    return parsed.path or ""


def _redacted_target_url(url: str | None) -> str | None:
    """Redact sensitive query parameter values in a URL."""
    if url is None:
        return None
    try:
        parsed = urlparse(url)
    except (ValueError, TypeError):
        return url

    if not parsed.query:
        return url

    # Parse query params and redact sensitive ones
    from urllib.parse import parse_qsl, urlencode

    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    redacted_pairs: list[tuple[str, str]] = []
    for key, value in pairs:
        if _normalize_query_key(key) in _REDACT_QUERY_KEYS:
            redacted_pairs.append((key, "[redacted]"))
        else:
            redacted_pairs.append((key, value))

    redacted_query = urlencode(redacted_pairs)
    return urlunparse(parsed._replace(query=redacted_query))


def _normalize_query_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())


def _classify_operation(operation: str, server_name: str) -> BrowserIntent | None:
    """Classify a tool operation into a browser intent.

    Uses explicit operation tables for known servers, then falls back to
    pattern matching. Returns None if the operation is not browser-related
    and the server is not a confirmed browser server.
    """
    op_lower = operation.lower()
    server_lower = server_name.lower()

    is_chrome = bool(re.search(r"chrome[\-_\s]?devtools", server_lower, re.IGNORECASE))
    is_playwright = bool(re.search(r"@playwright/mcp|playwright", server_lower, re.IGNORECASE))
    is_browser_server = (
        is_chrome
        or is_playwright
        or bool(
            re.search(r"browser[\-_\s]?(tools|mcp)", server_lower, re.IGNORECASE)
            or re.search(r"puppeteer", server_lower, re.IGNORECASE)
        )
    )

    # Chrome DevTools explicit tables
    if is_chrome:
        if op_lower in _CHROME_DEVTOOLS_NAVIGATION:
            return "browser.navigation"
        if op_lower in _CHROME_DEVTOOLS_INSPECT:
            return "browser.inspect"
        if op_lower in _CHROME_DEVTOOLS_INTERACT:
            return "browser.interact"
        if op_lower in _CHROME_DEVTOOLS_TRANSFER:
            return "browser.transfer"
        if op_lower in _CHROME_DEVTOOLS_PRIVILEGED:
            return "browser.privileged"

    # Playwright explicit tables
    if is_playwright:
        if op_lower in _PLAYWRIGHT_NAVIGATION:
            return "browser.navigation"
        if op_lower in _PLAYWRIGHT_INSPECT:
            return "browser.inspect"
        if op_lower in _PLAYWRIGHT_INTERACT:
            return "browser.interact"
        if op_lower in _PLAYWRIGHT_TRANSFER:
            return "browser.transfer"
        if op_lower in _PLAYWRIGHT_PRIVILEGED:
            return "browser.privileged"

    # Pattern-based fallback (only for confirmed browser servers)
    if is_browser_server:
        if any(re.search(pattern, op_lower, re.IGNORECASE) for pattern in _NAVIGATION_PATTERNS):
            return "browser.navigation"
        if any(re.search(pattern, op_lower, re.IGNORECASE) for pattern in _PRIVILEGED_PATTERNS):
            return "browser.privileged"
        if any(re.search(pattern, op_lower, re.IGNORECASE) for pattern in _TRANSFER_PATTERNS):
            return "browser.transfer"
        if any(re.search(pattern, op_lower, re.IGNORECASE) for pattern in _INTERACT_PATTERNS):
            return "browser.interact"
        if any(re.search(pattern, op_lower, re.IGNORECASE) for pattern in _INSPECT_PATTERNS):
            return "browser.inspect"

    return None


def _detect_sensitive_surfaces(
    operation: str,
    arguments: Mapping[str, object],
    schema: Mapping[str, object],
    description: str,
) -> tuple[str, ...]:
    """Detect sensitive browser surfaces from operation name, args, schema, description."""
    surfaces: list[str] = []
    combined = f"{operation} {description}".lower()
    arg_keys_lower = " ".join(str(k) for k in arguments).lower()
    schema_keys = _extract_schema_keys(schema)
    schema_combined = " ".join(schema_keys).lower()
    all_text = f"{combined} {arg_keys_lower} {schema_combined}"

    if any(p in all_text for p in _SENSITIVE_COOKIE_PATTERNS):
        surfaces.append("cookies")
    if any(p in all_text for p in _SENSITIVE_STORAGE_PATTERNS):
        surfaces.append("storage")
    if any(p in all_text for p in _SENSITIVE_AUTH_PATTERNS):
        surfaces.append("auth_headers")
    if any(p in all_text for p in _SENSITIVE_CDP_PATTERNS):
        surfaces.append("cdp")
    if any(p in all_text for p in _SENSITIVE_SCRIPT_EVAL_PATTERNS):
        surfaces.append("script_eval")
    if any(p in all_text for p in _SENSITIVE_UPLOAD_PATTERNS):
        surfaces.append("upload")
    if any(p in all_text for p in _SENSITIVE_DOWNLOAD_PATTERNS):
        surfaces.append("download")
    if any(p in all_text for p in _SENSITIVE_CLIPBOARD_PATTERNS):
        surfaces.append("clipboard")
    if any(p in all_text for p in _SENSITIVE_INTERCEPT_PATTERNS):
        surfaces.append("network_intercept")

    # Password field detection from schema
    if any(p in schema_combined for p in _SENSITIVE_PASSWORD_PATTERNS):
        surfaces.append("password_field")

    return tuple(dict.fromkeys(surfaces))


def _extract_schema_keys(schema: Mapping[str, object]) -> list[str]:
    """Extract property key names from a JSON schema."""
    keys: list[str] = []

    def _walk(obj: object) -> None:
        if isinstance(obj, Mapping):
            props = obj.get("properties")
            if isinstance(props, Mapping):
                keys.extend(str(k) for k in props)
            for value in obj.values():
                _walk(value)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item)

    _walk(schema)
    return keys


def _detect_profile_mode(
    server_name: str,
    metadata: Mapping[str, object],
) -> BrowserProfileMode:
    """Detect browser profile mode from MCP server args/metadata."""
    server_identity = metadata.get("mcp_server_identity")
    args: list[str] = []

    if isinstance(server_identity, Mapping):
        raw_args = server_identity.get("args")
        if isinstance(raw_args, (list, tuple)):
            args = [str(a) for a in raw_args]

    # Also check metadata for args (direct 'args' key or 'server_args')
    for args_key in ("args", "server_args"):
        meta_args = metadata.get(args_key)
        if isinstance(meta_args, (list, tuple)):
            args.extend(str(a) for a in meta_args)

    # Check isolated first (most specific) — use startswith per arg
    # to avoid false positives from substring matching.
    if any(any(arg.startswith(flag) for arg in args) for flag in _ISOLATED_FLAGS):
        return "isolated"

    # Check remote debugging
    if any(any(arg.startswith(flag) for arg in args) for flag in _REMOTE_DEBUG_FLAGS):
        return "remote-debugging"

    # Check dedicated/persistent profile
    if any(any(arg.startswith(flag) for arg in args) for flag in _PROFILE_DIR_FLAGS):
        return "dedicated"

    # Check for shared profile indicators
    if any(arg.startswith("--shared") or arg.startswith("--no-isolated") for arg in args):
        return "shared"

    return "unknown"


def _collect_volatile_fields(mapping: Mapping[str, object] | None) -> tuple[str, ...]:
    """Collect volatile field names present in arguments."""
    if mapping is None:
        return ()
    return tuple(key for key in mapping if isinstance(key, str) and key in _VOLATILE_FIELDS)


def _intent_to_method(intent: BrowserIntent) -> BrowserMethod:
    """Map an intent to a method label."""
    mapping: dict[BrowserIntent, BrowserMethod] = {
        "browser.navigation": "navigate",
        "browser.inspect": "read",
        "browser.interact": "interact",
        "browser.transfer": "upload",
        "browser.privileged": "privileged",
    }
    return mapping.get(intent, "read")


def _optional_str(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


__all__ = [
    "_VOLATILE_FIELDS",
    "BrowserIntent",
    "BrowserMethod",
    "BrowserProfileMode",
    "GuardBrowserAutomationIntentV1",
    "_classify_operation",
    "_collect_volatile_fields",
    "_detect_profile_mode",
    "_detect_sensitive_surfaces",
    "_extract_mapping",
    "_extract_target_url",
    "_extract_tool_operation",
    "_normalize_path_prefix",
    "_normalize_target_domain",
    "_normalize_target_origin",
    "_redacted_target_url",
    "is_browser_mcp_server",
    "normalize_browser_mcp_intent",
]
