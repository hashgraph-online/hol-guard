// Existing browser operation, surface, and redaction tables.
// Regex whitespace includes CPython's additional U+001C–U+001F characters.

const CHROME_DEVTOOLS_NAVIGATION: &[&str] = &[
    "close_page",
    "go_back",
    "go_forward",
    "list_pages",
    "navigate_page",
    "new_page",
    "reload_page",
    "select_page",
    "wait_for",
];

const CHROME_DEVTOOLS_INSPECT: &[&str] = &[
    "accessibility_snapshot",
    "get_console",
    "get_console_message",
    "get_dom",
    "get_html",
    "get_network",
    "get_performance",
    "get_snapshot",
    "lighthouse_audit",
    "list_console_messages",
    "list_network_requests",
    "list_resources",
    "performance_analyze_insight",
    "performance_start_trace",
    "performance_stop_trace",
    "performance_trace",
    "read_console",
    "read_network",
    "take_screenshot",
    "take_snapshot",
];

const CHROME_DEVTOOLS_INTERACT: &[&str] = &[
    "accept_dialog",
    "click",
    "dismiss_dialog",
    "drag",
    "emulate",
    "fill_form",
    "fill_input",
    "focus_element",
    "handle_dialog",
    "hover",
    "press_key",
    "resize_page",
    "scroll",
    "select_dropdown",
    "submit_form",
    "type_text",
];

const CHROME_DEVTOOLS_TRANSFER: &[&str] = &[
    "download_file",
    "drag_drop_file",
    "read_clipboard",
    "save_file",
    "upload_file",
    "write_clipboard",
];

const CHROME_DEVTOOLS_PRIVILEGED: &[&str] = &[
    "clear_storage",
    "evaluate_script",
    "get_auth_headers",
    "get_cookies",
    "get_network_request",
    "get_storage",
    "manage_extension",
    "manage_profile",
    "manage_session",
    "mock_network",
    "network_intercept",
    "raw_cdp",
    "read_cookies",
    "read_storage",
    "set_cookies",
    "set_network_intercept",
    "set_storage",
];

const PLAYWRIGHT_NAVIGATION: &[&str] = &[
    "browser_close",
    "browser_close_context",
    "browser_close_page",
    "browser_list_pages",
    "browser_navigate",
    "browser_navigate_back",
    "browser_navigate_forward",
    "browser_new_context",
    "browser_new_page",
    "browser_reload",
    "browser_select_page",
    "browser_wait_for_load_state",
    "browser_wait_for_url",
];

const PLAYWRIGHT_INSPECT: &[&str] = &[
    "browser_accessibility_snapshot",
    "browser_console_messages",
    "browser_get_dom",
    "browser_get_html",
    "browser_network_requests",
    "browser_performance",
    "browser_screenshot",
    "browser_snapshot",
];

const PLAYWRIGHT_INTERACT: &[&str] = &[
    "browser_click",
    "browser_dialog_accept",
    "browser_dialog_dismiss",
    "browser_drag",
    "browser_fill",
    "browser_focus",
    "browser_hover",
    "browser_press_key",
    "browser_scroll",
    "browser_select_option",
    "browser_select_text",
    "browser_submit_form",
    "browser_type",
];

const PLAYWRIGHT_TRANSFER: &[&str] = &[
    "browser_clipboard_read",
    "browser_clipboard_write",
    "browser_download",
    "browser_drag_and_drop_file",
    "browser_file_upload",
    "browser_pdf_save",
];

const PLAYWRIGHT_PRIVILEGED: &[&str] = &[
    "browser_auth_headers",
    "browser_context_manage",
    "browser_cookies_clear",
    "browser_cookies_get",
    "browser_cookies_set",
    "browser_evaluate",
    "browser_execute_script",
    "browser_network_intercept",
    "browser_profile_manage",
    "browser_raw_cdp",
    "browser_route_intercept",
    "browser_session_manage",
    "browser_storage_clear",
    "browser_storage_get",
    "browser_storage_set",
];

const NAVIGATION_PATTERNS: &[&str] = &[
    "^navigate_",
    "^new_page$",
    "^select_page$",
    "^list_pages$",
    "^close_page$",
    "^wait_for",
    "^reload",
    "^go_back$",
    "^go_forward$",
    "^browser_navigate",
];

const INSPECT_PATTERNS: &[&str] = &[
    "screenshot",
    "snapshot",
    "console",
    "network",
    "performance",
    "trace",
    "^list_resources$",
    "^get_dom$",
    "^get_html$",
];

const INTERACT_PATTERNS: &[&str] = &[
    "^click$",
    "^hover$",
    "^press_",
    "^type_",
    "^fill_",
    "^select_",
    "^submit_",
    "^handle_dialog$",
    "^accept_dialog$",
    "^dismiss_dialog$",
    "^scroll$",
    "^focus_",
    "browser_click",
    "browser_type",
    "browser_fill",
    "browser_hover",
    "browser_press",
];

const TRANSFER_PATTERNS: &[&str] = &[
    "upload",
    "download",
    "save_file",
    "clipboard",
    "drag_drop",
    "drag_and_drop",
];

const PRIVILEGED_PATTERNS: &[&str] = &[
    "evaluate_script",
    "execute_script",
    "raw_cdp",
    "cdp_",
    "cookies",
    "storage",
    "auth_header",
    "intercept",
    "mock_network",
    "manage_extension",
    "manage_profile",
    "manage_session",
    "browser_evaluate",
    "browser_cookies",
    "browser_storage",
];

const VOLATILE_FIELDS: &[&str] = &[
    "cursor",
    "duration",
    "height",
    "offsetX",
    "offsetY",
    "pageId",
    "requestId",
    "scrollX",
    "scrollY",
    "selector",
    "tabId",
    "timeout",
    "traceId",
    "viewport",
    "waitUntil",
    "width",
];

const SENSITIVE_COOKIE_PATTERNS: &[&str] = &["cookie", "cookies"];

const SENSITIVE_STORAGE_PATTERNS: &[&str] = &[
    "storage",
    "local_storage",
    "session_storage",
    "localstorage",
    "sessionstorage",
];

const SENSITIVE_AUTH_PATTERNS: &[&str] =
    &["auth_header", "authorization", "auth_token", "authtoken"];

const SENSITIVE_CDP_PATTERNS: &[&str] = &["cdp", "chrome_devtools_protocol", "raw_cdp"];

const SENSITIVE_SCRIPT_EVAL_PATTERNS: &[&str] = &["eval", "script", "javascript", "expression"];

const SENSITIVE_UPLOAD_PATTERNS: &[&str] = &["upload", "file_input", "file_path", "filepath"];

const SENSITIVE_DOWNLOAD_PATTERNS: &[&str] = &[
    "download",
    "save_path",
    "savepath",
    "download_path",
    "downloadpath",
];

const SENSITIVE_CLIPBOARD_PATTERNS: &[&str] = &["clipboard"];

const SENSITIVE_PASSWORD_PATTERNS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "credential",
    "api_key",
    "apikey",
    "access_token",
    "accesstoken",
];

const SENSITIVE_INTERCEPT_PATTERNS: &[&str] = &["intercept", "mock_network", "route_intercept"];

const URL_ARGUMENT_KEYS: &[&str] = &[
    "url", "href", "target", "uri", "pageUrl", "page_url", "website",
];

const REDACT_QUERY_KEYS: &[&str] = &[
    "accesstoken",
    "apikey",
    "auth",
    "authorization",
    "code",
    "credential",
    "guardtoken",
    "key",
    "passwd",
    "password",
    "refreshtoken",
    "secret",
    "session",
    "token",
];

const BROWSER_SERVER_NAME_PATTERNS: &[&str] = &[
    "chrome[\\-_\\s\\x{001c}-\\x{001f}]?devtools",
    "@playwright/mcp",
    "playwright[\\-_\\s\\x{001c}-\\x{001f}]?mcp",
    "browser[\\-_\\s\\x{001c}-\\x{001f}]?tools",
    "browser[\\-_\\s\\x{001c}-\\x{001f}]?mcp",
    "puppeteer[\\-_\\s\\x{001c}-\\x{001f}]?mcp",
    "web[\\-_\\s\\x{001c}-\\x{001f}]?browser",
];

const BROWSER_PACKAGE_PATTERNS: &[&str] = &[
    "@modelcontextprotocol/server-chrome-devtools",
    "@playwright/mcp",
    "puppeteer",
    "playwright",
];

const ISOLATED_FLAGS: &[&str] = &["--isolated", "--isolated-context"];

const PROFILE_DIR_FLAGS: &[&str] = &[
    "--user-data-dir",
    "--persistent",
    "--profile-dir",
    "--storage-state",
];

const REMOTE_DEBUG_FLAGS: &[&str] = &[
    "--remote-debugging-port",
    "--remote-debugging-pipe",
    "--ws-endpoint",
];
