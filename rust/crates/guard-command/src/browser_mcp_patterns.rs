// Generic browser operation, surface, and redaction tables. The Chrome DevTools MCP and
// Playwright MCP tool lists and launch flags live in first-party driver profiles.
// Regex whitespace includes CPython's additional U+001C–U+001F characters.

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
