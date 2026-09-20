"""Default limits and route policy constants for the Guard daemon."""

_AUDIT_REMEDIATION_ACTIONS = {"package_shim_path"}
_REMOTE_REVIEW_POST_ROUTES = {
    "/v1/command-queue/worker/refresh",
    "/v1/requests/bulk-allow-once",
}
_SUPPLY_CHAIN_PACKAGE_ACTIONS = {
    "activate",
    "install",
    "repair",
    "test",
    "audit",
    "sync",
    "remove",
    "uninstall",
    "connect",
    "open-shell",
}
_SUPPLY_CHAIN_CONNECT_POLL_AFTER_MS = 1_500
_SUPPLY_CHAIN_CONNECT_WAIT_TIMEOUT_SECONDS = 180
_LOCAL_DASHBOARD_SESSION_REFRESH_GRACE_SECONDS = 7 * 24 * 60 * 60
_DEFAULT_HEADLESS_CLOUD_SYNC_INTERVAL_SECONDS = 30.0
_DEFAULT_HEADLESS_CLOUD_SYNC_BACKOFF_SECONDS = 10.0
_EXTENSION_CONTROL_PATHS = frozenset(
    {
        "/v1/extension-controls/preview",
        "/v1/extension-controls/test",
        "/v1/extension-controls/apply",
        "/v1/extension-controls/refresh",
        "/v1/extension-controls/recover-authority",
        "/v1/extension-controls/acknowledge-degraded",
    }
)
_LOCAL_CLI_PATHS = frozenset(
    {
        "/v1/local-clis/preview",
        "/v1/local-clis/apply",
        "/v1/local-clis/recognize",
        "/v1/local-clis/discover",
    }
)
_MAX_CONCURRENT_DAEMON_REQUESTS = 32
_MAX_CONCURRENT_DAEMON_CONTROL_REQUESTS = 8
_MAX_CONCURRENT_DAEMON_CRITICAL_REQUESTS = 8
_MAX_CONCURRENT_DAEMON_CONNECTIONS = 128
_AUTH_AUDIT_COALESCE_SECONDS = 60.0
_AUTH_AUDIT_KEY_LIMIT = 64
_AUTH_AUDIT_SQLITE_TIMEOUT_SECONDS = 0.25
_MAX_CONCURRENT_RUNTIME_HOOKS = 32
_MAX_CONCURRENT_RUNTIME_HOOKS_PER_HARNESS = 24
_RUNTIME_HOOK_ADMISSION_TIMEOUT_SECONDS = 3.0
_RUNTIME_HOOK_PROCESS_TIMEOUT_SECONDS = 1.45
_RUNTIME_POST_HOOK_PROCESS_TIMEOUT_SECONDS = 2.75
_DAEMON_REQUEST_READ_TIMEOUT_SECONDS = 0.4
_DAEMON_SERVE_THREAD_START_TIMEOUT_SECONDS = 5.0
_DAEMON_CONNECTION_ADMISSION_WAIT_SECONDS = 0.05
_DAEMON_CONTROL_ADMISSION_WAIT_SECONDS = 1.0
_DAEMON_UNCLASSIFIED_WATCHDOG_POLL_SECONDS = 0.025
_AIBOM_REFRESH_STOP_JOIN_TIMEOUT_SECONDS = 5.0
_DAEMON_CONTROL_PATHS = frozenset(
    {
        "/v1/healthz/details",
        "/v1/healthz/verify",
    }
)
_DAEMON_CRITICAL_PATHS = frozenset(
    {
        "/healthz",
        "/v1/daemon/identity-challenge",
    }
)
_PEER_DISCONNECT_ERRORS = (BrokenPipeError, ConnectionResetError, ConnectionAbortedError)
_DASHBOARD_CSP = "; ".join(
    (
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: https:",
        "font-src 'self' data:",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "frame-ancestors 'none'",
        "form-action 'self'",
    )
)
_ROOT_STATIC_FILES = {
    "/favicon.svg",
    "/favicon.ico",
    "/favicon-16x16.png",
    "/favicon-32x32.png",
}
_RUNTIME_HOOK_ENV_ALLOWLIST = frozenset(
    {
        "HOL_GUARD_MANAGED_CURSOR_HOOK",
        "HOL_GUARD_CURSOR_APPROVAL_BINDING",
        "HOL_GUARD_CURSOR_AFTER_SHELL_PROOF",
        "CURSOR_PROJECT_DIR",
        "CURSOR_VERSION",
        "CURSOR_TRACE_ID",
        "CURSOR_SESSION_ID",
        "CURSOR_TRANSCRIPT_PATH",
    }
)
_DEFAULT_SUPPLY_CHAIN_REFRESH_BACKOFF_SECONDS = 60.0
_DEFAULT_SUPPLY_CHAIN_REFRESH_INTERVAL_SECONDS = 15 * 60.0
_EPHEMERAL_GUARD_DAEMON_IDLE_TIMEOUT_SECONDS = 5
_GUARD_DAEMON_IDLE_POLL_INTERVAL_SECONDS = 0.5
_HOSTED_GUARD_DASHBOARD_ORIGINS = frozenset({"https://hol.org", "https://www.hol.org"})
_HEADLESS_APP_ACTIONS = {
    "connect": ("install", "install"),
    "repair": ("repair", "repair"),
    "disconnect": ("remove", "uninstall"),
    "status": ("status", "verify"),
    "test": ("scan", "verify"),
}
_CLOUD_APP_DASHBOARD_SESSION_ACTIONS = {
    "connect": frozenset({"connect", "status", "test"}),
    "repair": frozenset({"repair", "status", "test"}),
    "status": frozenset({"status"}),
    "test": frozenset({"status", "test"}),
}
_HEADLESS_OPERATIONS = ("install", "repair", "remove", "status", "scan", "policy_sync")
_PROTECTION_REPAIR_PROBE_COMMAND = "git status --porcelain=v1"
_HARNESS_RETRY_COPY: dict[str, str] = {
    "codex": "Return to Codex and retry",
    "claude-code": "Return to Claude and retry",
    "opencode": "Return to OpenCode and retry",
    "copilot": "Return to Copilot and retry",
    "pi": "Return to Pi and retry",
    "omp": "Return to Oh My Pi and retry",
}
_DEFAULT_RETRY_COPY = "Return to your AI assistant and retry"
