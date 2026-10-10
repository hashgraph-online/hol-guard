//! Static daemon route tables: which URL paths need a header token, which a
//! dashboard session may reach, and which supply-chain action a path names.
//!
//! Every function takes the URL path (query string removed) and derives the
//! non-empty `/`-separated segments itself, so the transport cannot disagree
//! with the policy about how a path splits.

const REMOTE_REVIEW_POST_ROUTES: &[&str] = &[
    "/v1/command-queue/worker/refresh",
    "/v1/requests/bulk-allow-once",
];

const EXTENSION_CONTROL_PATHS: &[&str] = &[
    "/v1/extension-controls/preview",
    "/v1/extension-controls/test",
    "/v1/extension-controls/inspect",
    "/v1/extension-controls/apply",
    "/v1/extension-controls/refresh",
    "/v1/extension-controls/recover-authority",
    "/v1/extension-controls/acknowledge-degraded",
];

const LOCAL_CLI_PATHS: &[&str] = &[
    "/v1/local-clis/preview",
    "/v1/local-clis/apply",
    "/v1/local-clis/recognize",
    "/v1/local-clis/discover",
    "/v1/local-clis/forget",
    "/v1/local-clis/provider-actions",
    "/v1/local-clis/provider-workflows",
    "/v1/local-clis/registry-search",
    "/v1/local-clis/registry-setup",
    "/v1/local-clis/refresh-job",
    "/v1/local-clis/skills",
    "/v1/local-clis/mcp-skills",
];

const HEADLESS_APP_ACTIONS: &[&str] = &["connect", "repair", "disconnect", "status", "test"];
const HARNESS_ACTIONS: &[&str] = &["install", "verify", "repair", "uninstall"];

const TOKEN_REQUIRED_PATHS: &[&str] = &[
    "/v1/cloud-review",
    "/v1/clients/attach",
    "/v1/clients/heartbeat",
    "/v1/sessions/start",
    "/v1/operations/start",
    "/v1/connect/requests",
    "/v1/connect/result",
    "/v1/operations/block",
    "/v1/policy/decisions",
    "/v1/policy/resolve",
    "/v1/policy/claim",
    "/v1/policy/cloud-exceptions",
    "/v1/policy/cloud-exception-requests",
    "/v1/policy/clear",
    "/v1/policy/sync",
    "/v1/requests/clear",
    "/v1/settings",
    "/v1/settings/import",
    "/v1/settings/reset",
    "/v1/approval-gate/cooldown/revoke",
    "/v1/approval-gate/totp/enroll",
    "/v1/approval-gate/totp/verify",
    "/v1/approval-gate/totp/disable",
    "/v1/daemon/repair",
    "/v1/protection/repair",
    "/v1/protection/repair/approval-gate/setup",
    "/v1/insights/share",
    "/v1/cloud/connect",
    "/v1/notifications/setup",
    "/v1/update",
    "/v1/update/channel",
    "/v1/update/reconnect/prepare",
    "/v1/command-activity/feedback",
];

const HOSTED_API_PATHS: &[&str] = &[
    "/v1/capabilities",
    "/v1/connect/complete",
    "/v1/inventory",
    "/v1/connect/state",
    "/v1/daemon/repair",
    "/v1/evidence",
    "/v1/evidence/export",
    "/v1/command-activity",
    "/v1/command-activity/analytics",
    "/v1/command-activity/diagnostics",
    "/v1/command-activity/events",
    "/v1/command-activity/feedback",
    "/v1/command-extensions",
    "/v1/extension-controls/catalog",
    "/v1/extension-controls/effective",
    "/v1/extension-controls/history",
    "/v1/local-clis",
    "/v1/harnesses",
    "/v1/notifications/setup",
    "/v1/policy",
    "/v1/policy/cloud-exceptions",
    "/v1/policy/cloud-exception-requests",
    "/v1/policy/clear",
    "/v1/receipts",
    "/v1/receipts/analytics",
    "/v1/insights/share",
    "/v1/cloud/connect",
    "/v1/supply-chain/package-shims/connect",
    "/v1/supply-chain/package-shims/activate",
    "/v1/receipts/latest",
    "/v1/runtime",
    "/v1/settings",
    "/v1/protection/repair/approval-gate/setup",
    "/v1/settings/export",
    "/v1/settings/import",
    "/v1/settings/reset",
    "/v1/read-state",
    "/v1/update",
    "/v1/update/channel",
    "/v1/update/reconnect/challenge",
    "/v1/update/reconnect/prepare",
    "/v1/update/reconnect/verify",
    "/v1/update/status",
];

const LOCAL_SURFACE_PATHS: &[&str] = &[
    "/v1/cloud-review",
    "/v1/capabilities",
    "/v1/sessions",
    "/v1/runtime",
    "/v1/harnesses",
    "/v1/inventory",
    "/v1/settings",
    "/v1/settings/export",
    "/v1/events",
    "/v1/events/stream",
    "/v1/command-activity",
    "/v1/command-activity/analytics",
    "/v1/command-activity/diagnostics",
    "/v1/command-activity/events",
    "/v1/command-activity/feedback",
    "/v1/command-extensions",
    "/v1/requests",
    "/v1/receipts",
    "/v1/receipts/analytics",
    "/v1/insights/share",
    "/v1/cloud/connect",
    "/v1/receipts/latest",
    "/v1/policy",
    "/v1/policy/cloud-exceptions",
    "/v1/evidence",
    "/v1/evidence/export",
    "/v1/clients/attach",
    "/v1/clients/heartbeat",
    "/v1/sessions/start",
    "/v1/operations/start",
    "/v1/operations/block",
    "/v1/policy/sync",
    "/v1/requests/clear",
    "/v1/settings/import",
    "/v1/settings/reset",
    "/v1/read-state",
    "/v1/policy/clear",
    "/v1/approval-gate/cooldown/revoke",
    "/v1/approval-gate/totp/enroll",
    "/v1/approval-gate/totp/verify",
    "/v1/approval-gate/totp/disable",
    "/v1/daemon/repair",
    "/v1/protection/repair",
    "/v1/notifications/setup",
    "/v1/update/status",
    "/v1/update/channel",
    "/v1/update/reconnect/prepare",
];

/// The non-empty `/`-separated segments of a URL path.
pub(crate) fn segments(path: &str) -> Vec<&str> {
    path.split('/').filter(|part| !part.is_empty()).collect()
}

fn starts_with(parts: &[&str], prefix: &[&str]) -> bool {
    parts.len() >= prefix.len() && parts[..prefix.len()] == *prefix
}

/// `extension_control`, `local_cli` or `none`.
pub(crate) fn route_class(path: &str) -> &'static str {
    if EXTENSION_CONTROL_PATHS.contains(&path) {
        "extension_control"
    } else if LOCAL_CLI_PATHS.contains(&path) {
        "local_cli"
    } else {
        "none"
    }
}

pub(crate) fn requires_header_token(path: &str) -> bool {
    let parts = segments(path);
    if TOKEN_REQUIRED_PATHS.contains(&path) || REMOTE_REVIEW_POST_ROUTES.contains(&path) {
        return true;
    }
    let n = parts.len();
    (n >= 3 && starts_with(&parts, &["v1", "hooks"]))
        || (n == 3
            && starts_with(&parts, &["v1", "apps"])
            && HEADLESS_APP_ACTIONS.contains(&parts[2]))
        || (n >= 2 && starts_with(&parts, &["v1", "supply-chain"]))
        || (n == 4 && starts_with(&parts, &["v1", "audit", "remediations"]))
        || (n == 4
            && starts_with(&parts, &["v1", "operations"])
            && matches!(parts[3], "items" | "status"))
        || (n == 4
            && starts_with(&parts, &["v1", "requests"])
            && matches!(parts[3], "approve" | "block" | "resume" | "live-decision"))
        || (n == 4
            && starts_with(&parts, &["v1", "harnesses"])
            && HARNESS_ACTIONS.contains(&parts[3]))
        || (n == 5 && starts_with(&parts, &["v1", "apps"]) && parts[3..] == ["cloud", "start"])
        || (n == 3 && parts[0] == "approvals" && parts[2] == "decision")
        || (n == 4 && starts_with(&parts, &["v1", "approvals"]) && parts[3] == "decision")
        || (n == 5
            && starts_with(&parts, &["v1", "mcp-policy", "requests"])
            && parts[4] == "decision")
}

pub(crate) fn hosted_dashboard_api_path(path: &str) -> bool {
    if HOSTED_API_PATHS.contains(&path)
        || (EXTENSION_CONTROL_PATHS.contains(&path) && path != "/v1/extension-controls/inspect")
        || LOCAL_CLI_PATHS.contains(&path)
    {
        return true;
    }
    let parts = segments(path);
    let n = parts.len();
    (n == 3 && starts_with(&parts, &["v1", "receipts"]))
        || (n >= 4 && starts_with(&parts, &["v2", "extension-controls", "catalog"]))
        || (n == 4 && starts_with(&parts, &["v1", "audit", "remediations"]))
        || (n == 4 && starts_with(&parts, &["v1", "approvals"]) && parts[3] == "decision")
        || (n == 5
            && starts_with(&parts, &["v1", "apps"])
            && parts[3] == "cloud"
            && parts[4] == "start")
        || (n == 4
            && starts_with(&parts, &["v1", "harnesses"])
            && HARNESS_ACTIONS.contains(&parts[3]))
        || (n == 4 && starts_with(&parts, &["v1", "artifacts"]) && parts[3] == "diff")
}

pub(crate) fn local_surface_session_allowed(method: &str, path: &str) -> bool {
    if LOCAL_SURFACE_PATHS.contains(&path) || REMOTE_REVIEW_POST_ROUTES.contains(&path) {
        return true;
    }
    let parts = segments(path);
    let n = parts.len();
    if (n == 3 && starts_with(&parts, &["v1", "apps"]) && HEADLESS_APP_ACTIONS.contains(&parts[2]))
        || (n >= 2 && starts_with(&parts, &["v1", "supply-chain"]))
    {
        return true;
    }
    match method {
        "GET" => {
            (n == 4 && starts_with(&parts, &["v1", "requests"]) && parts[3] == "business-summary")
                || (n == 4 && starts_with(&parts, &["v1", "mcp-policy", "requests"]))
                || (n == 3
                    && (starts_with(&parts, &["v1", "requests"])
                        || starts_with(&parts, &["v1", "receipts"])
                        || starts_with(&parts, &["v1", "operations"])))
                || (n == 4 && starts_with(&parts, &["v1", "sessions"]) && parts[3] == "resume")
        }
        "POST" => {
            (n == 5
                && starts_with(&parts, &["v1", "mcp-policy", "requests"])
                && parts[4] == "decision")
                || path == "/v1/update"
                || (n == 4
                    && starts_with(&parts, &["v1", "requests"])
                    && matches!(parts[3], "approve" | "block" | "resume"))
                || (n == 4
                    && starts_with(&parts, &["v1", "operations"])
                    && matches!(parts[3], "items" | "status"))
        }
        _ => false,
    }
}

pub(crate) fn protection_repair_session_allowed(method: &str, path: &str) -> bool {
    match method {
        "GET" => matches!(
            path,
            "/v1/runtime"
                | "/v1/settings"
                | "/v1/extension-controls/effective"
                | "/v1/update/status"
        ),
        "POST" => matches!(
            path,
            "/v1/initialize" | "/v1/extension-controls/recover-authority"
        ),
        _ => false,
    }
}

pub(crate) fn session_path(method: &str, path: &str) -> bool {
    hosted_dashboard_api_path(path) || local_surface_session_allowed(method, path)
}

/// The supply-chain action a path names, for claim scoping.
pub(crate) fn supply_chain_claim_action(path: &str) -> Option<String> {
    match path {
        "/v1/supply-chain/package-shims" => return Some("package_shims_status".to_owned()),
        "/v1/supply-chain/entitlement" => return Some("supply_chain_entitlement".to_owned()),
        "/v1/supply-chain/bundle" => return Some("supply_chain_bundle".to_owned()),
        "/v1/supply-chain/repair" => return Some("package_shims_repair_all".to_owned()),
        _ => {}
    }
    let parts = segments(path);
    if parts.len() == 4 && starts_with(&parts, &["v1", "supply-chain", "package-shims"]) {
        let action = if parts[3] == "uninstall" {
            "remove"
        } else {
            parts[3]
        };
        if matches!(
            action,
            "activate" | "install" | "repair" | "test" | "remove" | "open-shell"
        ) {
            return Some(format!("package_shims_{action}"));
        }
    }
    if parts.len() == 3
        && starts_with(&parts, &["v1", "supply-chain"])
        && matches!(parts[2], "audit" | "sync")
    {
        return Some(format!("package_shims_{}", parts[2]));
    }
    None
}
