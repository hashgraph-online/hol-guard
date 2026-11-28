//! Site grants (BP-T060) over the recorded approval schema: a grant covers the
//! pending routine requests of the same driver identity on the same site, and
//! no request of another site, another driver or an unprofiled tool. The
//! source's identity must also be the driver's current one in the ledger
//! (BP-T065).

use std::path::Path;

use serde_json::{json, Value};

use super::{covered, grant, pending, store_of, CATEGORY, SERVER};
use crate::browser_grant_scope::driver_identity_hash;

const SCHEMA: &str = "schema-text-example";

/// A filed playwright call of `tool`, before any driver identity is added.
fn call(tool: &str, schema: &str) -> Value {
    json!({
        "mcp_server_identity_hash": SERVER,
        "mcp_server_name": "playwright",
        "mcp_tool_name": tool,
        "mcp_schema_hash": schema,
    })
}

/// Records `tool` with `schema` in the ledger under `home`, as filing does,
/// and returns the hash its grants are filed under.
fn record(home: &Path, tool: &str, schema: &str) -> String {
    driver_identity_hash(home, &call(tool, schema)).expect("profiled tool")
}

/// The hash the ledger of a fresh store files the driver's grants under.
fn current() -> String {
    let scratch = tempfile::tempdir().expect("scratch home");
    record(scratch.path(), "browser_navigate", SCHEMA)
}

/// The store for `requests`, with the ledger holding the tools they name.
fn seeded(
    label: &str,
    requests: Vec<(&'static str, &'static str, &'static str, String)>,
) -> std::path::PathBuf {
    let home = store_of(label, requests);
    for tool in ["browser_navigate", "browser_snapshot"] {
        assert_eq!(record(&home, tool, SCHEMA), current());
    }
    home
}

fn site_intent(driver: Option<String>, origin: &str, intent: &str, category: &str) -> String {
    let tool = if intent == "browser.inspect" {
        "browser_snapshot"
    } else {
        "browser_navigate"
    };
    let mut filed = call(tool, SCHEMA);
    filed["intent"] = json!(intent);
    filed["risk_categories"] = json!([category]);
    filed["target_origin"] = json!(origin);
    if let Some(hash) = driver {
        filed["driver_identity_hash"] = json!(hash);
    }
    filed.to_string()
}

fn requests() -> Vec<(&'static str, &'static str, &'static str, String)> {
    let shop = "https://shop.example.test";
    let navigate = |driver, origin| site_intent(driver, origin, "browser.navigation", CATEGORY);
    vec![
        (
            "s-source",
            "codex",
            "require-reapproval",
            navigate(Some(current()), shop),
        ),
        (
            "s-other-tool",
            "codex",
            "require-reapproval",
            site_intent(
                Some(current()),
                shop,
                "browser.inspect",
                "browser_inspection",
            ),
        ),
        (
            "s-other-site",
            "codex",
            "require-reapproval",
            navigate(Some(current()), "https://mail.example.test"),
        ),
        (
            "s-schema-changed",
            "codex",
            "require-reapproval",
            navigate(Some("e".repeat(64)), shop),
        ),
        (
            "s-unprofiled",
            "codex",
            "require-reapproval",
            navigate(None, shop),
        ),
    ]
}

#[test]
fn a_site_grant_covers_another_profiled_tool_of_the_driver_on_that_site() {
    let home = seeded("site", requests());
    let reply = grant(&home, "s-source", "site").unwrap();
    assert_eq!(reply["result"]["resolved"], json!(true));
    assert_eq!(covered(&reply), ["s-other-tool"]);
    // Another site, a driver whose identity hash changed with its schema, and
    // a tool the profile does not map stay pending.
    assert_eq!(
        pending(&home),
        ["s-other-site", "s-schema-changed", "s-unprofiled"]
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_site_category_grant_leaves_other_categories_on_the_site_pending() {
    let home = seeded("site-category", requests());
    let reply = grant(&home, "s-source", "site-category").unwrap();
    assert_eq!(covered(&reply), Vec::<String>::new());
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_site_grant_from_a_request_without_a_site_scope_covers_nothing_else() {
    let home = seeded("site-unscoped", requests());
    let reply = grant(&home, "s-unprofiled", "site").unwrap();
    assert_eq!(covered(&reply), Vec::<String>::new());
    let _ = std::fs::remove_dir_all(&home);
}

/// BP-T061: a navigation on the shop in session `session`, with `risks` and
/// any extra filed fields.
fn session_intent(session: char, risks: &[&str], extra: Value) -> String {
    let mut filed = call("browser_navigate", SCHEMA);
    filed["intent"] = json!("browser.navigation");
    filed["risk_categories"] = json!(risks);
    filed["target_origin"] = json!("https://shop.example.test");
    filed["driver_identity_hash"] = json!(current());
    filed["session_ref_digest"] = json!(session.to_string().repeat(64));
    for (key, value) in extra.as_object().expect("extra") {
        filed[key] = value.clone();
    }
    filed.to_string()
}

fn session_requests() -> Vec<(&'static str, &'static str, &'static str, String)> {
    let shared = [CATEGORY, "browser_shared_profile"];
    let row = |id, intent| (id, "codex", "require-reapproval", intent);
    vec![
        row("x-source", session_intent('5', &[CATEGORY], json!({}))),
        row("x-shared", session_intent('5', &shared, json!({}))),
        row(
            "x-shared-password",
            session_intent('5', &shared, json!({"element": {"is_password": true}})),
        ),
        row(
            "x-shared-transfer",
            session_intent(
                '5',
                &[CATEGORY, "browser_shared_profile", "browser_transfer"],
                json!({}),
            ),
        ),
        row(
            "x-secret-input",
            session_intent(
                '5',
                &[CATEGORY],
                json!({"input": {"preview_class": "looks_like_secret"}}),
            ),
        ),
        row(
            "x-other-session",
            session_intent('6', &[CATEGORY], json!({})),
        ),
    ]
}

#[test]
fn a_session_site_grant_covers_a_clean_shared_profile_call_in_that_session() {
    let home = seeded("session-site", session_requests());
    let reply = grant(&home, "x-source", "session-site").unwrap();
    assert_eq!(covered(&reply), ["x-shared"]);
    assert_eq!(
        pending(&home),
        [
            "x-other-session",
            "x-secret-input",
            "x-shared-password",
            "x-shared-transfer"
        ]
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_site_grant_never_covers_a_shared_profile_call_or_an_unclean_surface() {
    let home = seeded("site-surface", session_requests());
    let reply = grant(&home, "x-source", "site").unwrap();
    assert_eq!(covered(&reply), ["x-other-session"]);
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_legacy_grant_still_covers_only_routine_calls() {
    let home = seeded("legacy-surface", session_requests());
    let reply = grant(&home, "x-source", "server").unwrap();
    // The legacy targets keep today's rule: risks only, no surface check.
    assert_eq!(covered(&reply), ["x-other-session", "x-secret-input"]);
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_site_grant_filed_under_a_retired_driver_identity_covers_nothing_else() {
    let home = seeded("site-retired", requests());
    // A changed schema for a seen tool moves the driver to a new identity.
    assert_ne!(
        record(&home, "browser_snapshot", "schema-text-changed"),
        current()
    );
    let reply = grant(&home, "s-source", "site").unwrap();
    assert_eq!(reply["result"]["resolved"], json!(true));
    assert_eq!(covered(&reply), Vec::<String>::new());
    let _ = std::fs::remove_dir_all(&home);
}
