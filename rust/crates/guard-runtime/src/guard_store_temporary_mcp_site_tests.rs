//! Site grants (BP-T060) over the recorded approval schema: a grant covers the
//! pending routine requests of the same driver identity on the same site, and
//! no request of another site, another driver or an unprofiled tool.

use serde_json::json;

use super::{covered, grant, pending, store_of, CATEGORY, SERVER};

fn site_intent(driver: Option<char>, origin: &str, intent: &str, category: &str) -> String {
    let mut filed = json!({
        "mcp_server_identity_hash": SERVER,
        "mcp_server_name": "browser",
        "intent": intent,
        "risk_categories": [category],
        "target_origin": origin,
    });
    if let Some(seed) = driver {
        filed["driver_identity_hash"] = json!(seed.to_string().repeat(64));
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
            navigate(Some('d'), shop),
        ),
        (
            "s-other-tool",
            "codex",
            "require-reapproval",
            site_intent(Some('d'), shop, "browser.inspect", "browser_inspection"),
        ),
        (
            "s-other-site",
            "codex",
            "require-reapproval",
            navigate(Some('d'), "https://mail.example.test"),
        ),
        (
            "s-schema-changed",
            "codex",
            "require-reapproval",
            navigate(Some('e'), shop),
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
    let home = store_of("site", requests());
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
    let home = store_of("site-category", requests());
    let reply = grant(&home, "s-source", "site-category").unwrap();
    assert_eq!(covered(&reply), Vec::<String>::new());
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_site_grant_from_a_request_without_a_site_scope_covers_nothing_else() {
    let home = store_of("site-unscoped", requests());
    let reply = grant(&home, "s-unprofiled", "site").unwrap();
    assert_eq!(covered(&reply), Vec::<String>::new());
    let _ = std::fs::remove_dir_all(&home);
}

/// BP-T061: a navigation on the shop in session `session`, with `risks` and
/// any extra filed fields.
fn session_intent(session: char, risks: &[&str], extra: serde_json::Value) -> String {
    let mut filed = json!({
        "mcp_server_identity_hash": SERVER,
        "mcp_server_name": "browser",
        "intent": "browser.navigation",
        "risk_categories": risks,
        "target_origin": "https://shop.example.test",
        "driver_identity_hash": "d".repeat(64),
        "session_ref_digest": session.to_string().repeat(64),
    });
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
    let home = store_of("session-site", session_requests());
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
    let home = store_of("site-surface", session_requests());
    let reply = grant(&home, "x-source", "site").unwrap();
    assert_eq!(covered(&reply), ["x-other-session"]);
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_legacy_grant_still_covers_only_routine_calls() {
    let home = store_of("legacy-surface", session_requests());
    let reply = grant(&home, "x-source", "server").unwrap();
    // The legacy targets keep today's rule: risks only, no surface check.
    assert_eq!(covered(&reply), ["x-other-session", "x-secret-input"]);
    let _ = std::fs::remove_dir_all(&home);
}
