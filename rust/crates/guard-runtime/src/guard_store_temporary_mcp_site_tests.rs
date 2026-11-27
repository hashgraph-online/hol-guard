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
