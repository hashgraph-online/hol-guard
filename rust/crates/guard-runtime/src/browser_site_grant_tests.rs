use serde_json::json;

use super::*;

fn digest(seed: char) -> String {
    seed.to_string().repeat(64)
}

fn scope(origin: &str) -> SiteScope {
    site_scope(&json!({
        "driver_identity_hash": digest('d'),
        "target_origin": origin,
        "site_group": "example.test",
        "session_ref_digest": digest('5'),
    }))
    .expect("scope")
}

#[test]
fn an_intent_without_a_driver_identity_or_origin_has_no_site_scope() {
    let missing_driver = json!({"target_origin": "https://shop.example.test"});
    let bad_driver = json!({"driver_identity_hash": "abc", "target_origin": "https://a.test"});
    let missing_origin = json!({"driver_identity_hash": digest('d')});
    for intent in [missing_driver, bad_driver, missing_origin, json!("text")] {
        assert_eq!(site_scope(&intent), None, "{intent}");
    }
}

#[test]
fn only_the_named_parts_of_a_scope_are_offered() {
    let full = scope("https://shop.example.test");
    assert_eq!(site_targets(&full), SITE_TARGETS.to_vec());
    let bare = site_scope(&json!({
        "driver_identity_hash": digest('d'),
        "target_origin": "https://shop.example.test",
    }))
    .expect("scope");
    assert_eq!(site_targets(&bare), ["site-category", "site"]);
    assert_eq!(
        site_selector(&bare, "site-group", "browser_navigation"),
        None
    );
    assert_eq!(
        site_selector(&bare, "session-site", "browser_navigation"),
        None
    );
}

#[test]
fn selectors_follow_prd_5_5() {
    let site = scope("https://shop.example.test");
    let (driver, origin) = (&site.driver_identity_hash, &site.origin_digest);
    let group = site.site_group_digest.clone().expect("group");
    let session = site.session_ref_digest.clone().expect("session");
    let selector = |target| site_selector(&site, target, "browser_interaction").expect("selector");
    assert_eq!(
        selector("site-category"),
        format!("browser-grant:v2:{driver}:site:{origin}:category:browser_interaction")
    );
    assert_eq!(
        selector("site"),
        format!("browser-grant:v2:{driver}:site:{origin}")
    );
    assert_eq!(
        selector("site-group"),
        format!("browser-grant:v2:{driver}:group:{group}")
    );
    assert_eq!(
        selector("session-site"),
        format!("browser-grant:v2:{driver}:session:{session}:site:{origin}")
    );
    assert_eq!(site_selector(&site, "server", "browser_interaction"), None);
}

#[test]
fn a_site_grant_covers_other_profiled_tools_of_the_driver_on_that_site_only() {
    let granted = scope("https://shop.example.test");
    let interact = (&granted, "browser_interaction");
    let same_site_other_tool = scope("https://shop.example.test");
    let other_site = scope("https://mail.example.test");
    let mut other_driver = scope("https://shop.example.test");
    other_driver.driver_identity_hash = digest('e');
    let mut other_session = scope("https://shop.example.test");
    other_session.session_ref_digest = Some(digest('7'));

    let navigate = (&same_site_other_tool, "browser_navigation");
    assert!(site_covers("site", interact, navigate));
    assert!(!site_covers("site-category", interact, navigate));
    assert!(site_covers(
        "site-category",
        interact,
        (&same_site_other_tool, "browser_interaction")
    ));
    assert!(!site_covers(
        "site",
        interact,
        (&other_site, "browser_interaction")
    ));
    assert!(site_covers(
        "site-group",
        interact,
        (&other_site, "browser_interaction")
    ));
    assert!(site_covers("session-site", interact, navigate));
    assert!(!site_covers(
        "session-site",
        interact,
        (&other_session, "browser_navigation")
    ));
    for target in SITE_TARGETS {
        // Another driver identity, including the same driver after its hash
        // changed, is never covered.
        assert!(!site_covers(
            target,
            interact,
            (&other_driver, "browser_interaction")
        ));
        assert!(!site_covers("server", interact, navigate));
    }
}
