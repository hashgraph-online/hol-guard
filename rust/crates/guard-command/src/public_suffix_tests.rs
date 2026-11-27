use super::*;

fn group(host: &str) -> Option<String> {
    registrable_domain(host)
}

#[test]
fn the_embedded_snapshot_decodes() {
    assert!(public_suffix_available());
    assert!(!public_suffix_version().is_empty());
}

#[test]
fn a_host_under_an_unlisted_suffix_groups_on_the_last_two_labels() {
    assert_eq!(
        group("storefront.example-org.test").as_deref(),
        Some("example-org.test")
    );
    assert_eq!(
        group("example-org.test").as_deref(),
        Some("example-org.test")
    );
}

#[test]
fn a_multi_label_suffix_keeps_one_more_label() {
    assert_eq!(
        group("shop.example-org.co.uk").as_deref(),
        Some("example-org.co.uk")
    );
    assert_eq!(
        group("example-org.co.uk").as_deref(),
        Some("example-org.co.uk")
    );
}

#[test]
fn a_host_that_is_a_public_suffix_has_no_group() {
    assert_eq!(group("co.uk"), None);
    assert_eq!(group("uk"), None);
}

#[test]
fn wildcard_and_exception_rules_apply() {
    // `*.ck` makes every second-level name a suffix, `!www.ck` exempts one.
    assert_eq!(group("example-org.ck"), None);
    assert_eq!(
        group("shop.example-org.ck").as_deref(),
        Some("shop.example-org.ck")
    );
    assert_eq!(group("www.ck").as_deref(), Some("www.ck"));
    assert_eq!(group("a.www.ck").as_deref(), Some("www.ck"));
    assert_eq!(
        group("shop.city.kawasaki.jp").as_deref(),
        Some("city.kawasaki.jp")
    );
    assert_eq!(group("example-org.kawasaki.jp"), None);
}

#[test]
fn unicode_rules_are_matched_in_punycode() {
    // `公司.cn` is stored as its ASCII form, which is how URL hosts arrive.
    let suffix = idna::domain_to_ascii("公司.cn").unwrap();
    assert_eq!(group(&suffix), None);
    assert_eq!(
        group(&format!("example-org.{suffix}")),
        Some(format!("example-org.{suffix}"))
    );
}

#[test]
fn hosts_guard_does_not_group() {
    for host in [
        "",
        "localhost",
        "127.0.0.1",
        "[::1]",
        "example..test",
        ".example.test",
        "shop example.test",
        "shöp.example.test",
        "shop.-example.test",
        "shop.example-.test",
        "example.test-",
    ] {
        assert_eq!(group(host), None, "{host:?}");
    }
    assert_eq!(group(&format!("{}.test", "a".repeat(260))), None);
    assert_eq!(group(&format!("{}.test", "a".repeat(64))), None);
    let longest_label = "a".repeat(63);
    assert_eq!(
        group(&format!("{longest_label}.test")),
        Some(format!("{longest_label}.test"))
    );
}

#[test]
fn case_and_a_trailing_dot_are_normalised() {
    assert_eq!(
        group("Shop.Example-Org.Test.").as_deref(),
        Some("example-org.test")
    );
}

#[test]
fn parse_rejects_an_empty_rule_list() {
    assert!(parse("").is_none());
    assert!(parse("!www.ck\n*.ck\n").is_none());
    let parsed = parse("uk\nco.uk\n*.ck\n!www.ck\n").unwrap();
    assert_eq!(suffix_label_count(&parsed, &["a", "b", "co", "uk"]), 2);
    assert_eq!(suffix_label_count(&parsed, &["a", "b", "ck"]), 2);
    assert_eq!(suffix_label_count(&parsed, &["a", "www", "ck"]), 1);
    assert_eq!(suffix_label_count(&parsed, &["a", "b", "test"]), 1);
}

#[test]
fn the_browser_target_groups_on_the_registrable_domain() {
    let target = crate::browser_action_target::browser_target(
        "https://shop.example-org.co.uk/cart?id=1",
        &[],
    );
    assert_eq!(target.site_group.as_deref(), Some("example-org.co.uk"));
    for (url, group) in [
        ("http://localhost:3000/", "localhost"),
        ("http://127.0.0.1:8080/", "127.0.0.1"),
        ("https://co.uk/", "co.uk"),
        ("https://storefront.example-org.test/", "example-org.test"),
    ] {
        let target = crate::browser_action_target::browser_target(url, &[]);
        assert_eq!(target.site_group.as_deref(), Some(group), "{url}");
    }
}
