use serde_json::json;

use super::LaunchAdvisories;
use crate::runtime_identity_range::SemVer;

fn advisories() -> LaunchAdvisories {
    let range = |introduced: &str, fixed: &str| json!({"introduced": introduced, "fixed": fixed, "last_affected": null});
    LaunchAdvisories::for_tests(
        json!([
            {
                "advisory_id": "CVE-0000-0001",
                "family": "node",
                "vendor": "nodejs.org",
                "version_scheme": "semver",
                "severity": "high",
                "ranges": [
                    range("11.7.0", "22.23.4"),
                    range("23.0.0", "24.22.1"),
                    range("25.0.0", "26.12.1"),
                ],
            },
            {
                "advisory_id": "CVE-0000-0002",
                "family": "node",
                "vendor": "nodejs.org",
                "version_scheme": "semver",
                "severity": "critical",
                "ranges": [range("26.12.0", "26.12.2")],
            },
            {
                "advisory_id": "CVE-0000-0003",
                "family": "node",
                "vendor": "nodejs.org",
                "version_scheme": "semver",
                "severity": "medium",
                "ranges": [range("24.0.0", "24.30.0")],
            },
            {
                "advisory_id": "CVE-0000-0004",
                "family": "bun",
                "vendor": "oven.sh",
                "version_scheme": "semver",
                "severity": "critical",
                "ranges": [range("0.1.0", "99.0.0")],
            },
        ]),
        json!({"state": "verified"}),
    )
}

fn version(raw: &str) -> SemVer {
    SemVer::parse(raw).expect("version")
}

#[test]
fn a_version_is_clean_only_outside_every_serious_range_of_its_family() {
    let advisories = advisories();
    assert!(!advisories.version_is_clean("node", &version("25.2.1")));
    assert!(!advisories.version_is_clean("node", &version("22.22.2")));
    // A medium advisory does not hold a launch, so it does not hold advice.
    assert!(advisories.version_is_clean("node", &version("24.22.1")));
    assert!(advisories.version_is_clean("node", &version("22.23.4")));
    // Another family's advisory says nothing about Node.js.
    assert!(advisories.version_is_clean("node", &version("27.0.0")));
    assert!(!advisories.version_is_clean("node", &version("27.0.0-rc.1")));
}

#[test]
fn the_patched_release_stays_on_its_line_and_skips_a_fix_another_advisory_holds() {
    let advisories = advisories();
    let patched = |current: &str| advisories.patched_release("node", &version(current));
    assert_eq!(patched("24.1.0").as_deref(), Some("24.22.1"));
    assert_eq!(patched("22.0.0").as_deref(), Some("22.23.4"));
    // Line 25 has no fix of its own; 26.12.1 sits inside the critical range,
    // so the next clean fix is 26.12.2.
    assert_eq!(patched("25.2.1").as_deref(), Some("26.12.2"));
    assert_eq!(patched("26.12.3"), None);
    assert_eq!(advisories.patched_release("deno", &version("1.0.0")), None);
}
