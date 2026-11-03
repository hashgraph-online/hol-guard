//! The conservative semver subset Guard can prove locally, case for case.
use super::semver_spec_matches;

#[test]
fn semver_matches_only_the_provable_subset() {
    // Unsupported syntax has to fail closed: a range Guard cannot reason about
    // must never report a local package as satisfying it.
    const CASES: &[(&str, &str, bool)] = &[
        ("4.1.8", "4.1.8", true),
        ("4.1.8", "4.1.9", false),
        ("^4.1.8", "4.9.0", true),
        ("^4.1.8", "5.0.0", false),
        ("^0.2.3", "0.2.9", true),
        ("^0.2.3", "0.3.0", false),
        ("^0.0.3", "0.0.3", true),
        ("^0.0.3", "0.0.4", false),
        ("~4.1.8", "4.1.9", true),
        ("~4.1.8", "4.2.0", false),
        ("16.3.0-preview.8", "16.3.0-preview.8", true),
        ("16.3.0-preview.8", "16.3.0-preview.9", false),
        ("^16.3.0", "16.3.0-preview.8", false),
        (">=4.1.8", "4.1.8", false),
        ("^4.1", "4.1.8", false),
        (" ^4.1.8", "4.1.8", false),
    ];
    for (specifier, version, expected) in CASES {
        assert_eq!(
            semver_spec_matches(specifier, version),
            *expected,
            "{specifier} against {version}"
        );
    }
}
