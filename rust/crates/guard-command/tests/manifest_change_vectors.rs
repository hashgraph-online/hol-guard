//! Parity vectors recorded from the legacy Python
//! `parse_manifest_dependency_changes` while it still existed, one per call the
//! package-intent test suites made (before and after manifest text, limits and
//! the resulting changes, truncation flag and parse errors).

use guard_command::package_manifest_diff::parse_manifest_dependency_changes;
use serde_json::Value;

const VECTORS: &str = include_str!("../testdata/manifest_change_vectors.json");

/// The vectors record Python's 50 ms deadline, and none of them expect
/// `deadline_exceeded`. On a loaded, coverage-instrumented runner the first
/// parse can take longer than that, so the parity check gets enough time to
/// finish. `deadline_exceeded_truncates` covers the deadline path itself.
const PARITY_DEADLINE_MS: u64 = 10_000;

#[test]
fn recorded_python_change_vectors_match() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    assert!(vectors.len() >= 25);
    for (index, vector) in vectors.iter().enumerate() {
        let path = vector["path"].as_str().unwrap();
        let result = parse_manifest_dependency_changes(
            path,
            vector["before"].as_str(),
            vector["after"].as_str(),
            vector["byte_limit"].as_u64().unwrap() as usize,
            vector["deadline_ms"]
                .as_u64()
                .unwrap()
                .max(PARITY_DEADLINE_MS),
        );
        let changes: Vec<Value> = result
            .changes
            .iter()
            .map(|change| serde_json::json!([change.package_name, change.before, change.after]))
            .collect();
        assert_eq!(Value::Array(changes), vector["changes"], "{index} {path}");
        assert_eq!(result.truncated, vector["truncated"], "{index} {path}");
        assert_eq!(
            serde_json::json!(result.parse_errors),
            vector["parse_errors"],
            "{index} {path}"
        );
    }
}
