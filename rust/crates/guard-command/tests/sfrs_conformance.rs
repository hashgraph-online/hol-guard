//! Conformance harness for the request-classification parity vectors.
//!
//! The vectors were recorded from the Python implementation while its existing
//! tests ran. Each vector holds the call inputs, the result, a bounded snapshot
//! of the directory the call could read and the SHA-256 pre-images that were
//! hashed. Replay materializes the snapshot below a fresh root, rewrites the
//! recorded prefix to that root, recomputes every path-dependent digest from
//! its rewritten pre-image and compares the classifier output with the
//! rewritten expectation. Entries the classifier does not implement yet only
//! prove that their vectors load, materialize and remap deterministically.
#![cfg(unix)]

#[path = "sfrs_support/mod.rs"]
mod sfrs_support;

use std::fs;
use std::path::Path;

use serde_json::{json, Value};
use sfrs_support::{ReplayVector, TOKEN};

fn replay_vectors(entry: &str) -> (Vec<ReplayVector>, impl Drop) {
    sfrs_support::replay_vectors(ENTRIES, entry)
}

macro_rules! entries {
    ($($name:ident),* $(,)?) => {
        const ENTRIES: &[(&str, &[u8])] = &[$((
            stringify!($name),
            include_bytes!(concat!("fixtures/sfrs/", stringify!($name), ".json.gz")),
        )),*];

        mod entry_checks {
            $(
                #[test]
                fn $name() {
                    super::check_entry(stringify!($name));
                }
            )*
        }
    };
}

entries!(
    classify_sensitive_path,
    command_list_candidate_texts,
    extract_sensitive_file_read_request_from_action,
    extract_sensitive_file_read_request,
    extract_sensitive_file_write_request,
    extract_sensitive_tool_action_request,
    build_file_read_request_artifact,
    build_file_write_request_artifact,
    build_tool_action_request_artifact,
    is_explicitly_benign_tool_action_request,
    is_explicitly_benign_native_file_read_request,
    classify_github_shell_capabilities,
    low_risk_compound_developer_execution_context,
    literal_cd_execution_context,
    shell_execution_context_starts_with_literal_cd,
    read_only_lookup_target_is_safe,
    hook_runtime_artifact,
);

/// Families the secret corpus gained after the vectors were recorded.
///
/// The vectors froze the Python implementation's answers, and Python did not
/// know these families, so every vector that names one of them recorded
/// `null`. A recorded `null` may therefore become a match in one of these
/// families and in nothing else: a vector Python matched still has to match
/// the same way, and a new match in a family Python already knew is still a
/// failure. [`CORPUS_EXPANSIONS`] pins how far the expansion reaches, so
/// widening one of these families later has to be recorded here.
const EXPANDED_FAMILIES: &[&str] = &["SSH key material", "GitHub CLI credentials"];

/// Vectors per entry whose recorded `null` is now a match in an expanded
/// family. Entries absent from this table allow none.
const CORPUS_EXPANSIONS: &[(&str, usize)] = &[
    ("classify_sensitive_path", 6),
    ("extract_sensitive_file_read_request", 50),
    ("extract_sensitive_file_write_request", 36),
];

/// Every family the result names, under whichever key carries it.
fn families(value: &Value) -> Vec<&str> {
    fn walk<'a>(value: &'a Value, found: &mut Vec<&'a str>) {
        match value {
            Value::Object(map) => {
                for (key, item) in map {
                    if matches!(key.as_str(), "family" | "path_class") {
                        if let Some(text) = item.as_str() {
                            found.push(text);
                        }
                    }
                    walk(item, found);
                }
            }
            Value::Array(items) => items.iter().for_each(|item| walk(item, found)),
            _ => {}
        }
    }
    let mut found = Vec::new();
    walk(value, &mut found);
    found
}

/// True when `actual` is a match the expanded corpus explains and the vector
/// recorded no match at all.
fn is_corpus_expansion(expected: &Value, actual: &Value) -> bool {
    if !expected.is_null() {
        return false;
    }
    let found = families(actual);
    !found.is_empty()
        && found
            .iter()
            .all(|family| EXPANDED_FAMILIES.contains(family))
}

fn check_entry(entry: &str) {
    let (vectors, _root) = replay_vectors(entry);
    assert!(!vectors.is_empty(), "{entry}: no vectors");
    let mut ids: Vec<&str> = vectors.iter().map(|vector| vector.id.as_str()).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), vectors.len(), "{entry}: duplicate vector ids");
    for vector in &vectors {
        assert!(vector.dir.is_dir(), "{}: directory missing", vector.id);
        let expected = vector.expected(&Value::Null);
        for value in [&vector.args, &expected, &vector.env] {
            assert!(
                !value.to_string().contains(TOKEN),
                "{}: unreplaced root token",
                vector.id
            );
        }
    }
    if !guard_command::sfrs_replay::implements(entry) {
        return;
    }
    let mut failures = Vec::new();
    let mut compared = 0usize;
    let mut resident_deferred = 0usize;
    let mut expanded = 0usize;
    for vector in &vectors {
        if vector.host_dependent {
            continue;
        }
        let actual = guard_command::sfrs_replay::replay_entry(
            entry,
            &vector.args,
            &vector.evaluation,
            &vector.env,
            &vector.dir,
        )
        .unwrap_or_else(|error| json!({ "replay_error": error }));
        let actual =
            if actual == json!({ guard_command::sfrs_replay::RESIDENT_HOST_REQUIRED: true }) {
                // Replay failed closed where the resident would answer. A recorded
                // null or `false` still has to match; any other result waits for
                // the resident host.
                match vector.expected(&Value::Null) {
                    Value::Null => Value::Null,
                    Value::Bool(false) => json!(false),
                    _ => {
                        resident_deferred += 1;
                        continue;
                    }
                }
            } else {
                actual
            };
        let expected = normalize_identities(&vector.expected(&actual));
        let actual = normalize_identities(&actual);
        compared += 1;
        if actual != expected {
            if is_corpus_expansion(&expected, &actual) {
                expanded += 1;
                continue;
            }
            failures.push(format!(
                "{}\n  args: {}\n  expected: {expected}\n  actual:   {actual}",
                vector.id, vector.args
            ));
        }
    }
    assert!(compared > 0, "{entry}: every vector was skipped");
    assert!(
        resident_deferred * 5 <= compared,
        "{entry}: {resident_deferred} resident-backed vectors deferred against {compared} compared"
    );
    if let Some(dir) = std::env::var_os("SFRS_FAILURE_DIR") {
        let _ = fs::write(
            Path::new(&dir).join(format!("{entry}.txt")),
            failures.join("\n"),
        );
    }
    assert!(
        failures.is_empty(),
        "{entry}: {} of {compared} vectors differ\n{}",
        failures.len(),
        failures
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    let recorded = CORPUS_EXPANSIONS
        .iter()
        .find(|(name, _)| *name == entry)
        .map_or(0, |(_, count)| *count);
    assert_eq!(
        expanded, recorded,
        "{entry}: {expanded} recorded-null vectors now match an expanded family, against {recorded} recorded"
    );
}

/// Replace filesystem identities with first-seen ordinals.
///
/// Device, inode and timestamps differ on every materialization, so the
/// comparison proves that identities keep their file type and are shared by
/// the same positions rather than matching the recorded numbers.
fn normalize_identities(value: &Value) -> Value {
    fn walk(value: &Value, seen: &mut Vec<Value>) -> Value {
        match value {
            Value::Object(map) if map.get("$type") == Some(&json!("ShellPathIdentity")) => {
                let key = json!([
                    map.get("device"),
                    map.get("inode"),
                    map.get("change_time_ns")
                ]);
                let ordinal = seen
                    .iter()
                    .position(|item| *item == key)
                    .unwrap_or_else(|| {
                        seen.push(key);
                        seen.len() - 1
                    });
                json!({ "$type": "ShellPathIdentity", "mode": map.get("mode"), "ordinal": ordinal })
            }
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(key, item)| (key.clone(), walk(item, seen)))
                    .collect(),
            ),
            Value::Array(items) => {
                Value::Array(items.iter().map(|item| walk(item, seen)).collect())
            }
            other => other.clone(),
        }
    }
    walk(value, &mut Vec::new())
}

#[test]
fn path_dependent_digests_follow_the_replay_root() {
    let (vectors, _root) = replay_vectors("build_tool_action_request_artifact");
    let moved = vectors
        .iter()
        .filter(|vector| !vector.host_dependent)
        .count();
    assert!(moved > 0, "expected non-host-dependent artifact vectors");
    for vector in &vectors {
        let expected = vector.expected(&Value::Null);
        let artifact_id = expected["artifact_id"].as_str().unwrap_or_default();
        let fingerprint = artifact_id.rsplit(':').next().unwrap_or_default();
        assert!(
            fingerprint.len() == 64 && fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "{}: artifact fingerprint is not a sha256 digest: {artifact_id}",
            vector.id
        );
    }
}

#[test]
fn replay_roots_are_isolated_per_process_and_entry() {
    let (first, first_root) = replay_vectors("classify_sensitive_path");
    let (second, second_root) = replay_vectors("extract_sensitive_file_read_request");
    assert!(!first.is_empty() && !second.is_empty());
    assert_ne!(first[0].dir.parent(), second[0].dir.parent());
    drop(first_root);
    assert!(second[0].dir.is_dir());
    drop(second_root);
}
