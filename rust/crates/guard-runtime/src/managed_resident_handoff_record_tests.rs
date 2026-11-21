use super::*;
use std::fs;
use std::path::PathBuf;

fn digest(tag: char) -> String {
    tag.to_string().repeat(64)
}

fn scope_for(name: &str) -> PathBuf {
    let scope = std::env::temp_dir().join(format!(
        "hol-guard-handoff-record-{}-{}-{}",
        name,
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&scope).unwrap();
    scope
}

fn read_back(scope: &Path) -> HandoffRecord {
    let encoded = fs::read(scope.join(RECORD_FILE)).unwrap();
    assert!(encoded.len() <= 4096, "record outgrew the bounded read");
    serde_json::from_slice(&encoded).unwrap()
}

#[test]
fn repeated_retirements_of_one_runtime_share_a_count() {
    let scope = scope_for("repeat");
    let ours = digest('a');
    let theirs = digest('b');

    record_in_scope(&scope, &ours, &theirs, Retirement::Rejected).unwrap();
    record_in_scope(&scope, &ours, &theirs, Retirement::Rejected).unwrap();

    let record = read_back(&scope);
    assert_eq!(record.schema, RECORD_SCHEMA);
    assert_eq!(record.runtime, ours);
    assert_eq!(record.entries.len(), 1);
    assert_eq!(record.entries[0].foreign, theirs);
    assert_eq!(record.entries[0].reason, "rejected");
    assert_eq!(record.entries[0].count, 2);
    assert!(record.entries[0].last_unix >= record.entries[0].first_unix);

    fs::remove_dir_all(scope).unwrap();
}

/// An orphan left behind by a runtime nothing uses and a live resident that
/// rejects this runtime's requests are different faults, so a home that shows
/// both must not report them as one number.
#[test]
fn an_orphan_and_a_rejecting_resident_are_counted_apart() {
    let scope = scope_for("reasons");
    let ours = digest('a');
    let theirs = digest('b');

    record_in_scope(&scope, &ours, &theirs, Retirement::Orphaned).unwrap();
    record_in_scope(&scope, &ours, &theirs, Retirement::Rejected).unwrap();

    let record = read_back(&scope);
    assert_eq!(record.entries.len(), 2);
    let mut reasons: Vec<&str> = record
        .entries
        .iter()
        .map(|entry| entry.reason.as_str())
        .collect();
    reasons.sort_unstable();
    assert_eq!(reasons, ["orphaned", "rejected"]);

    fs::remove_dir_all(scope).unwrap();
}

/// A home that has seen more runtimes than the record holds keeps the newest
/// pairs: the churn being diagnosed is the one happening now.
#[test]
fn the_record_drops_the_stalest_pair_when_it_is_full() {
    let scope = scope_for("bounded");
    let ours = digest('f');
    for tag in ['0', '1', '2', '3', '4', '5', '6', '7'] {
        record_in_scope(&scope, &ours, &digest(tag), Retirement::Rejected).unwrap();
    }
    record_in_scope(&scope, &ours, &digest('8'), Retirement::Rejected).unwrap();

    let record = read_back(&scope);
    assert_eq!(record.entries.len(), MAX_ENTRIES);
    assert!(!record
        .entries
        .iter()
        .any(|entry| entry.foreign == digest('0')));
    assert!(record
        .entries
        .iter()
        .any(|entry| entry.foreign == digest('8')));

    fs::remove_dir_all(scope).unwrap();
}

/// Diagnostics are not authority: a record that cannot be trusted is started
/// again rather than refused, so a damaged file cannot stop the counting.
#[test]
fn a_damaged_record_is_replaced() {
    let scope = scope_for("damaged");
    let ours = digest('a');
    let path = scope.join(RECORD_FILE);
    fs::write(&path, b"{not json").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    record_in_scope(&scope, &ours, &digest('b'), Retirement::Orphaned).unwrap();

    let record = read_back(&scope);
    assert_eq!(record.entries.len(), 1);
    assert_eq!(record.entries[0].count, 1);

    fs::remove_dir_all(scope).unwrap();
}

/// A record whose runtime is not this one belongs to a different build that
/// happens to share a scope name; its counts are not ours to extend.
#[test]
fn a_record_from_another_runtime_is_not_extended() {
    let scope = scope_for("foreign-record");
    let ours = digest('a');
    record_in_scope(&scope, &digest('c'), &digest('b'), Retirement::Rejected).unwrap();

    record_in_scope(&scope, &ours, &digest('b'), Retirement::Rejected).unwrap();

    let record = read_back(&scope);
    assert_eq!(record.runtime, ours);
    assert_eq!(record.entries.len(), 1);
    assert_eq!(record.entries[0].count, 1);

    fs::remove_dir_all(scope).unwrap();
}

#[test]
fn a_value_that_is_not_a_runtime_digest_is_refused() {
    let scope = scope_for("digest");
    let ours = digest('a');

    assert_eq!(
        record_in_scope(&scope, &ours, "../../etc", Retirement::Rejected).unwrap_err(),
        "native_resident_runtime_digest_invalid"
    );
    assert!(!scope.join(RECORD_FILE).exists());

    fs::remove_dir_all(scope).unwrap();
}
