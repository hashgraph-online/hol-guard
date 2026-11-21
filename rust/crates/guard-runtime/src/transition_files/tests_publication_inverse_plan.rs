use std::path::Path;

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Map, Value};

use super::dispatch;
use super::inspect::sha256_hex;
use super::publication::Call;
use super::publication_inverse_plan::prior;
use crate::codex_hook_authority_record::python_json::python_canonical_json;

const HOME: &str = "/guard-home";
const CONFIG: &str = "/home/user/.codex/config.toml";
const OPERATION: &str = "1b4e28ba-2fa1-41d2-883f-0016d3cca427";

fn change(path: &str, after: &[u8]) -> Value {
    json!({
        "path": path,
        "before": null,
        "after": STANDARD.encode(after),
        "before_mode": 0o600,
        "after_mode": 0o600,
        "kind": "binding",
        "no_follow": true,
    })
}

fn record() -> Map<String, Value> {
    let (manifest, receipt) = Call::targets(Path::new(HOME), CONFIG);
    let plan = json!({
        "schema": "hol-guard.codex-publication-inverse-plan.v1",
        "action": "apps.repair.codex-publication-inverse",
        "guard_home": HOME,
        "config_path": CONFIG,
        "operation_id": OPERATION,
        "interrupted_operation_id": "interrupted",
        "files": [
            change(CONFIG, b"config"),
            change(&manifest.to_string_lossy(), b"manifest"),
            change(&receipt.to_string_lossy(), b"receipt"),
        ],
    });
    let canonical = python_canonical_json(&plan).unwrap();
    let subject = format!(
        "codex-publication-inverse:{OPERATION}:{}",
        sha256_hex(canonical.as_bytes())
    );
    let mut record = Map::new();
    record.insert("config_path".to_owned(), json!(CONFIG));
    record.insert("operation_id".to_owned(), json!("interrupted"));
    for (key, bytes) in [
        ("before_config", &b"config"[..]),
        ("before_manifest", b"manifest"),
        ("before_receipt", b"receipt"),
    ] {
        record.insert(key.to_owned(), json!(STANDARD.encode(bytes)));
    }
    record.insert(
        "publication_inverse".to_owned(),
        json!({
            "schema": "hol-guard.codex-explicit-publication-inverse.v1",
            "phase": "restoring",
            "plan": plan,
            "subject": subject,
            "owner_pid": 42,
            "owner_operation_id": "owner",
            "publication_monotonic": 12.5,
            "file_identities": [null, [1, 2, 3, 4, 5], null],
            "restored": [1],
        }),
    );
    record
}

#[test]
fn a_record_without_a_prior_inverse_names_none() {
    let mut record = record();
    record.remove("publication_inverse");
    assert_eq!(prior(Path::new(HOME), &record).ok(), Some(None));
}

#[test]
fn a_valid_prior_inverse_names_its_operation() {
    let answer = prior(Path::new(HOME), &record()).ok().flatten();
    assert_eq!(answer.as_deref(), Some(OPERATION));
}

#[test]
fn a_prior_inverse_with_a_forged_subject_or_restore_order_is_refused() {
    for (key, value) in [
        ("subject", json!("codex-publication-inverse:forged")),
        ("restored", json!([2])),
        ("owner_pid", json!(true)),
        ("phase", json!("verified")),
    ] {
        let mut record = record();
        record["publication_inverse"][key] = value;
        assert!(prior(Path::new(HOME), &record).is_err(), "{key}");
    }
}

#[test]
fn a_prior_inverse_that_restores_other_bytes_is_refused() {
    let mut record = record();
    record.insert("before_config".to_owned(), json!(STANDARD.encode(b"other")));
    assert!(prior(Path::new(HOME), &record).is_err());
}

#[test]
fn the_plan_subject_binds_its_canonical_payload() {
    let ask = |workspace: Value| {
        dispatch(&json!({
            "op": "publication_inverse_plan",
            "home": HOME,
            "config": CONFIG,
            "operation_id": OPERATION,
            "interrupted_operation_id": "interrupted",
            "resumed_inverse_operation_id": null,
            "journal_sha256": "0".repeat(64),
            "journal_identity": [1, 2, 3, 4, 5],
            "files": [],
            "file_identities": [],
            "dependencies": [],
            "native_runtime": null,
            "verification_workspace": workspace,
        }))
        .unwrap()["value"]["subject"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let first = ask(Value::Null);
    assert!(first.starts_with(&format!("codex-publication-inverse:{OPERATION}:")));
    assert_eq!(first, ask(Value::Null));
    assert_ne!(first, ask(json!("/workspace")));
}

#[cfg(unix)]
#[test]
fn a_journal_that_changed_or_vanished_is_not_the_one_the_inverse_pinned() {
    use super::publication_io::rollback_identity;
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::TempDir::new().unwrap();
    let home = root.path().join("guard");
    let codex = home.join("managed/codex");
    std::fs::create_dir_all(&codex).unwrap();
    for directory in [&home, &home.join("managed"), &codex] {
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let journal = codex.join("pending-hook-publication.json");
    let ask = |identity: Value, sha256: String| {
        dispatch(&json!({
            "op": "publication_inverse_journal",
            "home": home.to_string_lossy(),
            "journal_identity": identity,
            "journal_sha256": sha256,
            "record": {},
        }))
        .unwrap()["error"]
            .to_string()
    };
    // No journal: its identity cannot be the captured one.
    let missing = ask(json!([1, 2, 3, 4, 5]), "0".repeat(64));
    assert!(
        missing.contains("publication_inverse_journal_changed"),
        "{missing}"
    );
    std::fs::write(&journal, b"journal").unwrap();
    std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();
    let identity = rollback_identity(&journal).unwrap().unwrap();
    // The identity holds but the bytes are not the ones hashed.
    let altered = ask(identity, "0".repeat(64));
    assert!(
        altered.contains("publication_inverse_journal_changed"),
        "{altered}"
    );
}
