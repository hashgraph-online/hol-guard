use super::{read_controller_invocations_root_owned, read_for_owner};
use crate::controller_invocations::audit_controller_invocations;
use rustix::process::geteuid;
use serde_json::Value;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../tests/fixtures/python_controller_invocations_v1.json"
    ))
    .unwrap()
}

fn install() -> (tempfile::TempDir, PathBuf, Value) {
    let frozen = fixture();
    let case = frozen["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == "valid-delta")
        .unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let base = temporary.path().canonicalize().unwrap();
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
    let state = base.join("state");
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    let attempts = state.join("controller-attempts");
    std::fs::create_dir(&attempts).unwrap();
    std::fs::set_permissions(&attempts, std::fs::Permissions::from_mode(0o700)).unwrap();
    let record = &case["records"][0];
    let invocation = attempts.join(record["name"].as_str().unwrap());
    std::fs::create_dir(&invocation).unwrap();
    std::fs::set_permissions(&invocation, std::fs::Permissions::from_mode(0o700)).unwrap();
    for (name, raw) in record["files"].as_object().unwrap() {
        let path = invocation.join(name);
        std::fs::write(&path, raw.as_str().unwrap()).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    (temporary, state, frozen)
}

fn invocation(state: &Path) -> PathBuf {
    state.join("controller-attempts/shard-000-synthetic")
}

#[test]
fn idle_private_snapshot_feeds_only_diagnostic_accounting() {
    let (_temporary, state, frozen) = install();
    let records = read_for_owner(&state, geteuid().as_raw()).unwrap().unwrap();
    assert_eq!(records.len(), 1);
    let audit = audit_controller_invocations(
        Some(&records),
        frozen["config_digest"].as_str().unwrap(),
        frozen["manifest_digest"].as_str().unwrap(),
        &frozen["provider_pins"],
        1,
        30,
    )
    .unwrap();
    assert_eq!(audit["errors"], serde_json::json!([]));
    assert_eq!(audit["provider_tokens_delta"], 30);
    assert_eq!(audit["qualification_eligible"], false);
    if geteuid().as_raw() != 0 || !cfg!(target_os = "linux") {
        assert!(read_controller_invocations_root_owned(&state).is_err());
    }
}

#[test]
fn private_snapshot_refuses_active_or_mutable_records() {
    let (_temporary, state, _) = install();
    let owner = geteuid().as_raw();
    let attempts = state.join("controller-attempts");
    let record = invocation(&state);
    let before = record.join("provider-before.json");
    let after = record.join("provider-after.json");
    let original_after = std::fs::read(&after).unwrap();

    let active = state.join("ci-controller.lock");
    std::fs::write(&active, "active").unwrap();
    assert!(read_for_owner(&state, owner)
        .unwrap_err()
        .to_string()
        .contains("active or uncertain"));
    std::fs::remove_file(active).unwrap();

    std::fs::set_permissions(&attempts, std::fs::Permissions::from_mode(0o750)).unwrap();
    assert!(read_for_owner(&state, owner).is_err());
    std::fs::set_permissions(&attempts, std::fs::Permissions::from_mode(0o700)).unwrap();

    let hardlink = record.join("provider-before-other.json");
    std::fs::hard_link(&before, &hardlink).unwrap();
    assert!(read_for_owner(&state, owner).is_err());
    std::fs::remove_file(hardlink).unwrap();

    std::fs::remove_file(&after).unwrap();
    symlink(&before, &after).unwrap();
    assert!(read_for_owner(&state, owner).is_err());
    std::fs::remove_file(&after).unwrap();
    std::fs::write(&after, original_after).unwrap();
    std::fs::set_permissions(&after, std::fs::Permissions::from_mode(0o600)).unwrap();

    let linked_directory = attempts.join("shard-001-link");
    symlink(&record, &linked_directory).unwrap();
    assert!(read_for_owner(&state, owner).is_err());
}

#[test]
fn absent_inventory_still_requires_idle_private_state() {
    let temporary = tempfile::tempdir().unwrap();
    let base = temporary.path().canonicalize().unwrap();
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
    let state = base.join("state");
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    let owner = geteuid().as_raw();
    assert!(read_for_owner(&state, owner).unwrap().is_none());
    std::fs::write(state.join("ci-controller.lock"), "active").unwrap();
    assert!(read_for_owner(&state, owner).is_err());
}
