//! A Windows machine nobody manages has no policy key, and that has to read as
//! no authority: the fail-closed floor is for configured authority that did not
//! load, not for every Windows machine. Everything that is configured and
//! unusable still fails closed.

use super::*;

use crate::managed_policy::POLICY_SCHEMA_VERSION;
use crate::managed_policy_load::{load_managed_policy, MachineSystem};
use serde_json::json;
use tempfile::TempDir;

fn windows(root: &TempDir, read: RegistryRead) -> ManagedPolicySource {
    ManagedPolicySource {
        system: MachineSystem::Windows,
        policy_path: None,
        write_cache: false,
        machine_root: Some(root.path().to_path_buf()),
        registry: RegistryAuthority::Fixed(read),
    }
}

fn policy_text() -> String {
    json!({
        "schemaVersion": POLICY_SCHEMA_VERSION,
        "settings": {"mode": "enforce"},
        "lockedSettings": ["mode"],
    })
    .to_string()
}

#[test]
fn a_machine_without_the_policy_key_has_no_authority() {
    let root = TempDir::new().expect("tempdir");

    let state = load_managed_policy(&windows(&root, RegistryRead::Missing));

    assert_eq!(state.status, ManagedPolicyStatus::Absent);
    assert_eq!(state.reason_code, Some("managed_policy_absent"));
    assert_eq!(state.source, REGISTRY_SOURCE);
    assert!(!state.status.fails_closed());
}

#[test]
fn a_removed_key_that_left_a_cache_behind_still_fails_closed() {
    let root = TempDir::new().expect("tempdir");
    let source = windows(&root, RegistryRead::Missing);
    let cache = root
        .path()
        .join("C/ProgramData/HOL Guard/managed-policy-cache.json");
    std::fs::create_dir_all(cache.parent().expect("parent")).expect("dirs");
    std::fs::write(&cache, policy_text()).expect("cache");

    let state = load_managed_policy(&source);

    assert_eq!(state.status, ManagedPolicyStatus::Tampered);
    assert_eq!(state.reason_code, Some("managed_policy_cache_tampered"));
    assert!(state.status.fails_closed());
}

#[test]
fn a_policy_key_this_account_may_not_read_fails_closed() {
    let root = TempDir::new().expect("tempdir");

    let state = load_managed_policy(&windows(&root, RegistryRead::Denied));

    assert_eq!(state.status, ManagedPolicyStatus::Inaccessible);
    assert_eq!(state.reason_code, Some("managed_policy_inaccessible"));
    assert!(state.status.fails_closed());
}

#[test]
fn a_policy_value_that_is_not_a_usable_document_fails_closed() {
    let root = TempDir::new().expect("tempdir");
    let oversized = format!("\"{}\"", "a".repeat(MAX_POLICY_BYTES as usize));
    for read in [
        RegistryRead::NotText,
        RegistryRead::TooLarge,
        RegistryRead::Failed("managed policy registry read failed: error 1015".to_owned()),
        RegistryRead::Text("{not json".to_owned()),
        RegistryRead::Text("{}".to_owned()),
        RegistryRead::Text(oversized),
    ] {
        let state = load_managed_policy(&windows(&root, read.clone()));

        assert_eq!(state.status, ManagedPolicyStatus::Invalid, "{read:?}");
        assert_eq!(state.reason_code, Some("managed_policy_invalid"));
        assert!(state.detail.is_some(), "{read:?}");
        assert!(state.status.fails_closed());
    }
}

#[test]
fn a_policy_value_loads_as_the_machine_policy() {
    let root = TempDir::new().expect("tempdir");

    let state = load_managed_policy(&windows(&root, RegistryRead::Text(policy_text())));

    assert_eq!(state.status, ManagedPolicyStatus::Active);
    assert_eq!(state.source, REGISTRY_SOURCE);
    let policy = state.policy.expect("policy");
    assert!(policy.locked_settings.contains("mode"));
}

#[test]
fn a_build_without_a_registry_reports_the_authority_unreadable() {
    let root = TempDir::new().expect("tempdir");

    let state = load_managed_policy(&windows(&root, RegistryRead::Unavailable));

    assert_eq!(state.status, ManagedPolicyStatus::Inaccessible);
    assert!(state.authority_unreadable());
    assert!(state.status.fails_closed());
}

#[cfg(windows)]
#[test]
fn a_windows_build_reads_this_machines_registry() {
    let state = load_managed_policy(&ManagedPolicySource {
        write_cache: false,
        ..ManagedPolicySource::native()
    });

    assert!(
        !state.authority_unreadable(),
        "a Windows build reads the policy key instead of assuming it unreadable"
    );
}
