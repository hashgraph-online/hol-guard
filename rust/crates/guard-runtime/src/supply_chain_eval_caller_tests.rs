//! What the caller brings to an evaluation: the machine's network policy, and
//! a spool directory that exists only while a round needs one.
//!
//! No exchange is performed here. The policy these tests pass refuses every
//! destination, so a need is answered as blocked before DNS or a socket.

use super::*;

use crate::managed_policy_registry::{RegistryAuthority, RegistryRead};

use std::fs;

use guard_contracts::EgressOutcomeV1;
use serde_json::json;
use tempfile::TempDir;

use crate::managed_policy::POLICY_SCHEMA_VERSION;
use crate::managed_policy_load::MachineSystem;

/// Refuses every destination, so a need is answered without a socket.
struct RefusedDestinations;

impl EgressPolicy for RefusedDestinations {
    fn validate(&self, _url: &str) -> Result<(), String> {
        Err("managed_destination_refused".to_owned())
    }
}

/// A machine whose paths live under a directory the test owns.
fn rooted(root: &TempDir) -> ManagedPolicySource {
    ManagedPolicySource {
        system: MachineSystem::Other,
        policy_path: None,
        write_cache: false,
        machine_root: Some(root.path().to_path_buf()),
        registry: RegistryAuthority::Native,
    }
}

/// An administrator's policy file read without the machine ownership walk,
/// which is how `policy_path=` reads one.
fn explicit(path: &Path) -> ManagedPolicySource {
    ManagedPolicySource {
        system: MachineSystem::Other,
        policy_path: Some(path.to_path_buf()),
        write_cache: false,
        machine_root: None,
        registry: RegistryAuthority::Native,
    }
}

fn need(url: &str) -> EgressNeedV1 {
    EgressNeedV1 {
        class: "registry".to_owned(),
        method: "GET".to_owned(),
        url: url.to_owned(),
        headers: Default::default(),
        body: None,
        body_sha256: String::new(),
        occurrence: 1,
        timeout_seconds: 1.0,
        max_redirects: 0,
        max_response_bytes: 1024,
        delay_seconds: 0.0,
        inspect: None,
    }
}

#[test]
fn a_machine_with_no_policy_exchanges_under_the_unmanaged_default() {
    let root = TempDir::new().expect("tempdir");

    let policy = caller_network_policy(&rooted(&root)).expect("an absent profile is unmanaged");

    assert_eq!(policy, ManagedNetworkPolicy::unmanaged_default());
}

#[test]
fn the_administrators_network_policy_is_the_one_the_caller_exchanges_under() {
    let root = TempDir::new().expect("tempdir");
    let path = root.path().join("policy.json");
    let document = json!({
        "schemaVersion": POLICY_SCHEMA_VERSION,
        "settings": {"mode": "enforce"},
        "lockedSettings": ["mode"],
        "network": {"allowPublicRegistries": false},
    });
    fs::write(&path, serde_json::to_vec(&document).expect("document")).expect("write");

    let policy = caller_network_policy(&explicit(&path)).expect("the profile loaded");

    assert!(
        !policy.allow_public_registries,
        "the administrator's registry rule reaches the caller"
    );
}

#[test]
fn a_profile_that_did_not_load_refuses_the_network() {
    let root = TempDir::new().expect("tempdir");
    let invalid = root.path().join("policy.json");
    fs::write(&invalid, b"{").expect("write");
    assert_eq!(
        CallerEgressFulfilment::resolve_policy(&explicit(&invalid)).err(),
        Some(CallerEgressFulfilment::policy_unhonoured()),
        "an invalid profile is not the unmanaged network"
    );

    let tampered = ManagedPolicySource {
        system: MachineSystem::Other,
        policy_path: None,
        write_cache: false,
        machine_root: Some(root.path().to_path_buf()),
        registry: RegistryAuthority::Native,
    };
    let native = root.path().join("etc/hol-guard/managed-policy.json");
    fs::create_dir_all(native.parent().expect("parent")).expect("parents");
    fs::write(
        &native,
        json!({
            "schemaVersion": POLICY_SCHEMA_VERSION,
            "settings": {"mode": "enforce"},
            "network": {"allowPublicRegistries": false},
        })
        .to_string(),
    )
    .expect("write");
    assert_eq!(
        CallerEgressFulfilment::resolve_policy(&tampered).err(),
        Some(CallerEgressFulfilment::policy_unhonoured()),
        "a profile this machine does not own is not the unmanaged network"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let blocked = root.path().join("blocked.json");
        fs::write(&blocked, b"{}").expect("write");
        let mut permissions = fs::metadata(&blocked).expect("metadata").permissions();
        permissions.set_mode(0o000);
        fs::set_permissions(&blocked, permissions.clone()).expect("block");
        let refusal = CallerEgressFulfilment::resolve_policy(&explicit(&blocked)).err();
        let hidden = fs::File::open(&blocked).is_err();
        permissions.set_mode(0o644);
        fs::set_permissions(&blocked, permissions).expect("restore");
        if hidden {
            assert_eq!(
                refusal,
                Some(CallerEgressFulfilment::policy_unhonoured()),
                "an unreadable profile is not the unmanaged network"
            );
        }
    }
}

#[test]
fn a_machine_whose_authority_this_runtime_cannot_read_exchanges_nothing() {
    // A policy key this account may not read is configured authority. An
    // administrator's proxy, CA, or public-registry rule may live there, so the
    // unmanaged default would exchange outside all of them.
    let registry = ManagedPolicySource {
        system: MachineSystem::Windows,
        policy_path: None,
        write_cache: false,
        machine_root: None,
        registry: RegistryAuthority::Fixed(RegistryRead::Denied),
    };

    assert_eq!(
        caller_network_policy(&registry).err(),
        Some(CallerEgressFulfilment::policy_unhonoured()),
        "an authority this runtime cannot read is not the unmanaged network"
    );
}

#[test]
fn nothing_is_spooled_until_a_round_needs_the_network() {
    let egress = CallerEgressFulfilment::new(&RefusedDestinations);

    assert!(egress.supplied().is_empty());
    assert_eq!(egress.spool_dir(), Path::new(""));
}

#[test]
fn a_performed_round_spools_into_an_owner_only_directory() {
    let mut egress = CallerEgressFulfilment::new(&RefusedDestinations);

    egress
        .fulfil(&[need("https://registry.npmjs.org/left-pad")])
        .expect("the round was performed");

    let dir = egress.spool_dir().to_path_buf();
    assert!(dir.is_dir(), "the round that needed the network opened it");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&dir).expect("spool").permissions().mode();
        assert_eq!(mode & 0o7777, 0o700, "the spool is owner-only");
    }
    assert!(matches!(
        egress.supplied()[0].outcome,
        EgressOutcomeV1::Blocked { .. }
    ));

    // The directory belongs to the evaluation that opened it.
    drop(egress);
    assert!(!dir.exists(), "the spool is removed with the caller");
}

#[test]
fn a_caller_whose_managed_policy_cannot_be_honoured_refuses_every_need() {
    let mut egress = CallerEgressFulfilment::refusing(CallerEgressFulfilment::policy_unhonoured());

    let refusal = egress.fulfil(&[need("https://registry.npmjs.org/left-pad")]);

    assert_eq!(refusal, Err(CallerEgressFulfilment::policy_unhonoured()));
    // Nothing was exchanged, so nothing was spooled either.
    assert_eq!(egress.spool_dir(), Path::new(""));
    assert!(egress.supplied().is_empty());
}

#[test]
fn an_answer_naming_an_archive_no_round_downloaded_is_refused() {
    let mut egress = CallerEgressFulfilment::new(&RefusedDestinations);

    let named = json!([{"sha256": "a".repeat(64), "blob_path": "/tmp/blob"}]);
    assert!(egress.claim_archives(Some(&named)).is_err());
    // An answer that names none is an evaluation with nothing to hand over.
    assert_eq!(egress.claim_archives(None).expect("no archives").len(), 0);
}
