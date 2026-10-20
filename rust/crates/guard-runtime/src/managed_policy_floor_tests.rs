//! A machine under a policy this runtime could not read is governed by the
//! floor, and a machine under no policy is governed by nothing.

use super::*;

use crate::managed_policy_load::ManagedPolicyStatus;

fn state(status: ManagedPolicyStatus, policy: Option<ManagedPolicy>) -> ManagedPolicyState {
    ManagedPolicyState {
        status,
        source: "/etc/hol-guard/managed-policy.json".to_owned(),
        policy,
        reason_code: None,
        detail: None,
    }
}

#[test]
fn authority_that_did_not_load_is_governed_by_the_floor() {
    for status in [
        ManagedPolicyStatus::Invalid,
        ManagedPolicyStatus::Inaccessible,
        ManagedPolicyStatus::Tampered,
    ] {
        let policy = effective_managed_policy(&state(status, None))
            .unwrap_or_else(|| panic!("{} is governed by no policy", status.as_str()));
        assert_eq!(policy, fail_closed_managed_policy());
    }
}

#[test]
fn a_machine_with_no_policy_is_not_handed_one() {
    assert!(effective_managed_policy(&state(ManagedPolicyStatus::Absent, None)).is_none());
}

#[test]
fn a_policy_that_loaded_is_the_policy_that_governs() {
    let loaded = ManagedPolicy {
        schema_version: POLICY_SCHEMA_VERSION.to_owned(),
        ..fail_closed_managed_policy()
    };
    let mut relaxed = loaded.clone();
    relaxed
        .settings
        .insert("mode".to_owned(), Value::from("observe"));
    relaxed.locked_settings.clear();

    let effective =
        effective_managed_policy(&state(ManagedPolicyStatus::Active, Some(relaxed.clone())))
            .expect("active policy");

    // The floor stands in for a policy that did not load; it never overrides
    // the one that did.
    assert_eq!(effective, relaxed);
    assert_eq!(effective.settings["mode"], Value::from("observe"));
}

#[test]
fn the_floor_locks_every_setting_it_names() {
    let floor = fail_closed_managed_policy();

    assert_eq!(floor.settings["mode"], Value::from("enforce"));
    assert_eq!(floor.settings["security_level"], Value::from("paranoid"));
    assert_eq!(floor.settings["sync"], Value::Bool(false));
    for (name, value) in &floor.settings {
        assert!(floor.locked_settings.contains(name), "{name} is not locked");
        if name != "mode" && name != "security_level" && name != "sync" {
            assert_eq!(value, &Value::from("block"), "{name}");
        }
    }
    // The floor is the machine's own policy, so an update it does not install
    // is not this runtime's to make.
    assert_eq!(floor.update.owner, InstallOwner::Mdm);
    assert_eq!(floor.daemon_startup, DaemonStartup::OnDemand);
    assert!(!floor.content_hash.is_empty());
}
