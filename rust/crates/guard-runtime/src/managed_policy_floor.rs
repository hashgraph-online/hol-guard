//! What governs a machine whose administrator installed a policy this runtime
//! cannot read.
//!
//! Port of `_effective_managed_policy` (config.py:377) and
//! `fail_closed_managed_policy` (mdm/policy.py:490). A profile that is present
//! but unreadable, invalid or tampered with is not an unmanaged machine, and
//! composing local configuration against nothing would hand that machine a
//! weaker policy than the one it is under. The floor below stands in instead:
//! every setting locked at its strictest value, so composition can only reach
//! up to it.

use guard_command::egress_caller_policy::ManagedNetworkPolicy;
use serde_json::{Map, Value};

use crate::managed_policy::{
    canonical_payload_hash, DaemonStartup, InstallOwner, ManagedIntegrityTrust, ManagedPolicy,
    ManagedUpdatePolicy, POLICY_SCHEMA_VERSION,
};
use crate::managed_policy_load::ManagedPolicyState;

/// `_effective_managed_policy` (config.py:377). Configured machine authority
/// this runtime could not read is not an unmanaged machine: the floor below
/// stands in for the policy so the effective configuration cannot be weaker
/// than the administrator asked for.
pub(crate) fn effective_managed_policy(state: &ManagedPolicyState) -> Option<ManagedPolicy> {
    if state.policy.is_none() && state.status.fails_closed() {
        return Some(fail_closed_managed_policy());
    }
    state.policy.clone()
}

/// `fail_closed_managed_policy` (mdm/policy.py:490). Every setting is locked,
/// so a local value can only be composed up to this floor, never below it.
pub(crate) fn fail_closed_managed_policy() -> ManagedPolicy {
    let mut settings = Map::new();
    settings.insert("mode".to_owned(), Value::from("enforce"));
    settings.insert("security_level".to_owned(), Value::from("paranoid"));
    for action in [
        "default_action",
        "unknown_publisher_action",
        "changed_hash_action",
        "new_network_domain_action",
        "subprocess_action",
    ] {
        settings.insert(action.to_owned(), Value::from("block"));
    }
    settings.insert("sync".to_owned(), Value::Bool(false));

    let mut hashed = Map::new();
    hashed.insert(
        "schemaVersion".to_owned(),
        Value::from(POLICY_SCHEMA_VERSION),
    );
    hashed.insert("settings".to_owned(), Value::Object(settings.clone()));
    hashed.insert("failClosed".to_owned(), Value::Bool(true));

    ManagedPolicy {
        schema_version: POLICY_SCHEMA_VERSION.to_owned(),
        locked_settings: settings.keys().cloned().collect(),
        settings,
        required_harnesses: Vec::new(),
        network: ManagedNetworkPolicy::unmanaged_default(),
        update: ManagedUpdatePolicy {
            owner: InstallOwner::Mdm,
            ..ManagedUpdatePolicy::default()
        },
        integrity_trust: ManagedIntegrityTrust::default(),
        daemon_startup: DaemonStartup::OnDemand,
        content_hash: canonical_payload_hash(&hashed),
        policy_bundle_keyring: None,
    }
}

#[cfg(test)]
#[path = "managed_policy_floor_tests.rs"]
mod tests;
