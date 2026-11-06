//! Windows machine authority: `HKLM\Software\Policies\HOL\Guard`, value
//! `PolicyJson`, as `_read_windows_policy` (mdm/policy.py:277) reads it.
//!
//! Group Policy and MDM write the policy there, and a standard account can read
//! the Policies hive. A machine nobody configured therefore has no key, which is
//! no authority, exactly as Python reports it. A key this account may not read,
//! a value that is not a string, and a value that does not parse are configured
//! authority that did not load, and each fails closed.

use serde_json::Value;

use crate::managed_policy::parse_managed_policy;
use crate::managed_policy_load::{
    load_cache, write_cache, ManagedPolicySource, ManagedPolicyState, ManagedPolicyStatus,
    MAX_POLICY_BYTES, REGISTRY_UNREADABLE,
};

/// How the authority is named in a state, as Python names it.
pub(crate) const REGISTRY_SOURCE: &str = r"HKLM\Software\Policies\HOL\Guard";

/// What reading the policy value found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RegistryRead {
    /// The key or the value is not there: no administrator configured one.
    #[cfg_attr(not(windows), allow(dead_code))]
    Missing,
    /// The key is there and this account may not read it.
    #[cfg_attr(not(windows), allow(dead_code))]
    Denied,
    /// The value is not a string.
    #[cfg_attr(not(windows), allow(dead_code))]
    NotText,
    /// The value is larger than any policy may be.
    #[cfg_attr(not(windows), allow(dead_code))]
    TooLarge,
    /// The value's text.
    #[cfg_attr(not(windows), allow(dead_code))]
    Text(String),
    /// The read failed without saying whether a policy exists.
    #[cfg_attr(not(windows), allow(dead_code))]
    Failed(String),
    /// This build has no registry to read.
    #[cfg_attr(windows, allow(dead_code))]
    Unavailable,
}

/// Where a Windows load reads the policy value from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) enum RegistryAuthority {
    /// This machine's registry.
    #[default]
    Native,
    /// A fixed answer, which the tests use in place of the machine's registry.
    #[allow(dead_code)]
    Fixed(RegistryRead),
}

impl RegistryAuthority {
    fn read(&self) -> RegistryRead {
        match self {
            Self::Native => read_native(),
            Self::Fixed(read) => read.clone(),
        }
    }
}

#[cfg(windows)]
fn read_native() -> RegistryRead {
    use guard_runtime_windows_process::{read_machine_registry_string, MachineRegistryString};

    // Python bounds the UTF-8 size. Every UTF-16 unit encodes to at least one
    // UTF-8 byte, so more units than that bound can never fit within it.
    let max_units = usize::try_from(MAX_POLICY_BYTES).unwrap_or(usize::MAX);
    match read_machine_registry_string(r"Software\Policies\HOL\Guard", "PolicyJson", max_units) {
        MachineRegistryString::Missing => RegistryRead::Missing,
        MachineRegistryString::Denied => RegistryRead::Denied,
        MachineRegistryString::NotText => RegistryRead::NotText,
        MachineRegistryString::TooLarge => RegistryRead::TooLarge,
        MachineRegistryString::Text(units) => match String::from_utf16(&units) {
            Ok(text) => RegistryRead::Text(text),
            Err(_) => {
                RegistryRead::Failed("PolicyJson registry value is not valid UTF-16".to_owned())
            }
        },
        MachineRegistryString::Failed(code) => {
            RegistryRead::Failed(format!("managed policy registry read failed: error {code}"))
        }
    }
}

#[cfg(not(windows))]
fn read_native() -> RegistryRead {
    RegistryRead::Unavailable
}

/// The Windows branch of `load_managed_policy` (mdm/policy.py:369).
pub(crate) fn load_registry_policy(source: &ManagedPolicySource) -> ManagedPolicyState {
    let invalid = |detail: &str| {
        ManagedPolicyState::new(
            ManagedPolicyStatus::Invalid,
            REGISTRY_SOURCE,
            "managed_policy_invalid",
        )
        .with_detail(detail)
    };
    let text = match source.registry.read() {
        // No key is no authority. A cache an earlier policy left behind is
        // never promoted to authority on Windows, but it still records a
        // managed machine, so it fails closed rather than reading as absent.
        RegistryRead::Missing => {
            return load_cache(source).unwrap_or_else(|| {
                ManagedPolicyState::new(
                    ManagedPolicyStatus::Absent,
                    REGISTRY_SOURCE,
                    "managed_policy_absent",
                )
            });
        }
        RegistryRead::Denied => {
            return ManagedPolicyState::new(
                ManagedPolicyStatus::Inaccessible,
                REGISTRY_SOURCE,
                "managed_policy_inaccessible",
            );
        }
        RegistryRead::Unavailable => {
            return ManagedPolicyState::new(
                ManagedPolicyStatus::Inaccessible,
                REGISTRY_SOURCE,
                REGISTRY_UNREADABLE,
            );
        }
        RegistryRead::NotText => return invalid("PolicyJson registry value must be a string"),
        RegistryRead::TooLarge => return invalid("managed policy exceeds size limit"),
        RegistryRead::Failed(detail) => return invalid(&detail),
        RegistryRead::Text(text) => text,
    };
    if text.len() as u64 > MAX_POLICY_BYTES {
        return invalid("managed policy exceeds size limit");
    }
    let payload: Value = match serde_json::from_str(&text) {
        Ok(payload) => payload,
        Err(error) => return invalid(&format!("managed policy is not valid JSON: {error}")),
    };
    match parse_managed_policy(&payload) {
        Ok(policy) => {
            if source.write_cache {
                write_cache(&payload, source);
            }
            ManagedPolicyState {
                status: ManagedPolicyStatus::Active,
                source: REGISTRY_SOURCE.to_owned(),
                policy: Some(policy),
                reason_code: None,
                detail: None,
            }
        }
        Err(detail) => invalid(&detail),
    }
}

#[cfg(test)]
#[path = "managed_policy_registry_tests.rs"]
mod tests;
