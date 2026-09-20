//! Bounded consumption of authenticated built-in command controls.
//!
//! The supported generic shell producer has no command-extension observations.
//! The bounded sensitive-read producer likewise has no command observations.
//! These facts are proven against the real Python registry/resolver. Other
//! Read/MCP and typed command facts are not modeled here.

use guard_contracts::GuardHookEnvelopeV2;
use guard_policy_snapshot::scoped_authority::{ControlTargetKind, ManagedAuthority};
use serde::Deserialize;
use std::sync::OnceLock;

const UNSUPPORTED: &str = "native_scoped_managed_policy_unsupported";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    schema: String,
    catalog_digest: String,
    extension_ids: Vec<String>,
    permission_ids: Vec<String>,
}

fn catalog() -> &'static Catalog {
    static CATALOG: OnceLock<Catalog> = OnceLock::new();
    CATALOG.get_or_init(|| {
        let value: Catalog =
            serde_json::from_str(include_str!("policy_scoped_managed_catalog.json"))
                .expect("source-bound managed catalog is valid");
        assert_eq!(value.schema, "guard-native-built-in-controls.v1");
        assert_eq!(value.catalog_digest.len(), 64);
        assert!(value
            .catalog_digest
            .bytes()
            .all(|v| v.is_ascii_hexdigit() && !v.is_ascii_uppercase()));
        assert!(value.extension_ids.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(value
            .permission_ids
            .windows(2)
            .all(|pair| pair[0] < pair[1]));
        value
    })
}

pub(crate) fn catalog_digest() -> &'static str {
    &catalog().catalog_digest
}

/// Validate the whole authority before resident storage can acknowledge it.
/// Delegated/package and unknown targets are absent from this exact catalog.
pub(crate) fn validate_authority(authority: Option<&ManagedAuthority>) -> Result<(), String> {
    let Some(authority) = authority else {
        return Ok(());
    };
    let catalog = catalog();
    if authority.catalog_digest() != catalog.catalog_digest {
        return Err("native_scoped_managed_catalog_mismatch".to_owned());
    }
    for control in authority.controls() {
        let targets = match control.target_kind() {
            ControlTargetKind::Extension => &catalog.extension_ids,
            ControlTargetKind::Permission => &catalog.permission_ids,
        };
        if targets
            .binary_search_by(|value| value.as_str().cmp(control.target_id()))
            .is_err()
        {
            return Err(UNSUPPORTED.to_owned());
        }
    }
    Ok(())
}

/// Generic signed allow and Observe cannot lower a managed block. Explicit
/// enabled controls are not approval grants. Other producer shapes refuse.
pub(crate) fn request_is_blocked(
    authority: Option<&ManagedAuthority>,
    envelope: &GuardHookEnvelopeV2,
    harness: &str,
) -> Result<bool, String> {
    validate_authority(authority)?;
    let Some(authority) = authority else {
        return Ok(false);
    };
    // Reuse the exact bounded generic command classifier. Merely having an
    // exact digest is insufficient: typed/runtime commands can have one too.
    crate::policy_scoped_request::generic_shell_artifact(envelope, harness)
        .map(|_| ())
        .or_else(|_| {
            crate::policy_scoped_sensitive_read::derive_sensitive_read_artifact(envelope, harness)
                .map(|_| ())
        })
        .map_err(|_| UNSUPPORTED.to_owned())?;
    Ok(authority.global_lockdown())
}
