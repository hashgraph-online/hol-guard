//! Signed workspace activation for hosted execution.
//!
//! On a device an external extension runs only after a local administrator
//! enables it, and a signed cloud layer can disable but never enable it.
//! Hosted execution has no local administrator, so it uses its own authority:
//! a workspace activation signed by the hosting service's key, verified here
//! against a public key fixed when the evaluator starts. This layer is
//! accepted only by the cloud action evaluator; device-side control layers
//! and their composition are unchanged.

use std::collections::BTreeMap;

use base64::Engine;
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::Deserialize;
use serde_json::Value;

use crate::cloud_action_binding::valid_label;
use crate::cloud_action_canonical::canonical_bytes;

pub const ACTIVATION_SCHEMA: &str = "guard.cloud-workspace-activation.v1";
pub const MAX_ACTIVATION_CONTROLS: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActivationState {
    Enabled,
    Disabled,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationControl {
    extension_id: String,
    state: ActivationState,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationPayload {
    schema: String,
    workspace_id: String,
    catalog_digest: String,
    global_lockdown: bool,
    controls: Vec<ActivationControl>,
    issued_at: String,
    expires_at: String,
}

/// The signed document as it arrives in a request.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedActivation {
    pub payload: Value,
    pub signature: String,
}

/// A verified activation for one workspace and catalog.
#[derive(Debug, Default)]
pub struct VerifiedActivation {
    pub global_lockdown: bool,
    states: BTreeMap<String, ActivationState>,
    pub digest: Option<String>,
}

impl VerifiedActivation {
    /// External extensions run only when this activation enables them.
    pub fn external_enabled(&self, extension_id: &str) -> bool {
        self.states.get(extension_id) == Some(&ActivationState::Enabled)
    }
}

pub struct ActivationContext<'a> {
    pub workspace_id: &'a str,
    pub catalog_digest: &'a str,
    /// RFC 3339 UTC evaluation time supplied by the hosting service.
    pub now: &'a str,
}

/// Verify a signed activation. Absent activation means no external extension
/// is enabled; any present activation that fails a check is an error, never
/// silently ignored.
pub fn verify_activation(
    signed: Option<&SignedActivation>,
    public_key: Option<&[u8; 32]>,
    context: &ActivationContext<'_>,
) -> Result<VerifiedActivation, &'static str> {
    let Some(signed) = signed else {
        return Ok(VerifiedActivation::default());
    };
    let key = public_key.ok_or("activation_key_unavailable")?;
    let message = canonical_bytes(&signed.payload).map_err(|_| "activation_invalid")?;
    let signature = base64::engine::general_purpose::STANDARD
        .decode(signed.signature.as_bytes())
        .map_err(|_| "activation_invalid")?;
    UnparsedPublicKey::new(&ED25519, key)
        .verify(&message, &signature)
        .map_err(|_| "activation_invalid")?;
    let payload: ActivationPayload =
        serde_json::from_value(signed.payload.clone()).map_err(|_| "activation_invalid")?;
    if payload.schema != ACTIVATION_SCHEMA {
        return Err("activation_unsupported_version");
    }
    if payload.workspace_id != context.workspace_id
        || payload.catalog_digest != context.catalog_digest
    {
        return Err("activation_mismatch");
    }
    if !is_utc_timestamp(&payload.issued_at)
        || !is_utc_timestamp(&payload.expires_at)
        || !is_utc_timestamp(context.now)
    {
        return Err("activation_invalid");
    }
    // Fixed-width UTC timestamps order lexically.
    if payload.issued_at.as_str() > context.now || payload.expires_at.as_str() <= context.now {
        return Err("activation_expired");
    }
    if payload.controls.len() > MAX_ACTIVATION_CONTROLS {
        return Err("limit");
    }
    let mut states = BTreeMap::new();
    for control in payload.controls {
        if !valid_label(&control.extension_id) {
            return Err("activation_invalid");
        }
        // A disable for the same extension always wins over an enable.
        let entry = states.entry(control.extension_id).or_insert(control.state);
        if control.state == ActivationState::Disabled {
            *entry = ActivationState::Disabled;
        }
    }
    Ok(VerifiedActivation {
        global_lockdown: payload.global_lockdown,
        states,
        digest: Some(crate::cloud_action_canonical::domain_digest(
            ACTIVATION_SCHEMA,
            &[&message],
        )),
    })
}

/// `YYYY-MM-DDTHH:MM:SSZ`, the only accepted form, so string order is time order.
pub fn is_utc_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 20
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            4 | 7 => *byte == b'-',
            10 => *byte == b'T',
            13 | 16 => *byte == b':',
            19 => *byte == b'Z',
            _ => byte.is_ascii_digit(),
        })
}

/// Parse a 32-byte hex Ed25519 public key.
pub fn parse_public_key(hex_key: &str) -> Result<[u8; 32], &'static str> {
    let bytes = hex::decode(hex_key.trim()).map_err(|_| "activation_key_invalid")?;
    bytes.try_into().map_err(|_| "activation_key_invalid")
}
