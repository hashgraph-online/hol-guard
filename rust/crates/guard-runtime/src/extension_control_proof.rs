//! The canonical digests an extension-control approval binds.
//!
//! An approval for a control commit or for first enrollment is granted for
//! one digest. The resident computes that digest from the mutation or the
//! enrollment the caller describes, and the commit plan recomputes it from
//! the layers it is about to seal, so a grant commits only what was approved.

use guard_command::extension_control::{ExtensionControl, ExtensionControlLayer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::guard_store_json::{dumps_sorted, py_strip};

const PREVIEW_SCHEMA: &str = "guard.extension-control-preview.v1";
const PROOF_ACTION: &str = "commit-layers";
const ENROLLMENT_SCHEMA: &str = "guard.extension-control-enrollment.v1";
const ENROLLMENT_ACTION: &str = "enroll-authority";
const MAX_IDENTITY_LENGTH: usize = 256;

pub(crate) const INVALID_REVISION: &str = "native_extension_control_invalid_revision";
pub(crate) const INVALID_CATALOG_DIGEST: &str = "native_extension_control_invalid_catalog_digest";
pub(crate) const INVALID_IDENTITY: &str = "native_extension_control_invalid_identity";
pub(crate) const UNENCODABLE: &str = "native_extension_control_invalid_digest_input";

/// One requested replacement of the control layers.
pub(crate) struct Mutation<'a> {
    pub previous_revision: i64,
    pub catalog_digest: &'a str,
    pub layers: &'a [ExtensionControlLayer],
    pub actor_id: &'a str,
    pub idempotency_key: &'a str,
    pub nonce: &'a str,
}

fn valid_catalog_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn valid_identity(value: &str) -> bool {
    !py_strip(value).is_empty() && value.chars().count() <= MAX_IDENTITY_LENGTH
}

fn control_key(control: &ExtensionControl) -> (&str, &str, &str) {
    (
        control.target.kind.as_str(),
        control.target.target_id.as_str(),
        control.state.as_str(),
    )
}

/// The layers ordered by kind and their controls by target and state, so the
/// digest does not depend on the order a caller listed them in.
fn canonical_layers(layers: &[ExtensionControlLayer]) -> Value {
    let mut ordered: Vec<&ExtensionControlLayer> = layers.iter().collect();
    ordered.sort_by(|left, right| left.kind.as_str().cmp(right.kind.as_str()));
    Value::Array(
        ordered
            .into_iter()
            .map(|layer| {
                let mut controls: Vec<&ExtensionControl> = layer.controls.iter().collect();
                controls.sort_by(|left, right| control_key(left).cmp(&control_key(right)));
                json!({
                    "schema_version": layer.schema_version,
                    "kind": layer.kind.as_str(),
                    "catalog_digest": layer.catalog_digest,
                    "global_lockdown": layer.global_lockdown,
                    "controls": controls
                        .into_iter()
                        .map(|control| json!({
                            "target_kind": control.target.kind.as_str(),
                            "target_id": control.target.target_id,
                            "state": control.state.as_str(),
                        }))
                        .collect::<Vec<_>>(),
                })
            })
            .collect(),
    )
}

/// SHA-256 of `schema NUL length NUL canonical-json`. The canonical form
/// escapes every non-ASCII character, so its length in bytes is its length in
/// characters.
fn framed_digest(schema: &str, payload: &Value) -> Result<String, &'static str> {
    let canonical = dumps_sorted(payload).ok_or(UNENCODABLE)?;
    let framed = format!("{schema}\0{}\0{canonical}", canonical.len());
    Ok(hex::encode(Sha256::digest(framed.as_bytes())))
}

/// The digest a commit proof binds: the action, the identities, the revision
/// the mutation replaces and the canonical layers it writes.
pub(crate) fn mutation_digest(mutation: &Mutation<'_>) -> Result<String, &'static str> {
    if mutation.previous_revision < 0 {
        return Err(INVALID_REVISION);
    }
    if !valid_catalog_digest(mutation.catalog_digest) {
        return Err(INVALID_CATALOG_DIGEST);
    }
    if ![mutation.actor_id, mutation.idempotency_key, mutation.nonce]
        .into_iter()
        .all(valid_identity)
    {
        return Err(INVALID_IDENTITY);
    }
    framed_digest(
        PREVIEW_SCHEMA,
        &json!({
            "action": PROOF_ACTION,
            "actor_id": mutation.actor_id,
            "catalog_digest": mutation.catalog_digest,
            "idempotency_key": mutation.idempotency_key,
            "layers": canonical_layers(mutation.layers),
            "nonce": mutation.nonce,
            "previous_revision": mutation.previous_revision,
            "schema_version": PREVIEW_SCHEMA,
        }),
    )
}

/// The digest a first-enrollment proof binds.
pub(crate) fn enrollment_digest(
    catalog_digest: &str,
    actor_id: &str,
    nonce: &str,
) -> Result<String, &'static str> {
    if !valid_catalog_digest(catalog_digest) {
        return Err(INVALID_CATALOG_DIGEST);
    }
    if ![actor_id, nonce].into_iter().all(valid_identity) {
        return Err(INVALID_IDENTITY);
    }
    framed_digest(
        ENROLLMENT_SCHEMA,
        &json!({
            "action": ENROLLMENT_ACTION,
            "actor_id": actor_id,
            "catalog_digest": catalog_digest,
            "nonce": nonce,
            "schema_version": ENROLLMENT_SCHEMA,
        }),
    )
}

#[cfg(test)]
#[path = "extension_control_proof_tests.rs"]
mod tests;
