//! `validate_synced_policy_bundle` for the `PolicyBundleAuthority` op: assemble
//! the trust root, validate the bundle under its contract, and derive the
//! keyring to persist.

use serde_json::{json, Value};

use crate::policy_bundle_keys::{keys_to_value, Key};
use crate::policy_bundle_keys_ctx::{persistable, verification_context, V2_CONTRACT};
use crate::policy_bundle_op::{document, field, number_field, Fail, Handled};
use crate::policy_bundle_op_keys::context_input;
use crate::policy_bundle_py::Obj;
use crate::policy_bundle_v1 as v1;
use crate::policy_bundle_v2 as v2;

enum Verdict {
    V1(v1::Accepted),
    V2,
    NeedsEvidence,
}

fn validate_v2(
    bundle: &Value,
    trusted: &[Key],
    anchored: &[Key],
    input: &Obj,
    expected_workspace: Option<&str>,
) -> Result<Verdict, Fail> {
    let authority = v2::Authority {
        trusted,
        anchored,
        now_micros: field(input, "now_micros")?.as_i64().ok_or(Fail::Invalid)?,
        key_now: number_field(input, "key_now")?,
    };
    let evidence = match input.get("evidence") {
        None | Some(Value::Null) => None,
        Some(Value::Object(item)) => match item.get("hash") {
            Some(Value::String(hash)) => Some(v2::Evidence::Hash(hash.clone())),
            _ => Some(v2::Evidence::Failed),
        },
        Some(_) => return Err(Fail::Invalid),
    };
    match v2::validate(bundle, &authority, evidence.as_ref()) {
        v2::Outcome::NeedsEvidence => Ok(Verdict::NeedsEvidence),
        v2::Outcome::Rejected(code) => Err(Fail::Code(code)),
        v2::Outcome::Accepted => {
            if let Some(expected) = expected_workspace {
                if bundle.get("workspaceId").and_then(Value::as_str) != Some(expected) {
                    return Err(Fail::from("wrong_workspace"));
                }
            }
            Ok(Verdict::V2)
        }
    }
}

pub(crate) fn synced(input: &Obj) -> Handled {
    let bundle = document(input, "bundle_chunks")?;
    synced_bundle(input, &bundle)
}

fn synced_bundle(input: &Obj, bundle: &Value) -> Handled {
    let given = context_input(input)?;
    let built = verification_context(
        given.stored_keyring,
        &given.sync_keys,
        given.managed_configured,
        &given.managed_keys,
        given.provenance_present,
        given.expected_workspace,
    );
    let is_v2 = bundle.get("contractVersion").and_then(Value::as_str) == Some(V2_CONTRACT);
    let verdict = if is_v2 {
        validate_v2(
            bundle,
            &built.trusted,
            &built.anchored,
            input,
            given.expected_workspace,
        )
    } else {
        let authority = v1::Authority {
            trusted: &built.trusted,
            anchored: &built.anchored,
            expected_workspace: given.expected_workspace,
            now: number_field(input, "now")?,
            daemon_version: crate::policy_bundle_op::text_field(input, "daemon_version")?,
        };
        v1::validate(bundle, &authority)
            .map(Verdict::V1)
            .map_err(Fail::from)
    };
    let anchored = keys_to_value(&built.anchored);
    let verdict = match verdict {
        Ok(verdict) => verdict,
        Err(Fail::Code(code)) => {
            return Ok(json!({ "error": code, "anchored_keys": anchored }));
        }
        Err(other) => return Err(other),
    };
    if matches!(verdict, Verdict::NeedsEvidence) {
        return Ok(json!({ "needs_evidence": true }));
    }
    let (payload_keys, payload_hash) = match &verdict {
        Verdict::V1(accepted) => (json!(accepted.keys), json!(accepted.payload_hash)),
        _ => (Value::Null, Value::Null),
    };
    let updated = if built.managed_configured {
        Vec::new()
    } else {
        persistable(&built.anchored, bundle)
    };
    Ok(json!({
        "ok": true,
        "contract": if is_v2 { "v2" } else { "v1" },
        "payload_keys": payload_keys,
        "payload_hash": payload_hash,
        "updated_keys": keys_to_value(&updated),
        "anchored_keys": anchored,
    }))
}

/// Fields a downgrade check compares; the rest of a checkpoint or bundle is
/// left out so both sides are judged on the same signed identity.
const ORDERING_KEYS: [&str; 5] = [
    "bundleVersion",
    "bundleHash",
    "payloadHash",
    "issuedAt",
    "workspaceId",
];

fn ordering_view(source: &Obj) -> Value {
    let view: Obj = ORDERING_KEYS
        .iter()
        .filter_map(|key| Some(((*key).to_owned(), source.get(*key)?.clone())))
        .collect();
    Value::Object(view)
}

/// The document a caller enforces: the whole bundle under the v2 contract, or
/// the signed payload fields of a v1 bundle with its computed payload hash.
fn enforced_document(bundle: &Obj, verdict: &Value) -> Result<Obj, Fail> {
    if verdict.get("contract").and_then(Value::as_str) == Some("v2") {
        return Ok(bundle.clone());
    }
    let (Some(Value::Array(keys)), Some(Value::String(hash))) =
        (verdict.get("payload_keys"), verdict.get("payload_hash"))
    else {
        return Err(Fail::Invalid);
    };
    let mut payload = Obj::new();
    for key in keys.iter().filter_map(Value::as_str) {
        if key != "payloadHash" {
            let value = bundle.get(key).ok_or(Fail::Invalid)?;
            payload.insert(key.to_owned(), value.clone());
        }
    }
    payload.insert("payloadHash".to_owned(), Value::String(hash.clone()));
    Ok(payload)
}

fn rejected(code: &str, verdict: &Value) -> Handled {
    let anchored = verdict.get("anchored_keys").cloned().unwrap_or(Value::Null);
    Ok(json!({ "error": code, "anchored_keys": anchored }))
}

/// `validate_synced` for a bundle already held in the store: it must also be
/// live authority and must not be older than the last accepted checkpoint.
pub(crate) fn cached(input: &Obj) -> Handled {
    let bundle = document(input, "bundle_chunks")?;
    let verdict = synced_bundle(input, &bundle)?;
    let checkpoint = match input.get("acceptance_checkpoint_chunks") {
        None | Some(Value::Null) => Value::Null,
        Some(_) => document(input, "acceptance_checkpoint_chunks")?,
    };
    judge(&bundle, verdict, &checkpoint)
}

/// Applies the live-authority and replay checks to an accepted verdict; any
/// other verdict passes through unchanged.
pub(crate) fn judge(bundle: &Value, verdict: Value, checkpoint: &Value) -> Handled {
    if verdict.get("ok").and_then(Value::as_bool) != Some(true) {
        return Ok(verdict);
    }
    let Value::Object(bundle) = bundle else {
        return Err(Fail::Invalid);
    };
    let enforced = enforced_document(bundle, &verdict)?;
    if !v1::is_enforceable(&enforced) {
        return rejected("inactive_rollout_state", &verdict);
    }
    if let (Value::Object(checkpoint), Value::Object(candidate)) =
        (checkpoint, ordering_view(&enforced))
    {
        if v1::is_downgrade(&ordering_view(checkpoint), &candidate) {
            return rejected("bundle_version_downgrade", &verdict);
        }
    }
    Ok(verdict)
}

#[path = "policy_bundle_op_sync_ack.rs"]
pub(crate) mod sync_ack;

#[cfg(test)]
#[path = "policy_bundle_op_synced_tests.rs"]
mod tests;
