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
            &bundle,
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
        v1::validate(&bundle, &authority)
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
        persistable(&built.anchored, &bundle)
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
