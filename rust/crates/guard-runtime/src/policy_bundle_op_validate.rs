//! Validation, hashing, transition and downgrade kinds of the
//! `PolicyBundleAuthority` op.

use serde_json::{json, Value};

use crate::policy_bundle_op::{
    document, field, keys_field, number_field, object_document, optional_text, text_field, Fail,
    Handled,
};
use crate::policy_bundle_op_page::{page_offset, page_text};
use crate::policy_bundle_py::{obj, Obj};
use crate::policy_bundle_v1 as v1;
use crate::policy_bundle_v2 as v2;
use crate::policy_bundle_v2_ack as ack;

fn validate_v1(input: &Obj) -> Handled {
    let bundle = document(input, "bundle_chunks")?;
    let (trusted, anchored) = (
        keys_field(input, "trusted_keys")?,
        keys_field(input, "anchored_keys")?,
    );
    let authority = v1::Authority {
        trusted: &trusted,
        anchored: &anchored,
        expected_workspace: optional_text(input, "expected_workspace_id")?,
        now: number_field(input, "now")?,
        daemon_version: text_field(input, "daemon_version")?,
    };
    let accepted = v1::validate(&bundle, &authority)?;
    Ok(json!({ "payload_keys": accepted.keys, "payload_hash": accepted.payload_hash }))
}

fn evidence(input: &Obj) -> Result<Option<v2::Evidence>, Fail> {
    match input.get("evidence") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(item)) => match item.get("hash") {
            Some(Value::String(hash)) => Ok(Some(v2::Evidence::Hash(hash.clone()))),
            _ if item.get("error").and_then(Value::as_bool) == Some(true) => {
                Ok(Some(v2::Evidence::Failed))
            }
            _ => Err(Fail::Invalid),
        },
        Some(_) => Err(Fail::Invalid),
    }
}

fn validate_v2(input: &Obj) -> Handled {
    let bundle = document(input, "bundle_chunks")?;
    let (trusted, anchored) = (
        keys_field(input, "trusted_keys")?,
        keys_field(input, "anchored_keys")?,
    );
    let authority = v2::Authority {
        trusted: &trusted,
        anchored: &anchored,
        now_micros: field(input, "now_micros")?.as_i64().ok_or(Fail::Invalid)?,
        key_now: number_field(input, "key_now")?,
    };
    match v2::validate(&bundle, &authority, evidence(input)?.as_ref()) {
        v2::Outcome::Accepted => Ok(json!({ "ok": true })),
        v2::Outcome::NeedsEvidence => Ok(json!({ "needs_evidence": true })),
        v2::Outcome::Rejected(code) => Err(Fail::Code(code)),
    }
}

fn transition(input: &Obj) -> Handled {
    let bundle = object_document(input, "bundle_chunks")?;
    let present = |name: &str| input.get(name).filter(|value| !value.is_null());
    let state = v2::Transition {
        current_version: present("current_version"),
        current_hash: present("current_hash"),
        expected_last_good_version: present("expected_last_good_version"),
        expected_last_good_hash: present("expected_last_good_hash"),
    };
    match v2::transition_error(&bundle, &state) {
        Some(code) => Err(Fail::from(code)),
        None => Ok(json!({ "ok": true })),
    }
}

fn acknowledgement(input: &Obj) -> Handled {
    let Some(item) = obj(input.get("ack")) else {
        return Err(Fail::Invalid);
    };
    match ack::validate(item, obj(input.get("previous"))) {
        Ok(()) => Ok(json!({ "ok": true })),
        Err(code) => Err(Fail::from(code)),
    }
}

fn downgrade(input: &Obj) -> Handled {
    let candidate = object_document(input, "bundle_chunks")?;
    let accepted = match input.get("accepted_chunks") {
        None | Some(Value::Null) => Value::Null,
        Some(_) => document(input, "accepted_chunks")?,
    };
    Ok(json!({ "value": v1::is_downgrade(&accepted, &candidate) }))
}

fn slim_bundle(input: &Obj) -> Result<&Obj, Fail> {
    obj(input.get("bundle")).ok_or(Fail::Invalid)
}

pub(crate) fn handle(kind: &str, input: &Obj) -> Option<Handled> {
    Some(match kind {
        "validate_v1" => validate_v1(input),
        "validate_v2" => validate_v2(input),
        "v1_bundle_hash" => object_document(input, "bundle_chunks").and_then(|bundle| {
            let hash = v1::bundle_hash(&bundle)?;
            Ok(json!({ "value": hash }))
        }),
        "v1_canonical_payload" => object_document(input, "bundle_chunks")
            .and_then(|bundle| Ok(v1::canonical_payload(&bundle)?))
            .and_then(|bytes| page_text(bytes, page_offset(input)?)),
        "v1_payload_hash" => object_document(input, "bundle_chunks").and_then(|bundle| {
            let hash = v1::payload_hash(&bundle)?;
            Ok(json!({ "value": hash }))
        }),
        "v2_bundle_hash" => object_document(input, "bundle_chunks").and_then(|bundle| {
            let hash = v2::bundle_hash(&bundle)?;
            Ok(json!({ "value": hash }))
        }),
        "v2_canonical_payload" => object_document(input, "bundle_chunks")
            .and_then(|bundle| Ok(v2::canonical_payload(&bundle)?))
            .and_then(|bytes| page_text(bytes, page_offset(input)?)),
        "v2_transition" => transition(input),
        "v2_acknowledgement" => acknowledgement(input),
        "is_downgrade" => downgrade(input),
        "is_enforceable" => slim_bundle(input).map(|b| json!({ "value": v1::is_enforceable(b) })),
        "daemon_version_supported" => slim_bundle(input).and_then(|b| {
            let current = text_field(input, "daemon_version")?;
            Ok(json!({ "value": v1::daemon_version_supported(b, current) }))
        }),
        _ => return None,
    })
}
