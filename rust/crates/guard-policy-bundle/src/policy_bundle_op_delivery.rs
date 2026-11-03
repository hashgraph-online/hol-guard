//! Decision materialization and delivery/acknowledgement kinds of the
//! `PolicyBundleAuthority` op.

use serde_json::{json, Value};

use crate::policy_bundle_decisions::build;
use crate::policy_bundle_delivery::{
    ack_payload, effective_ack, has_extension_semantics, validate_delivery, validate_managed,
    AckRequest, EffectiveRequest, Managed,
};
use crate::policy_bundle_families::saved_families;
use crate::policy_bundle_op::{
    field, flag, object_document, optional_text, text_field, Fail, Handled,
};
use crate::policy_bundle_op_page::{page_offset, page_rows};
use crate::policy_bundle_py::{obj, Obj};

fn decisions(input: &Obj) -> Handled {
    let bundle = object_document(input, "bundle_chunks")?;
    let rows = build(
        &bundle,
        text_field(input, "device_id")?,
        text_field(input, "device_name")?,
    );
    page_rows(&rows, page_offset(input)?)
}

fn families(input: &Obj) -> Handled {
    let rule = obj(input.get("rule")).ok_or(Fail::Invalid)?;
    Ok(json!({ "families": saved_families(rule) }))
}

fn delivery(input: &Obj) -> Handled {
    let bundle = object_document(input, "bundle_chunks")?;
    validate_delivery(
        field(input, "delivery")?,
        &bundle,
        optional_text(input, "workspace_id")?,
        text_field(input, "device_id")?,
        input.get("runtime_summary"),
    )?;
    Ok(json!({ "ok": true }))
}

fn managed(input: &Obj) -> Handled {
    let bundle = object_document(input, "bundle_chunks")?;
    let outcome = validate_managed(
        &bundle,
        flag(input, "provided")?,
        field(input, "delivery")?,
        optional_text(input, "workspace_id")?,
        text_field(input, "device_id")?,
        input.get("runtime_summary"),
        optional_text(input, "expected_projection")?,
    );
    match outcome {
        Managed::NotApplicable => Ok(json!({ "applicable": false })),
        Managed::Accepted => Ok(json!({ "applicable": true })),
        Managed::Rejected(code) => Err(Fail::from(code)),
    }
}

fn applied<'a>(input: &'a Obj, name: &str) -> Option<&'a Value> {
    input.get(name).filter(|value| !value.is_null())
}

fn acknowledgement(input: &Obj) -> Handled {
    let bundle = object_document(input, "bundle_chunks")?;
    let request = AckRequest {
        device_id: text_field(input, "device_id")?,
        device_name: text_field(input, "device_name")?,
        bundle: &bundle,
        synced_at: text_field(input, "synced_at")?,
        status: text_field(input, "status")?,
        previous: obj(input.get("previous")),
        delivery: obj(input.get("delivery")),
        applied_revision: applied(input, "applied_revision"),
        applied_digest: applied(input, "applied_digest"),
    };
    Ok(json!({ "ack": ack_payload(&request)? }))
}

fn effective(input: &Obj) -> Handled {
    let bundle = object_document(input, "effective_chunks")?;
    let request = EffectiveRequest {
        device_id: text_field(input, "device_id")?,
        device_name: text_field(input, "device_name")?,
        effective: &bundle,
        validated: obj(input.get("validated")),
        delivery: obj(input.get("delivery")),
        stored: obj(input.get("stored")),
        synced_at: text_field(input, "synced_at")?,
    };
    Ok(json!({ "ack": effective_ack(&request)? }))
}

pub(crate) fn handle(kind: &str, input: &Obj) -> Option<Handled> {
    Some(match kind {
        "build_decisions" => decisions(input),
        "saved_families" => families(input),
        "delivery_validate" => delivery(input),
        "managed_delivery" => managed(input),
        "has_extension_semantics" => object_document(input, "bundle_chunks")
            .map(|bundle| json!({ "value": has_extension_semantics(&bundle) })),
        "ack_payload" => acknowledgement(input),
        "effective_ack" => effective(input),
        _ => return None,
    })
}
