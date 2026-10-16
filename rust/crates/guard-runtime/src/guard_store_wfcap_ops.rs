//! The workflow-capability operations, ported statement for statement from
//! the original Python store: issue, claim, revoke, lookup and receipt
//! lookup. Each runs against one transaction; control-blob writes are
//! recorded on the context for the caller to persist.

use rusqlite::{Connection, Row};
use serde_json::{Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_wfcap_authority::{
    advance_state, append_revocation, create_state, load_and_validate,
};
use crate::guard_store_wfcap_claim::claim;
use crate::guard_store_wfcap_contract::{
    claim_sha256, decode_signed_claim, decode_signed_receipt, int, text, validate_signed_claim,
    verify_claim, verify_claim_signature, verify_receipt,
};
use crate::guard_store_wfcap_control::{
    finalize_transition, load_validate_and_observe, prepare_transition,
};
use crate::guard_store_wfcap_ctx::{int_at, optional_text_at, text_at, Ctx};
use crate::guard_store_wfcap_error::{cap, is_integrity, WfError, WfResult};
use crate::guard_store_wfcap_frame::{canonical, ident, is_reason_code, private_reference};
use crate::guard_store_wfcap_ledger::{
    append_transition, build_transition, claim_event_payload, event_payload, insert_event,
    TransitionInput,
};
use crate::guard_store_wfcap_schema::ensure_schema;

pub(crate) const CLAIM_COLUMNS: &str =
    "signed_claim_json, key_id, issued_at, not_before, expires_at, \
     max_uses, used_count, revoked_at, revocation_code, approval_provenance_id, nonce";

/// Validation that runs before the signing key is required.
pub(crate) fn prelude(op: &str, args: &Args<'_>) -> WfResult<()> {
    match op {
        "issue" => {
            let signed = signed_claim(args)?;
            let provenance = args.str("approval_provenance_id")?;
            ident("approval_provenance_id", provenance)?;
            if provenance != text(&signed["claim"], "approval_provenance_id") {
                return cap("capability_approval_binding_mismatch");
            }
            Ok(())
        }
        "claim" => {
            ident("capability_id", args.str("capability_id")?)?;
            ident("invocation_id", args.str("invocation_id")?)?;
            for name in [
                "expected_subject_id",
                "expected_task_id",
                "expected_issuer_id",
                "expected_approval_provenance_id",
            ] {
                ident(name, args.str(name)?)?;
            }
            Ok(())
        }
        "revoke" => {
            ident("capability_id", args.str("capability_id")?)?;
            if !is_reason_code(args.str("reason_code")?) {
                return cap("invalid_reason_code");
            }
            Ok(())
        }
        "lookup" => ident("capability_id", args.str("capability_id")?),
        "receipt_lookup" => {
            let (name, value) = selector(args)?;
            ident(name, value)
        }
        _ => Err(WfError::Store(crate::guard_store_db::StoreError::Invalid(
            "native_guard_store_args_invalid",
        ))),
    }
}

/// The operation proper; returns the Python-visible result.
pub(crate) fn run(op: &str, ctx: &mut Ctx<'_>, args: &Args<'_>) -> WfResult<Value> {
    match op {
        "issue" => issue(ctx, args),
        "claim" => claim(ctx, args),
        "revoke" => revoke(ctx, args),
        "lookup" => lookup(ctx, args),
        _ => receipt_lookup(ctx, args),
    }
}

pub(crate) fn signed_claim(args: &Args<'_>) -> WfResult<Value> {
    let Ok(signed) = serde_json::from_str::<Value>(args.str("signed_json")?) else {
        return cap("invalid_signed_capability");
    };
    validate_signed_claim(&signed)?;
    Ok(signed)
}

pub(crate) fn selector<'a>(args: &Args<'a>) -> WfResult<(&'static str, &'a str)> {
    let receipt = args.opt_str("receipt_id")?;
    let invocation = args.opt_str("invocation_id")?;
    match (receipt, invocation) {
        (Some(value), None) => Ok(("receipt_id", value)),
        (None, Some(value)) => Ok(("invocation_id", value)),
        _ => cap("receipt_lookup_requires_exact_selector"),
    }
}

pub(crate) fn integrity_as(error: rusqlite::Error, code: &str) -> WfError {
    let mapped = WfError::from(error);
    if is_integrity(&mapped) {
        WfError::Capability(code.to_owned())
    } else {
        mapped
    }
}

pub(crate) struct ClaimRow {
    pub(crate) encoded: String,
    pub(crate) key_id: String,
    pub(crate) issued_at: String,
    pub(crate) not_before: String,
    pub(crate) expires_at: String,
    pub(crate) max_uses: i64,
    pub(crate) used_count: i64,
    pub(crate) revoked_at: Option<String>,
    pub(crate) revocation_code: Option<String>,
    pub(crate) provenance: String,
    pub(crate) nonce: String,
}

pub(crate) fn read_claim_row(row: &Row<'_>) -> WfResult<ClaimRow> {
    Ok(ClaimRow {
        encoded: text_at(row, 0)?,
        key_id: text_at(row, 1)?,
        issued_at: text_at(row, 2)?,
        not_before: text_at(row, 3)?,
        expires_at: text_at(row, 4)?,
        max_uses: int_at(row, 5)?,
        used_count: int_at(row, 6)?,
        revoked_at: optional_text_at(row, 7)?,
        revocation_code: optional_text_at(row, 8)?,
        provenance: text_at(row, 9)?,
        nonce: text_at(row, 10)?,
    })
}

pub(crate) fn fetch_claim_row(
    conn: &Connection,
    capability_id: &str,
) -> WfResult<Option<ClaimRow>> {
    let sql =
        format!("select {CLAIM_COLUMNS} from guard_workflow_capabilities where capability_id = ?");
    let mut statement = conn.prepare(&sql)?;
    let mut rows = statement.query([capability_id])?;
    match rows.next()? {
        Some(row) => Ok(Some(read_claim_row(row)?)),
        None => Ok(None),
    }
}

/// `_validate_claim_row`.
pub(crate) fn validate_claim_row(
    signed: &Value,
    row: &ClaimRow,
    capability_id: &str,
) -> WfResult<()> {
    let claim = &signed["claim"];
    let matches = text(claim, "capability_id") == capability_id
        && text(claim, "approval_provenance_id") == row.provenance
        && text(claim, "nonce") == row.nonce
        && text(signed, "key_id") == row.key_id
        && text(claim, "issued_at") == row.issued_at
        && text(claim, "not_before") == row.not_before
        && text(claim, "expires_at") == row.expires_at
        && int(claim, "max_uses") == row.max_uses;
    if !matches {
        return cap("capability_row_binding_invalid");
    }
    Ok(())
}

fn issue(ctx: &mut Ctx<'_>, args: &Args<'_>) -> WfResult<Value> {
    let signed = signed_claim(args)?;
    let provenance = args.str("approval_provenance_id")?;
    let claim = &signed["claim"];
    verify_claim(&signed, &ctx.key, &ctx.key_id, &ctx.now, &claim["binding"])?;
    let encoded = canonical(&signed);
    ensure_schema(ctx.conn, &ctx.now)?;
    let control = load_validate_and_observe(ctx, true)?;
    let capability_id = text(claim, "capability_id");
    ctx.conn
        .execute(
            "insert into guard_workflow_capabilities (capability_id, approval_provenance_id, nonce, \
             signed_claim_json, key_id, issued_at, not_before, expires_at, max_uses, used_count, \
             revoked_at, revocation_code) values (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, null, null)",
            (
                capability_id,
                provenance,
                text(claim, "nonce"),
                &encoded,
                &ctx.key_id,
                text(claim, "issued_at"),
                text(claim, "not_before"),
                text(claim, "expires_at"),
                int(claim, "max_uses"),
            ),
        )
        .map_err(|error| integrity_as(error, "capability_already_exists"))?;
    let mut extra = Map::new();
    extra.insert(
        "approval_provenance_ref".to_owned(),
        Value::from(private_reference("approval-provenance", provenance)),
    );
    extra.insert("max_uses".to_owned(), Value::from(int(claim, "max_uses")));
    extra.insert(
        "task_ref".to_owned(),
        Value::from(private_reference("task", text(claim, "task_id"))),
    );
    let payload = event_payload(capability_id, None, extra.clone());
    let event_id = insert_event(
        ctx.conn,
        "workflow_capability.issued",
        capability_id,
        None,
        &ctx.now,
        extra,
    )?;
    let state = create_state(ctx, &signed)?;
    let transition = build_transition(
        ctx,
        TransitionInput {
            signed_claim: &signed,
            signed_state: &state,
            sequence: control.committed_sequence + 1,
            previous: &control.committed_head_sha256,
            kind: "issued",
            event_id,
            event_name: "workflow_capability.issued",
            event_payload: &payload,
            occurred_at: &ctx.now.clone(),
            use_number: None,
            receipt_id: None,
            revocation_id: None,
        },
    )?;
    let pending = prepare_transition(ctx, &control, &transition)?;
    append_transition(ctx.conn, &transition)?;
    finalize_transition(ctx, &pending)?;
    Ok(Value::Null)
}

fn revoke(ctx: &mut Ctx<'_>, args: &Args<'_>) -> WfResult<Value> {
    let capability_id = args.str("capability_id")?;
    let reason_code = args.str("reason_code")?;
    ensure_schema(ctx.conn, &ctx.now)?;
    let control = load_validate_and_observe(ctx, false)?;
    let Some(row) = fetch_claim_row(ctx.conn, capability_id)? else {
        return Ok(Value::Bool(false));
    };
    let signed = decode_signed_claim(&row.encoded)?;
    validate_claim_row(&signed, &row, capability_id)?;
    verify_claim_signature(&signed, &ctx.key, &ctx.key_id)?;
    let loaded = load_and_validate(
        ctx,
        &signed,
        row.used_count,
        row.revoked_at.as_deref(),
        row.revocation_code.as_deref(),
    )?;
    let state = loaded.state;
    if state.revocation_id.is_some() {
        return Ok(Value::Bool(false));
    }
    let revocation_id = args.str("revocation_id")?;
    let now = ctx.now.clone();
    append_revocation(ctx, &signed, reason_code, &now, revocation_id)?;
    let updated = ctx.conn.execute(
        "update guard_workflow_capabilities set revoked_at = ?, revocation_code = ? \
         where capability_id = ? and revoked_at is null",
        (&now, reason_code, capability_id),
    )?;
    if updated != 1 {
        return Ok(Value::Bool(false));
    }
    let mut extra = Map::new();
    extra.insert(
        "revocation_ref".to_owned(),
        Value::from(private_reference("revocation-code", reason_code)),
    );
    let payload = event_payload(capability_id, None, extra.clone());
    let event_id = insert_event(
        ctx.conn,
        "workflow_capability.revoked",
        capability_id,
        None,
        &now,
        extra,
    )?;
    let signed_state = advance_state(ctx, &state, None, Some(revocation_id), Some(&now))?;
    let transition = build_transition(
        ctx,
        TransitionInput {
            signed_claim: &signed,
            signed_state: &signed_state,
            sequence: control.committed_sequence + 1,
            previous: &control.committed_head_sha256,
            kind: "revoked",
            event_id,
            event_name: "workflow_capability.revoked",
            event_payload: &payload,
            occurred_at: &now,
            use_number: None,
            receipt_id: None,
            revocation_id: Some(revocation_id),
        },
    )?;
    let pending = prepare_transition(ctx, &control, &transition)?;
    append_transition(ctx.conn, &transition)?;
    finalize_transition(ctx, &pending)?;
    Ok(Value::Bool(true))
}

/// `load_validated_workflow_capability`.
pub(crate) fn load_validated(ctx: &Ctx<'_>, capability_id: &str) -> WfResult<Option<Value>> {
    let Some(row) = fetch_claim_row(ctx.conn, capability_id)? else {
        return Ok(None);
    };
    let signed = decode_signed_claim(&row.encoded)?;
    validate_claim_row(&signed, &row, capability_id)?;
    verify_claim_signature(&signed, &ctx.key, &ctx.key_id)?;
    load_and_validate(
        ctx,
        &signed,
        row.used_count,
        row.revoked_at.as_deref(),
        row.revocation_code.as_deref(),
    )?;
    Ok(Some(signed))
}

fn lookup(ctx: &mut Ctx<'_>, args: &Args<'_>) -> WfResult<Value> {
    ensure_schema(ctx.conn, &ctx.now)?;
    load_validate_and_observe(ctx, false)?;
    Ok(load_validated(ctx, args.str("capability_id")?)?.unwrap_or(Value::Null))
}

fn receipt_lookup(ctx: &mut Ctx<'_>, args: &Args<'_>) -> WfResult<Value> {
    let (name, value) = selector(args)?;
    ensure_schema(ctx.conn, &ctx.now)?;
    load_validate_and_observe(ctx, false)?;
    let sql = format!(
        "select r.receipt_id, r.capability_id, r.task_id, r.invocation_id, \
         r.approval_provenance_id as receipt_approval_provenance_id, \
         r.signed_receipt_json, r.claimed_at, r.use_number, r.event_id, \
         e.event_name, e.payload_json as event_payload_json, e.occurred_at \
         from guard_workflow_capability_receipts r \
         left join guard_events e on e.event_id = r.event_id where r.{name} = ?"
    );
    let mut statement = ctx.conn.prepare(&sql)?;
    let mut rows = statement.query([value])?;
    let Some(row) = rows.next()? else {
        return Ok(Value::Null);
    };
    let duplicated = (
        text_at(row, 0)?,
        text_at(row, 1)?,
        text_at(row, 2)?,
        text_at(row, 3)?,
        text_at(row, 4)?,
        text_at(row, 6)?,
        int_at(row, 7)?,
        int_at(row, 8)?,
    );
    let (encoded, event_name, event_payload_json, occurred_at) = (
        text_at(row, 5)?,
        text_at(row, 9)?,
        text_at(row, 10)?,
        text_at(row, 11)?,
    );
    drop(rows);
    drop(statement);
    let Some(signed_claim) = load_validated(ctx, &duplicated.1)? else {
        return cap("receipt_claim_missing");
    };
    let signed_receipt = decode_signed_receipt(&encoded)?;
    verify_receipt(&signed_receipt, &ctx.key, &ctx.key_id)?;
    let receipt = &signed_receipt["receipt"];
    let signed_values = (
        text(receipt, "receipt_id").to_owned(),
        text(receipt, "capability_id").to_owned(),
        text(receipt, "task_id").to_owned(),
        text(receipt, "invocation_id").to_owned(),
        text(receipt, "approval_provenance_id").to_owned(),
        text(receipt, "claimed_at").to_owned(),
        int(receipt, "use_number"),
        int(receipt, "event_id"),
    );
    if duplicated != signed_values {
        return cap("receipt_row_binding_invalid");
    }
    let claim = &signed_claim["claim"];
    if text(receipt, "capability_id") != text(claim, "capability_id")
        || text(receipt, "task_id") != text(claim, "task_id")
        || text(receipt, "approval_provenance_id") != text(claim, "approval_provenance_id")
        || receipt["binding"] != claim["binding"]
        || text(receipt, "claim_sha256") != claim_sha256(&signed_claim)
    {
        return cap("receipt_claim_binding_invalid");
    }
    if event_name != "workflow_capability.claimed"
        || occurred_at != text(receipt, "claimed_at")
        || event_payload_json != canonical(&claim_event_payload(receipt))
    {
        return cap("receipt_event_binding_invalid");
    }
    Ok(signed_receipt)
}
