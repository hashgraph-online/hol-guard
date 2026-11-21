//! The workflow-capability `claim` operation, ported statement for statement
//! from the original Python store.

use rusqlite::OptionalExtension;
use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_wfcap_authority::{advance_state, load_and_validate};
use crate::guard_store_wfcap_contract::{
    claim_sha256, decode_signed_claim, int, sign_receipt, text, verify_claim, RECEIPT_SCHEMA,
};
use crate::guard_store_wfcap_control::{
    finalize_transition, load_validate_and_observe, prepare_transition,
};
use crate::guard_store_wfcap_ctx::Ctx;
use crate::guard_store_wfcap_error::{cap, WfResult};
use crate::guard_store_wfcap_frame::canonical;
use crate::guard_store_wfcap_ledger::{
    append_transition, build_transition, claim_event_extra, event_payload, insert_event,
    TransitionInput,
};
use crate::guard_store_wfcap_ops::{fetch_claim_row, integrity_as, validate_claim_row};
use crate::guard_store_wfcap_schema::ensure_schema;

pub(crate) fn claim(ctx: &mut Ctx<'_>, args: &Args<'_>) -> WfResult<Value> {
    let capability_id = args.str("capability_id")?;
    let invocation_id = args.str("invocation_id")?;
    let expected_binding =
        args.raw("expected_binding")
            .ok_or(crate::guard_store_db::StoreError::Invalid(
                "native_guard_store_args_invalid",
            ))?;
    ensure_schema(ctx.conn, &ctx.now)?;
    let control = load_validate_and_observe(ctx, false)?;
    let Some(row) = fetch_claim_row(ctx.conn, capability_id)? else {
        return cap("capability_not_found");
    };
    let signed = decode_signed_claim(&row.encoded)?;
    validate_claim_row(&signed, &row, capability_id)?;
    let loaded = load_and_validate(
        ctx,
        &signed,
        row.used_count,
        row.revoked_at.as_deref(),
        row.revocation_code.as_deref(),
    )?;
    let state = loaded.state;
    verify_claim(&signed, &ctx.key, &ctx.key_id, &ctx.now, expected_binding)?;
    let claim = &signed["claim"];
    if text(claim, "subject_id") != args.str("expected_subject_id")?
        || text(claim, "task_id") != args.str("expected_task_id")?
        || text(claim, "issuer_id") != args.str("expected_issuer_id")?
        || text(claim, "approval_provenance_id") != args.str("expected_approval_provenance_id")?
    {
        return cap("capability_claimant_context_mismatch");
    }
    if state.revocation_id.is_some() {
        return cap("capability_revoked");
    }
    if row.used_count >= int(claim, "max_uses") {
        return cap("capability_exhausted");
    }
    let replayed = ctx
        .conn
        .query_row(
            "select 1 from guard_workflow_capability_receipts where invocation_id = ?",
            [invocation_id],
            |_| Ok(()),
        )
        .optional()?;
    if replayed.is_some() {
        return cap("capability_invocation_replayed");
    }
    let use_number = row.used_count + 1;
    let receipt_id = args.str("receipt_id")?;
    let updated = ctx.conn.execute(
        "update guard_workflow_capabilities set used_count = ? \
         where capability_id = ? and used_count = ? and revoked_at is null",
        (use_number, capability_id, row.used_count),
    )?;
    if updated != 1 {
        return cap("capability_claim_conflict");
    }
    let task_id = text(claim, "task_id");
    let provenance = text(claim, "approval_provenance_id");
    let extra = claim_event_extra(provenance, receipt_id, task_id, use_number);
    let payload = event_payload(capability_id, Some(invocation_id), extra.clone());
    let event_id = insert_event(
        ctx.conn,
        "workflow_capability.claimed",
        capability_id,
        Some(invocation_id),
        &ctx.now,
        extra,
    )?;
    let receipt = json!({
        "schema_version": RECEIPT_SCHEMA,
        "receipt_id": receipt_id,
        "capability_id": capability_id,
        "task_id": task_id,
        "invocation_id": invocation_id,
        "approval_provenance_id": provenance,
        "claim_sha256": claim_sha256(&signed),
        "binding": expected_binding,
        "use_number": use_number,
        "event_id": event_id,
        "claimed_at": ctx.now,
    });
    let signed_receipt = sign_receipt(&receipt, &ctx.key, &ctx.key_id)?;
    ctx.conn
        .execute(
            "insert into guard_workflow_capability_receipts (receipt_id, capability_id, task_id, \
             invocation_id, approval_provenance_id, signed_receipt_json, claimed_at, use_number, \
             event_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                receipt_id,
                capability_id,
                task_id,
                invocation_id,
                provenance,
                canonical(&signed_receipt),
                &ctx.now,
                use_number,
                event_id,
            ),
        )
        .map_err(|error| integrity_as(error, "capability_claim_conflict"))?;
    let signed_state = advance_state(ctx, &state, Some(use_number), None, None)?;
    let transition = build_transition(
        ctx,
        TransitionInput {
            signed_claim: &signed,
            signed_state: &signed_state,
            sequence: control.committed_sequence + 1,
            previous: &control.committed_head_sha256,
            kind: "claimed",
            event_id,
            event_name: "workflow_capability.claimed",
            event_payload: &payload,
            occurred_at: &ctx.now.clone(),
            use_number: Some(use_number),
            receipt_id: Some(receipt_id),
            revocation_id: None,
        },
    )?;
    let pending = prepare_transition(ctx, &control, &transition)?;
    append_transition(ctx.conn, &transition)?;
    finalize_transition(ctx, &pending)?;
    Ok(signed_receipt)
}
