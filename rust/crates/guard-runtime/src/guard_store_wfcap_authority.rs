//! Authenticated authority persistence: the signed mutable state, the
//! append-only revocation record, and revalidation of a capability's receipt
//! history against the ledger.

use serde_json::Value;

use crate::guard_store_wfcap_contract::{
    claim_sha256, decode_signed_receipt, int, text, verify_receipt,
};
use crate::guard_store_wfcap_ctx::{int_at, optional_text_at, text_at, Ctx};
use crate::guard_store_wfcap_error::{cap, WfResult};
use crate::guard_store_wfcap_frame::{canonical, parse_ts};
use crate::guard_store_wfcap_ledger::{claim_event_payload, validate_projection};
use crate::guard_store_wfcap_state::{
    decode_revocation, decode_state, encode_revocation, encode_state, sign_revocation, sign_state,
    verify_revocation, verify_state, AuthorityState, Revocation, SignedState,
};

/// `create_authority_state`.
pub(crate) fn create_state(ctx: &Ctx<'_>, signed_claim: &Value) -> WfResult<SignedState> {
    let state = AuthorityState {
        capability_id: text(&signed_claim["claim"], "capability_id").to_owned(),
        claim_sha256: claim_sha256(signed_claim),
        use_high_water: 0,
        observed_at: ctx.now.clone(),
        revision: 0,
        revocation_id: None,
        revoked_at: None,
    };
    let signed = sign_state(&state, &ctx.key, &ctx.key_id)?;
    write_state(ctx, &signed, true)?;
    Ok(signed)
}

pub(crate) struct Loaded {
    pub state: AuthorityState,
}

/// `load_and_validate_authority`.
pub(crate) fn load_and_validate(
    ctx: &Ctx<'_>,
    signed_claim: &Value,
    used_count: i64,
    revoked_at: Option<&str>,
    revocation_code: Option<&str>,
) -> WfResult<Loaded> {
    let capability_id = text(&signed_claim["claim"], "capability_id");
    let row = ctx.conn.query_row(
        "select signed_state_json, key_id, revision, use_high_water, observed_at, revocation_id \
         from guard_workflow_capability_authority_state where capability_id = ?",
        [capability_id],
        |row| {
            Ok((
                text_at(row, 0),
                text_at(row, 1),
                int_at(row, 2),
                int_at(row, 3),
                text_at(row, 4),
                optional_text_at(row, 5),
            ))
        },
    );
    let row = match row {
        Ok(row) => row,
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            return cap("capability_authority_state_missing")
        }
        Err(error) => return Err(error.into()),
    };
    let signed_state = decode_state(&row.0?)?;
    verify_state(&signed_state, &ctx.key, &ctx.key_id)?;
    let state = signed_state.inner.clone();
    let duplicated_matches = state.capability_id == capability_id
        && signed_state.key_id == row.1?
        && state.revision == row.2?
        && state.use_high_water == row.3?
        && state.observed_at == row.4?
        && state.revocation_id == row.5?;
    if !duplicated_matches || state.claim_sha256 != claim_sha256(signed_claim) {
        return cap("capability_authority_state_binding_invalid");
    }
    let receipt_count = validate_receipt_history(ctx, signed_claim)?;
    if state.use_high_water != receipt_count || used_count != receipt_count {
        return cap("capability_use_high_water_invalid");
    }
    let revocation = load_revocation(ctx, signed_claim)?;
    match &revocation {
        None => {
            if state.revocation_id.is_some() || revoked_at.is_some() || revocation_code.is_some() {
                return cap("capability_revocation_state_invalid");
            }
        }
        Some(revocation) => {
            if state.revocation_id.as_deref() != Some(revocation.revocation_id.as_str())
                || state.revoked_at.as_deref() != Some(revocation.revoked_at.as_str())
                || revoked_at != Some(revocation.revoked_at.as_str())
                || revocation_code != Some(revocation.reason_code.as_str())
            {
                return cap("capability_revocation_state_invalid");
            }
        }
    }
    validate_projection(
        ctx,
        signed_claim,
        &signed_state,
        receipt_count,
        revocation.as_ref().map(|r| r.revocation_id.as_str()),
    )?;
    Ok(Loaded { state })
}

/// `advance_authority_state`.
pub(crate) fn advance_state(
    ctx: &Ctx<'_>,
    state: &AuthorityState,
    use_high_water: Option<i64>,
    revocation_id: Option<&str>,
    revoked_at: Option<&str>,
) -> WfResult<SignedState> {
    if parse_ts(&ctx.now)? < parse_ts(&state.observed_at)? {
        return cap("capability_clock_rollback");
    }
    let mut updated = state.clone();
    updated.observed_at = ctx.now.clone();
    updated.revision = state.revision + 1;
    if let Some(value) = use_high_water {
        updated.use_high_water = value;
    }
    if let Some(value) = revocation_id {
        updated.revocation_id = Some(value.to_owned());
    }
    if let Some(value) = revoked_at {
        updated.revoked_at = Some(value.to_owned());
    }
    let updated = AuthorityState::from_value(&updated.to_value())?;
    let signed = sign_state(&updated, &ctx.key, &ctx.key_id)?;
    write_state(ctx, &signed, false)?;
    Ok(signed)
}

/// `append_revocation`.
pub(crate) fn append_revocation(
    ctx: &Ctx<'_>,
    signed_claim: &Value,
    reason_code: &str,
    revoked_at: &str,
    revocation_id: &str,
) -> WfResult<()> {
    let revocation = Revocation {
        revocation_id: revocation_id.to_owned(),
        capability_id: text(&signed_claim["claim"], "capability_id").to_owned(),
        claim_sha256: claim_sha256(signed_claim),
        reason_code: reason_code.to_owned(),
        revoked_at: revoked_at.to_owned(),
    };
    let revocation = Revocation::from_value(&revocation.to_value())?;
    let signed = sign_revocation(&revocation, &ctx.key, &ctx.key_id)?;
    ctx.conn.execute(
        "insert into guard_workflow_capability_revocations \
         (revocation_id, capability_id, signed_revocation_json, key_id, revoked_at) \
         values (?, ?, ?, ?, ?)",
        (
            revocation_id,
            &revocation.capability_id,
            encode_revocation(&signed),
            &ctx.key_id,
            revoked_at,
        ),
    )?;
    Ok(())
}

fn write_state(ctx: &Ctx<'_>, signed: &SignedState, insert: bool) -> WfResult<()> {
    let state = &signed.inner;
    let encoded = encode_state(signed);
    if insert {
        ctx.conn.execute(
            "insert into guard_workflow_capability_authority_state \
             (signed_state_json, key_id, revision, use_high_water, observed_at, revocation_id, \
              capability_id) values (?, ?, ?, ?, ?, ?, ?)",
            (
                encoded,
                &signed.key_id,
                state.revision,
                state.use_high_water,
                &state.observed_at,
                &state.revocation_id,
                &state.capability_id,
            ),
        )?;
        return Ok(());
    }
    let changed = ctx.conn.execute(
        "update guard_workflow_capability_authority_state \
         set signed_state_json = ?, key_id = ?, revision = ?, use_high_water = ?, \
             observed_at = ?, revocation_id = ? where capability_id = ?",
        (
            encoded,
            &signed.key_id,
            state.revision,
            state.use_high_water,
            &state.observed_at,
            &state.revocation_id,
            &state.capability_id,
        ),
    )?;
    if changed != 1 {
        return cap("capability_authority_state_update_failed");
    }
    Ok(())
}

fn load_revocation(ctx: &Ctx<'_>, signed_claim: &Value) -> WfResult<Option<Revocation>> {
    let capability_id = text(&signed_claim["claim"], "capability_id");
    let mut statement = ctx.conn.prepare(
        "select revocation_id, signed_revocation_json, key_id, revoked_at \
         from guard_workflow_capability_revocations where capability_id = ?",
    )?;
    let mut rows = statement.query([capability_id])?;
    let mut found = Vec::new();
    while let Some(row) = rows.next()? {
        found.push((
            text_at(row, 0)?,
            text_at(row, 1)?,
            text_at(row, 2)?,
            text_at(row, 3)?,
        ));
    }
    if found.is_empty() {
        return Ok(None);
    }
    if found.len() != 1 {
        return cap("capability_revocation_history_invalid");
    }
    let (revocation_id, encoded, key_id, revoked_at) = &found[0];
    let signed = decode_revocation(encoded)?;
    verify_revocation(&signed, &ctx.key, &ctx.key_id)?;
    let revocation = signed.inner.clone();
    if *revocation_id != revocation.revocation_id
        || *key_id != signed.key_id
        || *revoked_at != revocation.revoked_at
        || revocation.capability_id != capability_id
        || revocation.claim_sha256 != claim_sha256(signed_claim)
    {
        return cap("capability_revocation_binding_invalid");
    }
    Ok(Some(revocation))
}

fn validate_receipt_history(ctx: &Ctx<'_>, signed_claim: &Value) -> WfResult<i64> {
    let claim = &signed_claim["claim"];
    let capability_id = text(claim, "capability_id");
    let digest = claim_sha256(signed_claim);
    let mut statement = ctx.conn.prepare(
        "select r.receipt_id, r.task_id, r.invocation_id, r.approval_provenance_id, \
                r.signed_receipt_json, r.claimed_at, r.use_number, r.event_id, \
                e.event_name, e.payload_json, e.occurred_at \
         from guard_workflow_capability_receipts r \
         left join guard_events e on e.event_id = r.event_id \
         where r.capability_id = ? order by r.use_number",
    )?;
    let mut rows = statement.query([capability_id])?;
    let mut expected_use = 0_i64;
    while let Some(row) = rows.next()? {
        expected_use += 1;
        let signed = decode_signed_receipt(&text_at(row, 4)?)?;
        verify_receipt(&signed, &ctx.key, &ctx.key_id)?;
        let receipt = &signed["receipt"];
        let matches = int(receipt, "use_number") == expected_use
            && int_at(row, 6)? == expected_use
            && text(receipt, "receipt_id") == text_at(row, 0)?
            && text(receipt, "task_id") == text_at(row, 1)?
            && text(receipt, "invocation_id") == text_at(row, 2)?
            && text(receipt, "approval_provenance_id") == text_at(row, 3)?
            && text(receipt, "claimed_at") == text_at(row, 5)?
            && int(receipt, "event_id") == int_at(row, 7)?
            && text(receipt, "capability_id") == capability_id
            && text(receipt, "claim_sha256") == digest
            && receipt["binding"] == claim["binding"];
        if !matches {
            return cap("capability_receipt_history_invalid");
        }
        let event_valid = text_at(row, 8)? == "workflow_capability.claimed"
            && text_at(row, 10)? == text(receipt, "claimed_at")
            && text_at(row, 9)? == canonical(&claim_event_payload(receipt));
        if !event_valid {
            return cap("capability_receipt_event_history_invalid");
        }
    }
    Ok(expected_use)
}
