//! Signed append-only authority-transition ledger: building and appending
//! entries, global chain validation, per-capability projection validation,
//! and the `guard_events` rows the ledger authenticates.

use std::collections::BTreeSet;

use rusqlite::{Connection, OptionalExtension};
use serde_json::{Map, Value};

use crate::guard_store_wfcap_contract::{claim_sha256, text};
use crate::guard_store_wfcap_ctx::{int_at, text_at, Ctx};
use crate::guard_store_wfcap_error::{cap, WfResult};
use crate::guard_store_wfcap_frame::{canonical, framed_text_digest, private_reference};
use crate::guard_store_wfcap_state::{
    decode_transition, encode_transition, sign_transition, state_sha256, transition_sha256,
    verify_transition, SignedState, SignedTransition, Transition, ZERO_SHA256,
};

pub(crate) fn event_payload_sha256(payload: &Value) -> String {
    framed_text_digest("authority-event", &canonical(payload))
}

/// `_workflow_capability_event_payload`.
pub(crate) fn event_payload(
    capability_id: &str,
    invocation_id: Option<&str>,
    extra: Map<String, Value>,
) -> Value {
    let mut payload = extra;
    payload.insert(
        "capability_ref".to_owned(),
        Value::from(private_reference("capability", capability_id)),
    );
    if let Some(invocation_id) = invocation_id {
        payload.insert(
            "invocation_ref".to_owned(),
            Value::from(private_reference("invocation", invocation_id)),
        );
    }
    Value::Object(payload)
}

/// `_claim_event_extra`.
pub(crate) fn claim_event_extra(
    approval_provenance_id: &str,
    receipt_id: &str,
    task_id: &str,
    use_number: i64,
) -> Map<String, Value> {
    let mut extra = Map::new();
    extra.insert(
        "approval_provenance_ref".to_owned(),
        Value::from(private_reference(
            "approval-provenance",
            approval_provenance_id,
        )),
    );
    extra.insert(
        "receipt_ref".to_owned(),
        Value::from(private_reference("receipt", receipt_id)),
    );
    extra.insert(
        "task_ref".to_owned(),
        Value::from(private_reference("task", task_id)),
    );
    extra.insert("use_number".to_owned(), Value::from(use_number));
    extra
}

/// `_claim_event_payload` for a decoded receipt.
pub(crate) fn claim_event_payload(receipt: &Value) -> Value {
    event_payload(
        text(receipt, "capability_id"),
        Some(text(receipt, "invocation_id")),
        claim_event_extra(
            text(receipt, "approval_provenance_id"),
            text(receipt, "receipt_id"),
            text(receipt, "task_id"),
            crate::guard_store_wfcap_contract::int(receipt, "use_number"),
        ),
    )
}

/// `_insert_workflow_capability_event`.
pub(crate) fn insert_event(
    conn: &Connection,
    event_name: &str,
    capability_id: &str,
    invocation_id: Option<&str>,
    occurred_at: &str,
    extra: Map<String, Value>,
) -> WfResult<i64> {
    let payload = event_payload(capability_id, invocation_id, extra);
    conn.execute(
        "insert into guard_events (event_name, payload_json, occurred_at) values (?, ?, ?)",
        (event_name, canonical(&payload), occurred_at),
    )?;
    Ok(conn.last_insert_rowid())
}

pub(crate) struct TransitionInput<'a> {
    pub signed_claim: &'a Value,
    pub signed_state: &'a SignedState,
    pub sequence: i64,
    pub previous: &'a str,
    pub kind: &'a str,
    pub event_id: i64,
    pub event_name: &'a str,
    pub event_payload: &'a Value,
    pub occurred_at: &'a str,
    pub use_number: Option<i64>,
    pub receipt_id: Option<&'a str>,
    pub revocation_id: Option<&'a str>,
}

/// `build_authority_transition`.
pub(crate) fn build_transition(
    ctx: &Ctx<'_>,
    input: TransitionInput<'_>,
) -> WfResult<SignedTransition> {
    let transition = Transition {
        sequence: input.sequence,
        capability_id: text(&input.signed_claim["claim"], "capability_id").to_owned(),
        claim_sha256: claim_sha256(input.signed_claim),
        revision: input.signed_state.inner.revision,
        kind: input.kind.to_owned(),
        previous_sha256: input.previous.to_owned(),
        signed_state_sha256: state_sha256(input.signed_state),
        event_id: input.event_id,
        event_name: input.event_name.to_owned(),
        event_payload_sha256: event_payload_sha256(input.event_payload),
        occurred_at: input.occurred_at.to_owned(),
        use_number: input.use_number,
        receipt_id: input.receipt_id.map(str::to_owned),
        revocation_id: input.revocation_id.map(str::to_owned),
    };
    revalidate(&transition)?;
    sign_transition(&transition, &ctx.key, &ctx.key_id)
}

/// The dataclass `__post_init__` the Python build runs on a fresh transition.
fn revalidate(transition: &Transition) -> WfResult<()> {
    Transition::from_value(&transition.to_value()).map(|_| ())
}

/// `append_authority_transition`.
pub(crate) fn append_transition(conn: &Connection, signed: &SignedTransition) -> WfResult<()> {
    let transition = &signed.inner;
    conn.execute(
        "insert into guard_workflow_capability_authority_transitions \
         (sequence, capability_id, revision, transition_kind, previous_transition_sha256, \
          signed_transition_json, key_id, event_id) values (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            transition.sequence,
            &transition.capability_id,
            transition.revision,
            &transition.kind,
            &transition.previous_sha256,
            encode_transition(signed),
            &signed.key_id,
            transition.event_id,
        ),
    )?;
    Ok(())
}

fn transition_event_matches(conn: &Connection, transition: &Transition) -> WfResult<bool> {
    let row = conn
        .query_row(
            "select event_name, payload_json, occurred_at from guard_events where event_id = ?",
            [transition.event_id],
            |row| Ok((text_at(row, 0), text_at(row, 1), text_at(row, 2))),
        )
        .optional()?;
    let Some((name, payload, occurred)) = row else {
        return Ok(false);
    };
    let (name, payload, occurred) = (name?, payload?, occurred?);
    if name != transition.event_name || occurred != transition.occurred_at {
        return Ok(false);
    }
    let decoded = decode_event_payload(&payload)?;
    Ok(event_payload_sha256(&decoded) == transition.event_payload_sha256)
}

fn decode_event_payload(encoded: &str) -> WfResult<Value> {
    let invalid = || cap::<Value>("capability_authority_transition_event_invalid");
    let Ok(payload) = serde_json::from_str::<Value>(encoded) else {
        return invalid();
    };
    if !payload.is_object() || canonical(&payload) != encoded {
        return invalid();
    }
    Ok(payload)
}

/// `validate_global_authority_ledger`: the head `(sequence, sha256)`.
pub(crate) fn validate_global_ledger(ctx: &Ctx<'_>) -> WfResult<(i64, String)> {
    let mut statement = ctx.conn.prepare(
        "select sequence, capability_id, revision, transition_kind, previous_transition_sha256, \
         signed_transition_json, key_id, event_id \
         from guard_workflow_capability_authority_transitions order by sequence",
    )?;
    let mut rows = statement.query([])?;
    let mut previous = ZERO_SHA256.to_owned();
    let mut event_ids = BTreeSet::new();
    let mut count = 0_i64;
    while let Some(row) = rows.next()? {
        count += 1;
        let signed = decode_transition(&text_at(row, 5)?)?;
        verify_transition(&signed, &ctx.key, &ctx.key_id)?;
        let transition = &signed.inner;
        let matches = int_at(row, 0)? == transition.sequence
            && text_at(row, 1)? == transition.capability_id
            && int_at(row, 2)? == transition.revision
            && text_at(row, 3)? == transition.kind
            && text_at(row, 4)? == transition.previous_sha256
            && text_at(row, 6)? == signed.key_id
            && int_at(row, 7)? == transition.event_id;
        if !matches || transition.sequence != count || transition.previous_sha256 != previous {
            return cap("capability_authority_transition_chain_invalid");
        }
        if !transition_event_matches(ctx.conn, transition)? {
            return cap("capability_authority_transition_event_invalid");
        }
        event_ids.insert(transition.event_id);
        previous = transition_sha256(&signed);
    }
    let mut events = ctx.conn.prepare(
        "select event_id from guard_events where event_name in \
         ('workflow_capability.issued', 'workflow_capability.claimed', 'workflow_capability.revoked')",
    )?;
    let mut event_rows = events.query([])?;
    let mut seen = BTreeSet::new();
    let mut total = 0_i64;
    while let Some(row) = event_rows.next()? {
        total += 1;
        seen.insert(int_at(row, 0)?);
    }
    if seen != event_ids || total != count {
        return cap("capability_authority_event_cardinality_invalid");
    }
    Ok((count, previous))
}

/// `validate_capability_transition_projection`.
pub(crate) fn validate_projection(
    ctx: &Ctx<'_>,
    signed_claim: &Value,
    signed_state: &SignedState,
    receipt_count: i64,
    revocation_id: Option<&str>,
) -> WfResult<()> {
    let invalid = || cap::<()>("capability_authority_transition_projection_invalid");
    let capability_id = text(&signed_claim["claim"], "capability_id");
    let claim_digest = claim_sha256(signed_claim);
    let mut statement = ctx.conn.prepare(
        "select signed_transition_json from guard_workflow_capability_authority_transitions \
         where capability_id = ? order by revision",
    )?;
    let mut rows = statement.query([capability_id])?;
    let mut transitions = Vec::new();
    while let Some(row) = rows.next()? {
        let signed = decode_transition(&text_at(row, 0)?)?;
        verify_transition(&signed, &ctx.key, &ctx.key_id)?;
        let transition = signed.inner;
        let expected_revision = i64::try_from(transitions.len()).unwrap_or(i64::MAX);
        if transition.revision != expected_revision
            || transition.capability_id != capability_id
            || transition.claim_sha256 != claim_digest
        {
            return invalid();
        }
        transitions.push(transition);
    }
    if transitions.is_empty() {
        return cap("capability_authority_transition_missing");
    }
    if transitions[0].kind != "issued" || transitions[1..].iter().any(|t| t.kind == "issued") {
        return invalid();
    }
    let claims: Vec<&Transition> = transitions.iter().filter(|t| t.kind == "claimed").collect();
    let uses: Vec<Option<i64>> = claims.iter().map(|t| t.use_number).collect();
    let expected_uses: Vec<Option<i64>> = (1..=receipt_count).map(Some).collect();
    if uses != expected_uses {
        return invalid();
    }
    let mut receipts = ctx.conn.prepare(
        "select receipt_id, use_number, event_id from guard_workflow_capability_receipts \
         where capability_id = ? order by use_number",
    )?;
    let mut receipt_rows = receipts.query([capability_id])?;
    let mut persisted = Vec::new();
    while let Some(row) = receipt_rows.next()? {
        persisted.push((text_at(row, 0)?, int_at(row, 1)?, int_at(row, 2)?));
    }
    let projected: Vec<(String, i64, i64)> = claims
        .iter()
        .map(|t| {
            (
                t.receipt_id.clone().unwrap_or_default(),
                t.use_number.unwrap_or_default(),
                t.event_id,
            )
        })
        .collect();
    if projected != persisted {
        return invalid();
    }
    let revokes: Vec<&Transition> = transitions.iter().filter(|t| t.kind == "revoked").collect();
    if revokes.len() != usize::from(revocation_id.is_some()) {
        return invalid();
    }
    if let Some(revoke) = revokes.first() {
        let last = transitions.last().map(|t| t.sequence);
        if revoke.revocation_id.as_deref() != revocation_id || Some(revoke.sequence) != last {
            return invalid();
        }
    }
    let last = &transitions[transitions.len() - 1];
    if last.revision != signed_state.inner.revision
        || last.signed_state_sha256 != state_sha256(signed_state)
    {
        return invalid();
    }
    Ok(())
}
