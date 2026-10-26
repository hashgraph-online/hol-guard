//! External monotonic control for the workflow-capability authority ledger:
//! the committed/pending head the credential store remembers, so a restored
//! database or a rolled-back clock is detected.

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_wfcap_ctx::Ctx;
use crate::guard_store_wfcap_error::{cap, WfResult};
use crate::guard_store_wfcap_frame::{canonical, digest, is_digest, parse_ts};
use crate::guard_store_wfcap_ledger::validate_global_ledger;
use crate::guard_store_wfcap_state::{transition_sha256, SignedTransition, ZERO_SHA256};

const CONTROL_VERSION: i64 = 1;
const FIELDS: [&str; 6] = [
    "version",
    "committed_sequence",
    "committed_head_sha256",
    "pending_sequence",
    "pending_head_sha256",
    "observed_at",
];

#[derive(Clone, Debug)]
pub(crate) struct Control {
    pub committed_sequence: i64,
    pub committed_head_sha256: String,
    pub pending_sequence: Option<i64>,
    pub pending_head_sha256: Option<String>,
    pub observed_at: String,
}

impl Control {
    fn to_value(&self) -> Value {
        json!({
            "version": CONTROL_VERSION,
            "committed_sequence": self.committed_sequence,
            "committed_head_sha256": self.committed_head_sha256,
            "pending_sequence": self.pending_sequence,
            "pending_head_sha256": self.pending_head_sha256,
            "observed_at": self.observed_at,
        })
    }

    fn encode(&self) -> String {
        canonical(&self.to_value())
    }
}

/// `load_validate_and_observe_control`.
pub(crate) fn load_validate_and_observe(ctx: &mut Ctx<'_>, create: bool) -> WfResult<Control> {
    let (sequence, head) = validate_global_ledger(ctx)?;
    let mut control = match ctx.load_control().map(str::to_owned) {
        None => {
            if has_authority_data(ctx.conn)? {
                return cap("capability_control_bootstrap_refused");
            }
            if !create {
                return cap("capability_control_unavailable");
            }
            let fresh = Control {
                committed_sequence: 0,
                committed_head_sha256: ZERO_SHA256.to_owned(),
                pending_sequence: None,
                pending_head_sha256: None,
                observed_at: ctx.now.clone(),
            };
            ctx.store_control(fresh.encode());
            fresh
        }
        Some(encoded) => decode(&encoded)?,
    };
    if let Some(pending) = control.pending_sequence {
        if sequence != pending || Some(&head) != control.pending_head_sha256.as_ref() {
            return cap("capability_control_pending_unresolved");
        }
        control = Control {
            committed_sequence: sequence,
            committed_head_sha256: head.clone(),
            pending_sequence: None,
            pending_head_sha256: None,
            observed_at: control.observed_at,
        };
        ctx.store_control(control.encode());
    }
    if sequence != control.committed_sequence || head != control.committed_head_sha256 {
        return cap("capability_control_rollback_detected");
    }
    let current = parse_ts(&ctx.now)?;
    let observed = parse_ts(&control.observed_at)?;
    if current < observed {
        return cap("capability_clock_rollback");
    }
    if current > observed {
        control.observed_at = ctx.now.clone();
        ctx.store_control(control.encode());
    }
    Ok(control)
}

/// `prepare_control_transition`.
pub(crate) fn prepare_transition(
    ctx: &mut Ctx<'_>,
    control: &Control,
    signed: &SignedTransition,
) -> WfResult<Control> {
    let transition = &signed.inner;
    let head = transition_sha256(signed);
    if control.pending_sequence.is_some()
        || transition.sequence != control.committed_sequence + 1
        || transition.previous_sha256 != control.committed_head_sha256
    {
        return cap("capability_control_transition_invalid");
    }
    let pending = Control {
        pending_sequence: Some(transition.sequence),
        pending_head_sha256: Some(head),
        observed_at: transition.occurred_at.clone(),
        ..control.clone()
    };
    ctx.store_control(pending.encode());
    Ok(pending)
}

/// `finalize_control_transition`, performed after the database commit.
pub(crate) fn finalize_transition(ctx: &mut Ctx<'_>, pending: &Control) -> WfResult<()> {
    let (Some(sequence), Some(head)) = (
        pending.pending_sequence,
        pending.pending_head_sha256.clone(),
    ) else {
        return cap("capability_control_pending_missing");
    };
    let finalized = Control {
        committed_sequence: sequence,
        committed_head_sha256: head,
        pending_sequence: None,
        pending_head_sha256: None,
        observed_at: pending.observed_at.clone(),
    };
    ctx.store_control_post_commit(finalized.encode());
    Ok(())
}

fn has_authority_data(conn: &Connection) -> WfResult<bool> {
    let total: i64 = conn.query_row(
        "select (select count(*) from guard_workflow_capabilities) + \
         (select count(*) from guard_workflow_capability_authority_transitions) + \
         (select count(*) from guard_events where event_name in ( \
         'workflow_capability.issued', 'workflow_capability.claimed', 'workflow_capability.revoked'))",
        [],
        |row| row.get(0),
    )?;
    Ok(total != 0)
}

fn decode(encoded: &str) -> WfResult<Control> {
    let invalid = || cap("capability_control_invalid");
    let Ok(payload) = serde_json::from_str::<Value>(encoded) else {
        return invalid();
    };
    let Some(map) = payload.as_object() else {
        return invalid();
    };
    if map.len() != FIELDS.len() || !FIELDS.iter().all(|field| map.contains_key(*field)) {
        return invalid();
    }
    let integer = |name: &str, nullable: bool| -> WfResult<Option<i64>> {
        match map.get(name) {
            Some(Value::Null) if nullable => Ok(None),
            Some(Value::Number(number)) if number.as_i64().is_some() => Ok(number.as_i64()),
            _ => cap("capability_control_invalid"),
        }
    };
    let string = |name: &str, nullable: bool| -> WfResult<Option<String>> {
        match map.get(name) {
            Some(Value::Null) if nullable => Ok(None),
            Some(Value::String(text)) => Ok(Some(text.clone())),
            _ => cap("capability_control_invalid"),
        }
    };
    let version = integer("version", false)?.unwrap_or_default();
    let committed_sequence = integer("committed_sequence", false)?.unwrap_or_default();
    let committed_head = string("committed_head_sha256", false)?.unwrap_or_default();
    let pending_sequence = integer("pending_sequence", true)?;
    let pending_head = string("pending_head_sha256", true)?;
    let observed_at = string("observed_at", false)?.unwrap_or_default();
    if version != CONTROL_VERSION {
        return cap("unsupported_capability_control_version");
    }
    if committed_sequence < 0 {
        return cap("invalid_capability_control_sequence");
    }
    digest("committed_head_sha256", &committed_head)?;
    if pending_sequence.is_some() != pending_head.is_some() {
        return cap("invalid_capability_control_pending");
    }
    if let (Some(sequence), Some(head)) = (pending_sequence, pending_head.as_deref()) {
        if sequence != committed_sequence + 1 {
            return cap("invalid_capability_control_pending");
        }
        if !is_digest(head) {
            return cap("invalid_pending_head_sha256");
        }
    }
    parse_ts(&observed_at)?;
    let control = Control {
        committed_sequence,
        committed_head_sha256: committed_head,
        pending_sequence,
        pending_head_sha256: pending_head,
        observed_at,
    };
    if control.encode() != encoded {
        return invalid();
    }
    Ok(control)
}
