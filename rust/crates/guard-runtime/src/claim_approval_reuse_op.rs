//! `ClaimApprovalReuseDecisions` — resident op that claims a batch of
//! prevalidated policy/local-once reuse decisions under one SQLite
//! `BEGIN IMMEDIATE` transaction.
//!
//! IO op (unlike `ApprovalReuseDecide`): opens `store_path` and calls
//! `claim_reuse::claim_approval_reuse_decisions`. The integrity evidence
//! (refreshed state, key material) is shipped by the caller before the write
//! lock is taken, so the op re-verifies its binding to the store under that
//! lock (`claim_reuse_binding`) and refuses on any change. The op derives the
//! policy-bundle identities itself when the caller sends none.

use guard_contracts::{
    ClaimApprovalReuseDecisionsRequestV1, ClaimApprovalReuseDecisionsResultV1,
    CLAIM_APPROVAL_REUSE_REQUEST_SCHEMA, CLAIM_APPROVAL_REUSE_RESULT_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;
use serde_json::Value;
use std::borrow::Cow;

use crate::policy_bundle_store_identities::{lookup_bundle_authority, Identity};

use super::context_digest_json::write_canonical_json_with_limit;

fn request_digest(request: &ClaimApprovalReuseDecisionsRequestV1) -> Result<String, &'static str> {
    let material =
        serde_json::to_value(request).map_err(|_| "native_claim_approval_reuse_invalid")?;
    let mut bytes = Vec::new();
    write_canonical_json_with_limit(&material, &mut bytes, usize::MAX)
        .map_err(|_| "native_claim_approval_reuse_invalid")?;
    Ok(format!("sha256:{}", digest_bytes(&bytes)))
}

pub(crate) fn evaluate_claim_approval_reuse_request(
    request: &ClaimApprovalReuseDecisionsRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request).map_err(str::to_owned)?;
    let result = evaluate(request);
    let (status, code, payload) = match result {
        Ok(payload) => ("ok".to_owned(), "ok".to_owned(), Some(payload)),
        Err(code) => ("error".to_owned(), code, None),
    };
    let result = ClaimApprovalReuseDecisionsResultV1 {
        schema: CLAIM_APPROVAL_REUSE_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        payload,
    };
    crate::encode_response(&result)
}

fn decode_key(encoded: Option<&str>) -> Option<Vec<u8>> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::decode_vec(encoded?).ok()
}

/// The identities the claim checks `policy-bundle` decisions against: those
/// the request carries, or else those the resident derives from the store at
/// the request's time. The caller reads the evidence binding first, so a
/// bundle source that moves afterwards still makes the claim refuse under the
/// write lock. `None` leaves every bundle decision unclaimable, as it was when
/// the caller could not derive them.
fn bundle_identities<'a>(
    request: &'a ClaimApprovalReuseDecisionsRequestV1,
    connection: &rusqlite::Connection,
) -> Option<Cow<'a, [Identity]>> {
    if let Some(identities) = request.policy_bundle_decision_identities.as_deref() {
        return Some(Cow::Borrowed(identities));
    }
    let bundle_decision = request
        .decisions
        .iter()
        .any(|decision| decision.get("source").and_then(Value::as_str) == Some("policy-bundle"));
    if !bundle_decision {
        return None;
    }
    let now = guard_contracts::canonical_utc_timestamp(&request.now)?;
    let (identities, _bundle) = lookup_bundle_authority(connection, &now).ok().flatten()?;
    (!identities.is_empty()).then_some(Cow::Owned(identities))
}

fn evaluate(request: &ClaimApprovalReuseDecisionsRequestV1) -> Result<Value, String> {
    evaluate_with_clock(request, false)
}

/// A launch owner must use the store's current clock, never the earlier
/// preview timestamp carried by the transport. This still uses the same
/// authenticated rows and atomic claim transaction.
#[cfg(target_os = "macos")]
pub(crate) fn claim_now_then<T>(
    request: &ClaimApprovalReuseDecisionsRequestV1,
    connection: &rusqlite::Connection,
    after: &mut dyn FnMut(&rusqlite::Connection) -> rusqlite::Result<Option<T>>,
) -> Result<Option<T>, String> {
    if request.schema != CLAIM_APPROVAL_REUSE_REQUEST_SCHEMA || request.decisions.is_empty() {
        return Err("native_claim_approval_reuse_schema_mismatch".to_owned());
    }
    let integrity_key = decode_key(request.integrity_key_b64.as_deref());
    let local_once_key = decode_key(request.local_once_integrity_key_b64.as_deref());
    let bundle_identities = bundle_identities(request, connection);
    let evidence = crate::claim_reuse::ClaimEvidence {
        integrity_state: request.integrity_state.as_ref(),
        integrity_key: integrity_key.as_deref(),
        integrity_key_id: request.integrity_key_id.as_deref(),
        local_once_key: local_once_key.as_deref(),
        local_once_key_id: request.local_once_integrity_key_id.as_deref(),
        policy_bundle_identities: bundle_identities.as_deref(),
    };
    crate::claim_reuse::claim_approval_reuse_decisions_now_then(
        connection,
        &request.decisions,
        &evidence,
        &|connection, members| {
            crate::claim_reuse_binding::evidence_is_bound(
                connection,
                members,
                &evidence,
                request.evidence_binding.as_ref(),
            )
        },
        true,
        after,
    )
    .map_err(|_| "native_claim_approval_reuse_store_error".to_owned())
}

fn evaluate_with_clock(
    request: &ClaimApprovalReuseDecisionsRequestV1,
    native_clock: bool,
) -> Result<Value, String> {
    if request.schema != CLAIM_APPROVAL_REUSE_REQUEST_SCHEMA {
        return Err("native_claim_approval_reuse_schema_mismatch".to_owned());
    }
    let supplied_now = if native_clock {
        None
    } else {
        Some(
            guard_contracts::canonical_utc_timestamp(&request.now)
                .ok_or_else(|| "native_claim_approval_reuse_invalid".to_owned())?,
        )
    };
    let connection = rusqlite::Connection::open_with_flags(
        &request.store_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
    )
    .map_err(|_| "native_claim_approval_reuse_store_unavailable".to_owned())?;
    connection
        .busy_timeout(std::time::Duration::from_millis(5000))
        .map_err(|_| "native_claim_approval_reuse_store_unavailable".to_owned())?;
    let integrity_key = decode_key(request.integrity_key_b64.as_deref());
    let local_once_key = decode_key(request.local_once_integrity_key_b64.as_deref());
    let bundle_identities = bundle_identities(request, &connection);
    let evidence = crate::claim_reuse::ClaimEvidence {
        integrity_state: request.integrity_state.as_ref(),
        integrity_key: integrity_key.as_deref(),
        integrity_key_id: request.integrity_key_id.as_deref(),
        local_once_key: local_once_key.as_deref(),
        local_once_key_id: request.local_once_integrity_key_id.as_deref(),
        policy_bundle_identities: bundle_identities.as_deref(),
    };
    let bound = |connection: &rusqlite::Connection, members: &[crate::claim_reuse::Member<'_>]| {
        crate::claim_reuse_binding::evidence_is_bound(
            connection,
            members,
            &evidence,
            request.evidence_binding.as_ref(),
        )
    };
    let claimed = if let Some(now) = supplied_now {
        crate::claim_reuse::claim_approval_reuse_decisions_with(
            &connection,
            &request.decisions,
            &now,
            &evidence,
            &bound,
            request.consume_local_once,
        )
    } else {
        crate::claim_reuse::claim_approval_reuse_decisions_now(
            &connection,
            &request.decisions,
            &evidence,
            &bound,
            request.consume_local_once,
        )
    }
    .map_err(|_| "native_claim_approval_reuse_store_error".to_owned())?;
    Ok(serde_json::json!({ "claimed": claimed }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request(
        source: &str,
        identities: Option<Vec<Identity>>,
    ) -> ClaimApprovalReuseDecisionsRequestV1 {
        let mut request: ClaimApprovalReuseDecisionsRequestV1 = serde_json::from_value(json!({
            "schema": CLAIM_APPROVAL_REUSE_REQUEST_SCHEMA,
            "store_path": "/unused/guard.db",
            "guard_home": "/unused",
            "decisions": [{"decision_id": 1, "source": source}],
            "now": "2030-01-01T00:00:00+00:00",
        }))
        .unwrap();
        request.policy_bundle_decision_identities = identities;
        request
    }

    /// A store whose `policy-bundle` row the resident cannot authorize.
    fn unreadable_bundle_store() -> rusqlite::Connection {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "create table policy_decisions (source text not null);
                 insert into policy_decisions values ('policy-bundle');
                 create table sync_state (state_key text primary key, payload_json text not null,
                   updated_at text not null);
                 insert into sync_state values ('policy_bundle', 'not json', '2030-01-01T00:00:00+00:00');",
            )
            .unwrap();
        connection
    }

    /// Identities the caller ships are used as sent; without them only a
    /// bundle decision asks the store, and a bundle the resident cannot
    /// authorize leaves the decision unclaimable rather than failing the op.
    #[test]
    fn a_claim_derives_bundle_identities_only_when_none_were_shipped() {
        let connection = unreadable_bundle_store();
        let shipped = vec![vec![json!("codex")]];

        let carried = request("policy-bundle", Some(shipped.clone()));
        assert_eq!(
            bundle_identities(&carried, &connection).as_deref(),
            Some(&shipped[..])
        );
        assert!(bundle_identities(&request("approval-gate", None), &connection).is_none());
        assert!(bundle_identities(&request("policy-bundle", None), &connection).is_none());
    }
}
