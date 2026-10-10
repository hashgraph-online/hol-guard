//! `DaemonHandler` — resident op for the daemon handlers' request validation.
//!
//! Pure: every query is answered from the request alone. A rejected query is a
//! bound `error` reply carrying its specific code, never a default verdict. A
//! handler answers either `reject` (the status and body to send) or `proceed`
//! (the normalized values the caller may act on).

use crate::daemon_handler_policy::{
    policy_clear, policy_upsert, PolicyClearInput, PolicyUpsertInput,
};
use crate::daemon_handler_requests::{
    bulk_allow, events_cursor, harness_action, requests_clear, requests_list,
};
use crate::package_authority_op::request_digest_with_limit;
use guard_contracts::{
    DaemonHandlerPayloadV1, DaemonHandlerQueryV1, DaemonHandlerRequestV1, DaemonHandlerResultV1,
    DAEMON_HANDLER_MAX_BYTES, DAEMON_HANDLER_REQUEST_SCHEMA, DAEMON_HANDLER_RESULT_SCHEMA,
};
use serde_json::Value;

/// One handler's answer before it is bound to a request.
pub(crate) struct Reply {
    outcome: &'static str,
    status: u16,
    body: Value,
    fields: Value,
}

impl Reply {
    pub(crate) fn reject(status: u16, body: Value) -> Self {
        Self {
            outcome: "reject",
            status,
            body,
            fields: Value::Object(Default::default()),
        }
    }

    /// `body` is the success body the caller may complete with store facts.
    pub(crate) fn proceed(body: Value, fields: Value) -> Self {
        Self {
            outcome: "proceed",
            status: 200,
            body,
            fields,
        }
    }
}

pub(crate) fn evaluate_daemon_handler_request(
    request: &DaemonHandlerRequestV1,
) -> Result<Vec<u8>, String> {
    // Bound the complete canonical request before any decision work.
    let request_sha256 = request_digest_with_limit(request, DAEMON_HANDLER_MAX_BYTES)
        .map_err(|_| "native_daemon_handler_too_large".to_owned())?;
    let (status, code, payload) = match decide(request) {
        Ok(payload) => ("ok", "ok".to_owned(), Some(payload)),
        Err(code) => ("error", code, None),
    };
    crate::encode_response(&DaemonHandlerResultV1 {
        schema: DAEMON_HANDLER_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code,
        payload,
    })
}

pub(crate) fn decide(request: &DaemonHandlerRequestV1) -> Result<DaemonHandlerPayloadV1, String> {
    if request.schema != DAEMON_HANDLER_REQUEST_SCHEMA {
        return Err("native_daemon_handler_schema_mismatch".to_owned());
    }
    let (kind, reply) = match &request.query {
        DaemonHandlerQueryV1::PolicyUpsert {
            harness,
            scope,
            action,
            artifact_id,
            workspace,
            publisher,
            reason,
        } => (
            "policy_upsert",
            policy_upsert(&PolicyUpsertInput {
                harness,
                scope,
                action,
                artifact_id,
                workspace,
                publisher,
                reason,
            }),
        ),
        DaemonHandlerQueryV1::PolicyClear {
            harness,
            source,
            scope,
            artifact_id,
            artifact_hash,
            workspace,
            publisher,
            all,
            artifact_id_is_null,
            artifact_hash_is_null,
        } => (
            "policy_clear",
            policy_clear(&PolicyClearInput {
                harness,
                source,
                scope,
                artifact_id,
                artifact_hash,
                workspace,
                publisher,
                all,
                artifact_id_is_null,
                artifact_hash_is_null,
            }),
        ),
        DaemonHandlerQueryV1::RequestsClear { status, harness } => {
            ("requests_clear", requests_clear(status, harness))
        }
        DaemonHandlerQueryV1::BulkAllow { request_ids } => ("bulk_allow", bulk_allow(request_ids)),
        DaemonHandlerQueryV1::RequestsList { query } => ("requests_list", requests_list(query)),
        DaemonHandlerQueryV1::HarnessAction { action, dry_run } => {
            ("harness_action", harness_action(action, dry_run))
        }
        DaemonHandlerQueryV1::EventsCursor { query } => ("events_cursor", events_cursor(query)),
    };
    Ok(DaemonHandlerPayloadV1 {
        kind: kind.to_owned(),
        outcome: reply.outcome.to_owned(),
        status: reply.status,
        body: reply.body,
        fields: reply.fields,
    })
}

#[cfg(test)]
#[path = "daemon_handler_tests.rs"]
mod tests;
