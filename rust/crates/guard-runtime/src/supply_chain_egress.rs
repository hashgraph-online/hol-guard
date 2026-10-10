//! Resident side of the brokered egress for `supply_chain_eval`.
//!
//! The resident never dials out for package evaluation: the caller owns the
//! managed network policy. An evaluation runs inside an [`EgressScope`] that
//! answers from the outcomes the caller supplied; whatever it could not answer
//! comes back as a `supply_chain_egress_required` question instead of a
//! verdict. See `guard_command::egress_broker` for the replay rules.

use std::path::Path;

use guard_command::egress_broker::{self, EgressScope};
use guard_contracts::{
    EgressNeedV1, EgressRequiredV1, SupplyChainEvalRequestV1, SupplyChainEvalResultV1,
    EGRESS_REQUIRED_CODE, PACKAGE_AUTHORITY_RESULT_SCHEMA,
};
use rusqlite::{Connection, OpenFlags};

/// Install the broker for one `supply_chain_eval` request.
pub(crate) fn enter_scope(request: &SupplyChainEvalRequestV1) -> Result<EgressScope, &'static str> {
    EgressScope::enter(
        request.egress_supplied.as_deref().unwrap_or(&[]),
        request.egress_spool_dir.as_deref(),
    )
}

/// The `ok` envelope that carries the exchanges the caller must perform. Its
/// `code`, not its status, says it is a question and not a verdict.
pub(crate) fn required_reply(
    request_id: &str,
    request_sha256: &str,
    needs: Vec<EgressNeedV1>,
) -> Result<Vec<u8>, String> {
    let payload = serde_json::to_value(EgressRequiredV1 { needs }).map_err(|e| e.to_string())?;
    crate::encode_response(&SupplyChainEvalResultV1 {
        schema: PACKAGE_AUTHORITY_RESULT_SCHEMA.to_owned(),
        request_id: request_id.to_owned(),
        request_sha256: request_sha256.to_owned(),
        status: "ok".to_owned(),
        code: EGRESS_REQUIRED_CODE.to_owned(),
        payload: Some(payload),
    })
}

/// Open the store. While an exchange is waiting on the caller the evaluation is
/// only exploring, and the round is discarded, so the connection is read-only
/// and every write it attempts fails closed instead of landing twice.
pub(crate) fn open_store(path: &Path) -> Result<Connection, rusqlite::Error> {
    if egress_broker::needs_pending() {
        return Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_URI
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        );
    }
    Connection::open(path)
}

/// A scope for an op that has no way to ask a caller: every exchange fails as
/// an unreachable network would.
pub(crate) fn deny_egress() -> Result<EgressScope, &'static str> {
    EgressScope::deny_all()
}
