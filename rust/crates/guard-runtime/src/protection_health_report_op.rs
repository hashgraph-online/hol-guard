//! `ProtectionHealthReport` — resident op that evaluates one machine's
//! protection health.
//!
//! The grammar already lived in `guard_command::protection_health`, but
//! nothing reached it: Python kept its own copy of which failures degrade the
//! state, which four checks a platform may simply not have, how a harness's
//! own row is assembled and the words an operator reads for each state, and a
//! recorded fixture was all that held the two together. The caller now sends
//! the signals it collected and reads the report the resident answers with.
//!
//! A request whose check IDs, statuses, reason codes or harness identities the
//! grammar refuses comes back as an error, never as a report with the bad rows
//! dropped: a protection report that quietly leaves out a check it could not
//! read would claim proof it never had.

use std::collections::BTreeMap;

use guard_command::protection_health::{
    evaluate_protection_health, ProtectionCheckStatus, ProtectionSignal,
};
use guard_contracts::{
    ProtectionHealthReportRequestV1, ProtectionHealthReportResultV1, ProtectionSignalV1,
    PROTECTION_HEALTH_REPORT_MAX_REQUEST_BYTES, PROTECTION_HEALTH_REPORT_REQUEST_SCHEMA,
    PROTECTION_HEALTH_REPORT_RESULT_SCHEMA,
};

use crate::package_authority_op::request_digest_with_limit;

fn invalid() -> String {
    "native_protection_health_report_invalid".to_owned()
}

fn status(name: &str) -> Option<ProtectionCheckStatus> {
    match name {
        "pass" => Some(ProtectionCheckStatus::Pass),
        "unknown" => Some(ProtectionCheckStatus::Unknown),
        "fail" => Some(ProtectionCheckStatus::Fail),
        _ => None,
    }
}

/// The grammar's signals, keyed as the request keyed them.
///
/// `ProtectionSignal::new` is what refuses a free-form reason code, so a row
/// that cannot be built is the whole request's refusal.
fn signals(
    wire: &BTreeMap<String, ProtectionSignalV1>,
) -> Result<BTreeMap<String, ProtectionSignal>, String> {
    wire.iter()
        .map(|(key, signal)| {
            let status = status(&signal.status).ok_or_else(invalid)?;
            let signal =
                ProtectionSignal::new(status, &signal.reason_code).map_err(|_| invalid())?;
            Ok((key.clone(), signal))
        })
        .collect()
}

pub(crate) fn evaluate_protection_health_report(
    request: &ProtectionHealthReportRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 =
        request_digest_with_limit(request, PROTECTION_HEALTH_REPORT_MAX_REQUEST_BYTES)?;
    if request.schema != PROTECTION_HEALTH_REPORT_REQUEST_SCHEMA {
        return Err("native_protection_health_report_schema_mismatch".to_owned());
    }
    if request.request_id.is_empty() {
        return Err(invalid());
    }
    let report = evaluate_protection_health(
        &signals(&request.signals)?,
        &signals(&request.harness_signals)?,
    )
    .map_err(|_| invalid())?;
    let payload = serde_json::to_value(&report).map_err(|_| invalid())?;
    crate::encode_response(&ProtectionHealthReportResultV1 {
        schema: PROTECTION_HEALTH_REPORT_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        payload: Some(payload),
    })
}

#[cfg(test)]
#[path = "protection_health_report_op_tests.rs"]
mod tests;
