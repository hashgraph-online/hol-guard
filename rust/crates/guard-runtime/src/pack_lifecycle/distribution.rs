//! Structural validation of the authenticated catalog distribution root and of
//! the provenance statement that attests it. Sigstore has already verified the
//! signature before a statement reaches here: this module decides only whether
//! the signed content describes this publisher's workflow, source and subject,
//! and whether a root's shape, epochs and validity window are acceptable.
//! Failures are stable `distribution_*` codes; the caller owns their wording.
use super::{hex, location::Rejection};
use serde_json::Value;

mod root;
mod statement;
#[cfg(test)]
#[path = "distribution_statement_tests.rs"]
mod statement_tests;
#[cfg(test)]
#[path = "distribution_tests.rs"]
mod tests;

pub(super) fn evaluate(input: &Value) -> Result<Value, String> {
    match input["operation"].as_str() {
        Some("root") => root::validate(input),
        Some("provenance-statement") => statement::validate(input),
        _ => Err("distribution_operation_invalid".into()),
    }
}

fn location_code(rejection: &Rejection) -> &'static str {
    match rejection {
        Rejection::Location => "distribution_location_invalid",
        Rejection::Identity => "distribution_location_identity_invalid",
        Rejection::Container => "distribution_location_container_invalid",
    }
}

/// Strict parsing refuses duplicate keys, oversize nesting and non-finite
/// numbers; each failure keeps the reason a caller reports.
fn json_failure(code: &str) -> &'static str {
    match code {
        "native_json_duplicate_key" => "distribution_duplicate_field",
        "native_json_number_invalid" => "distribution_nonfinite_value",
        _ => "distribution_encoding_invalid",
    }
}
