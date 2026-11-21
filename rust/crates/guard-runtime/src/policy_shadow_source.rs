//! `policy_shadow_source` runner-authority kind: which stored v1 bundle a
//! v2 policy-bundle candidate is compared against, and whether the candidate
//! is rolled out to watch its rules rather than enforce them. Ported from
//! `_legacy_shadow_predates_candidate`, `_policy_bundle_is_evaluating` and the
//! shadow selection in `policy_bundle_candidate_decisions`.
//!
//! `{"candidate", "stored_legacy", "existing"}` answers `{"legacy",
//! "evaluating"}`. `candidate` is the whole bundle; the other two carry only
//! each stored bundle's `contractVersion` and `issuedAt` (or `null` when that
//! slot holds no bundle), because two more whole bundles would not fit one
//! request. `legacy` names the shadow: `"stored"` for the stored legacy
//! bundle, else `"existing"` for the active bundle when it is not itself a v2
//! bundle, else `null`. A shadow issued before the candidate belongs to an
//! older publication, so it cannot show whether the candidate's compiler
//! agrees and is dropped. Python still reads the store, compiles both bundles
//! and records the mismatch.

use serde_json::{json, Map, Value};

use crate::cloud_request_text::py_truthy;
use crate::guard_store_json::py_str;
use crate::policy_bundle_time::from_isoformat;
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const CANONICAL_CONTRACT: &str = "guard-policy-bundle.v2";

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let args = args_object(args)?;
    if args
        .keys()
        .any(|key| !matches!(key.as_str(), "candidate" | "stored_legacy" | "existing"))
    {
        return Err(ERR_INVALID);
    }
    let candidate = args
        .get("candidate")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?;
    let header = |key: &str| match args.get(key) {
        Some(Value::Object(header)) => Ok(Some(header)),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(ERR_INVALID),
    };
    let stored = header("stored_legacy")?.map(|header| ("stored", header));
    let existing = header("existing")?
        .filter(|header| {
            header.get("contractVersion").and_then(Value::as_str) != Some(CANONICAL_CONTRACT)
        })
        .map(|header| ("existing", header));
    let legacy = stored
        .or(existing)
        .filter(|(_, header)| !predates(header, candidate))
        .map(|(source, _)| source);
    Ok(json!({"legacy": legacy, "evaluating": evaluating(candidate)}))
}

/// Whether the shadow was issued for an older publication than the
/// candidate. Unreadable times keep the comparison.
fn predates(legacy: &Map<String, Value>, candidate: &Map<String, Value>) -> bool {
    match (issued(legacy), issued(candidate)) {
        (Some(legacy), Some(candidate)) => legacy < candidate,
        _ => false,
    }
}

/// `_parse_iso_timestamp(str(bundle.get("issuedAt") or ""))` in UTC
/// microseconds: `Z` reads as `+00:00`, then `datetime.fromisoformat` (which
/// also takes the compact `20261120T100000` form), and an instant without an
/// offset reads as UTC.
fn issued(bundle: &Map<String, Value>) -> Option<i64> {
    let value = bundle.get("issuedAt").filter(|value| py_truthy(value))?;
    from_isoformat(&py_str(value)?.replace('Z', "+00:00"))?.utc_micros()
}

/// `_policy_bundle_is_evaluating`: an Evaluate bundle compiles to no rows on
/// purpose, so an older bundle's rows say nothing about its drift.
fn evaluating(candidate: &Map<String, Value>) -> bool {
    candidate
        .get("payload")
        .and_then(Value::as_object)
        .and_then(|payload| payload.get("spec"))
        .and_then(Value::as_object)
        .and_then(|spec| spec.get("defaults"))
        .and_then(Value::as_object)
        .and_then(|defaults| defaults.get("mode"))
        .and_then(Value::as_str)
        == Some("observe")
}

#[cfg(test)]
#[path = "policy_shadow_source_tests.rs"]
mod tests;
