//! Decide whether one evidence receipt may promote a harness protection claim.
//!
//! A receipt describes a run that exercised one capability row of the
//! contract: which harness, event, transport and surface, on which Guard build,
//! harness version and platform, and what Guard decided. Only a receipt that
//! reports a run against a real harness with live inference, checked by an
//! independent verifier, can raise a claim above `configured`. Receipts that
//! report a unit test, fixture, replay or probe are always refused.
//!
//! The receipt is not authenticated. Its source, inference, verifier and
//! witness fields are self-reported, so this check catches an inconsistent or
//! honestly-labelled synthetic receipt; it cannot tell a forged receipt from a
//! real one. The payload says so (`provenance: self_reported`), and the claim
//! takes effect only through a reviewed contract change in which the reviewer
//! confirms the run named by `evidence_reference`.
//!
//! A live block claim needs a native deny that landed before the action took
//! effect, and a benign counterpart that the same row allowed, so a row that
//! denies everything cannot prove itself. The promoted claim expires after a
//! fixed window and is checked by the same rules as every bundled claim.
//!
//! This only proposes a contract edit. It never decides a tool call and
//! nothing here feeds policy, approval, or admission.

use serde::Deserialize;
use serde_json::{json, Value};

use super::{check_claim, check_event, utc_timestamp, Claim, Document, CONTRACT, SCHEMA};

const RECEIPT_SCHEMA: &str = "hol-guard.harness-claim-evidence.v1";
const PAYLOAD_SCHEMA: &str = "hol-guard.harness-claim-promotion.v1";
/// How long promoted evidence stands before the row shows `stale`.
const VALID_DAYS: i64 = 30;
/// Nothing authenticates a receipt yet; a reviewer confirms the referenced run.
const PROVENANCE: &str = "self_reported";
/// Where a promotion may come from. Everything else is synthetic.
const LIVE_SOURCES: [&str; 2] = ["installed_harness", "gauntlet_lane"];
const PROMOTABLE_STATES: [&str; 4] = [
    "transport_ready",
    "live_block_proven",
    "live_allow_proven",
    "partial",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: String,
    harness: String,
    event: String,
    transport: String,
    surface: String,
    state: String,
    guard_version: String,
    harness_version: String,
    platform: String,
    evidence_reference: String,
    observed_at: String,
    source: String,
    inference: String,
    independent_verifier: bool,
    witnesses: Vec<Witness>,
    #[serde(default)]
    limitations: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Witness {
    /// `deny` for the destructive case, `allow` for its benign counterpart.
    outcome: String,
    /// The hook event the harness actually sent.
    harness_event: String,
    /// `native` when the Rust runtime made the decision.
    decided_by: String,
    /// True when the decision reached the harness before the action ran.
    before_effect: bool,
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// `timestamp` plus `days`, in the same fixed form. `timestamp` must already
/// be a valid fixed-form UTC time.
fn add_days(timestamp: &str, days: i64) -> String {
    let field = |range: std::ops::Range<usize>| timestamp[range].parse::<i64>().unwrap_or(0);
    let (year, month, day) =
        civil_from_days(days_from_civil(field(0..4), field(5..7), field(8..10)) + days);
    format!("{year:04}-{month:02}-{day:02}{}", &timestamp[10..])
}

fn witnessed(receipt: &Receipt, outcome: &str) -> bool {
    receipt.witnesses.iter().any(|witness| {
        witness.outcome == outcome
            && witness.decided_by == "native"
            && witness.before_effect
            && witness.harness_event == receipt.event
    })
}

fn source_refusals(receipt: &Receipt, refusals: &mut Vec<String>) {
    if receipt.schema != RECEIPT_SCHEMA {
        refusals.push(format!(
            "receipt schema {:?} is not supported",
            receipt.schema
        ));
    }
    if !LIVE_SOURCES.contains(&receipt.source.as_str()) {
        refusals.push(format!(
            "a {:?} receipt is synthetic and cannot promote a claim",
            receipt.source
        ));
    }
    if receipt.inference != "live" {
        refusals.push(format!(
            "inference {:?} is not a live harness run",
            receipt.inference
        ));
    }
    if !receipt.independent_verifier {
        refusals.push("the run was not checked by an independent verifier".to_owned());
    }
    if !PROMOTABLE_STATES.contains(&receipt.state.as_str()) {
        refusals.push(format!(
            "{:?} is not a state evidence can promote to",
            receipt.state
        ));
    }
}

fn witness_refusals(receipt: &Receipt, refusals: &mut Vec<String>) {
    let deny = witnessed(receipt, "deny");
    let allow = witnessed(receipt, "allow");
    let needs: &[(bool, &str)] = match receipt.state.as_str() {
        "live_block_proven" => &[
            (deny, "a native deny of this event before the action ran"),
            (
                allow,
                "a native allow of a benign counterpart on this event",
            ),
        ],
        "live_allow_proven" => &[(allow, "a native allow of this event before the action ran")],
        _ => &[(deny || allow, "a native decision on this event")],
    };
    for (present, what) in needs {
        if !present {
            refusals.push(format!("{} needs {what}", receipt.state));
        }
    }
}

fn claim_for(receipt: &Receipt) -> Claim {
    Claim {
        state: receipt.state.clone(),
        guard_version: Some(receipt.guard_version.clone()),
        harness_version: Some(receipt.harness_version.clone()),
        platform: Some(receipt.platform.clone()),
        evidence_reference: Some(receipt.evidence_reference.clone()),
        observed_at: Some(receipt.observed_at.clone()),
        expires_at: utc_timestamp(&receipt.observed_at)
            .then(|| add_days(&receipt.observed_at, VALID_DAYS)),
        limitations: receipt.limitations.clone(),
    }
}

fn claim_value(claim: &Claim) -> Value {
    let mut value = json!({
        "state": claim.state,
        "guard_version": claim.guard_version,
        "harness_version": claim.harness_version,
        "platform": claim.platform,
        "evidence_reference": claim.evidence_reference,
        "observed_at": claim.observed_at,
        "expires_at": claim.expires_at,
    });
    if !claim.limitations.is_empty() {
        value["limitations"] = json!(claim.limitations);
    }
    value
}

/// Refusals for promoting `receipt` against `contract` at `now`, and the
/// claim it would write when there are none.
fn promote(contract: &str, receipt: &Value, now: &str) -> (Vec<String>, Option<Value>) {
    let receipt: Receipt = match serde_json::from_value(receipt.clone()) {
        Ok(receipt) => receipt,
        Err(error) => return (vec![format!("receipt does not parse: {error}")], None),
    };
    let mut refusals = Vec::new();
    source_refusals(&receipt, &mut refusals);
    witness_refusals(&receipt, &mut refusals);
    let document: Document = match serde_json::from_str(contract) {
        Ok(document) => document,
        Err(error) => return (vec![format!("contract does not parse: {error}")], None),
    };
    if document.schema != SCHEMA {
        refusals.push(format!(
            "contract schema {:?} is not supported",
            document.schema
        ));
        return (refusals, None);
    }
    let mut row = document
        .contracts
        .into_iter()
        .filter(|entry| entry.harness == receipt.harness)
        .flat_map(|entry| entry.capability_events)
        .find(|event| {
            event.event == receipt.event
                && event.transport == receipt.transport
                && event.surface.as_deref() == Some(receipt.surface.as_str())
        });
    let Some(event) = row.as_mut() else {
        refusals.push(
            "the contract declares no row for this harness, event, transport and surface"
                .to_owned(),
        );
        return (refusals, None);
    };
    if !matches!(
        event.failure_behavior.as_deref(),
        Some("fail_closed" | "fail_open")
    ) {
        refusals.push("only a row that can enforce can carry live evidence".to_owned());
    }
    let claim = claim_for(&receipt);
    if utc_timestamp(&receipt.observed_at) {
        if receipt.observed_at.as_str() > now {
            refusals.push("observed_at is in the future".to_owned());
        }
        if claim
            .expires_at
            .as_deref()
            .is_some_and(|expires| expires <= now)
        {
            refusals.push(format!(
                "the evidence is older than {VALID_DAYS} days and has already expired"
            ));
        }
    }
    let mut problems = Vec::new();
    check_claim(&claim, &mut problems);
    let value = claim_value(&claim);
    event.claim = Some(claim);
    problems.extend(check_event(event));
    refusals.extend(problems);
    refusals.dedup();
    (refusals.clone(), refusals.is_empty().then_some(value))
}

/// The promotion decision for `params`: `receipt` (required), `now`
/// (required, fixed-form UTC), and `contract` (the source-tree contract text;
/// the contract built into this runtime when absent).
pub(crate) fn promotion_payload(params: &Value) -> Result<Value, &'static str> {
    let now = params
        .get("now")
        .and_then(Value::as_str)
        .filter(|now| utc_timestamp(now))
        .ok_or("harness_claim_promotion_time_invalid")?;
    let receipt = params
        .get("receipt")
        .ok_or("harness_claim_promotion_receipt_missing")?;
    let contract = match params.get("contract") {
        None => CONTRACT,
        Some(value) => value
            .as_str()
            .ok_or("harness_claim_promotion_contract_invalid")?,
    };
    let (refusals, claim) = promote(contract, receipt, now);
    Ok(json!({
        "schema": PAYLOAD_SCHEMA,
        "receipt_schema": RECEIPT_SCHEMA,
        "promotable": claim.is_some(),
        "refusals": refusals,
        "claim": claim,
        "valid_days": VALID_DAYS,
        "provenance": PROVENANCE,
    }))
}

#[cfg(test)]
#[path = "harness_claim_promotion_tests.rs"]
mod tests;
