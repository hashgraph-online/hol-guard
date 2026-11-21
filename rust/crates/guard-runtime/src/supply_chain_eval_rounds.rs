//! Caller side of a `supply_chain_eval`: the rounds, their binding and the
//! payload the evaluation settles on.
//!
//! Port of `native_supply_chain_eval_payload`. The resident owns every verdict;
//! this module only moves bytes and enforces what a caller must enforce:
//!
//! * every round carries a fresh request id and one pinned `now`, so a
//!   multi-round evaluation reads a single clock,
//! * every answer is bound to the exact request it answers - schema, request id
//!   and canonical request digest - and an unbound answer is a resident failure
//!   rather than a verdict,
//! * a `supply_chain_egress_required` answer is replayed with the outcomes the
//!   caller performed, and a `saved_policy_probe_required` answer is answered
//!   once,
//! * an evaluation that does not settle inside [`MAX_ROUNDS`] is a failure, not
//!   whatever the last round said,
//! * the settled payload has to be a complete evaluation, and the archives it
//!   names have to be archives this caller actually holds.
//!
//! Nothing here recomputes a decision, relaxes one, or answers from a previous
//! round: a failure is reported to the caller, which fails the request closed.

// The MCP front end that drives these rounds lands with the native relay lane;
// until it does, only the tests below call into the loop.
#![allow(dead_code)]

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use guard_command::egress_caller::EgressFulfilment;
use guard_command::restricted_archive::RestrictedArchiveDownload;
use guard_contracts::{
    EgressNeedV1, EgressRequiredV1, EgressSuppliedV1, SavedPolicyProbeV1, SupplyChainEvalRequestV1,
    SupplyChainEvalResultV1, EGRESS_REQUIRED_CODE, PACKAGE_AUTHORITY_RESULT_SCHEMA,
};
use serde_json::Value;

/// `_MAX_ROUNDS`: the first request plus this many follow-ups. The resident
/// collects a round's lookups at once, so an ordinary evaluation settles in a
/// handful of them.
pub(crate) const MAX_ROUNDS: usize = 24;
/// `_EVAL_MAX_REQUEST_BYTES`: replayed egress outcomes ride in every round, so
/// the generic package-authority cap is too small; this stays under the native
/// frame cap.
const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;
/// `_PROBE_REQUIRED_CODE`: the resident's question about a saved policy row it
/// cannot read itself, which `supply_chain_eval_op` answers with.
const PROBE_REQUIRED_CODE: &str = "saved_policy_probe_required";
/// `_PAYLOAD_DECISIONS`.
const PAYLOAD_DECISIONS: [&str; 5] = ["allow", "monitor", "warn", "ask", "block"];
/// `_PAYLOAD_TEXT_KEYS`.
const PAYLOAD_TEXT_KEYS: [&str; 7] = [
    "policy_action",
    "enforcement",
    "entitlement_state",
    "cache_status",
    "package_intent_hash",
    "policy_version",
    "risk_summary",
];

/// Why no settled evaluation came back.
///
/// Both variants fail the package request closed. They differ only in what the
/// caller records: an answer that was not bound to the request this caller
/// sent, or an evaluation that never settled, is a resident failure
/// (`_record_unbound_answer`), while a transport that already recorded its own
/// failure must not be counted twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RoundsError {
    /// No authoritative answer; the transport recorded why.
    Unavailable(&'static str),
    /// An answer arrived, but not one this caller may treat as a verdict.
    ResidentFailure(&'static str),
}

impl RoundsError {
    /// Whether the caller records a resident failure for this outcome.
    pub(crate) fn records_resident_failure(&self) -> bool {
        matches!(self, Self::ResidentFailure(_))
    }

    /// The short reason, for the caller's own diagnostics. It is never a
    /// verdict and never reaches a harness message.
    pub(crate) fn reason(&self) -> &'static str {
        match self {
            Self::Unavailable(reason) | Self::ResidentFailure(reason) => reason,
        }
    }
}

/// What one settled evaluation hands back.
#[derive(Debug)]
pub(crate) struct SettledEvaluation {
    /// `PackageRequestEvaluation.to_dict()`, already checked for completeness.
    pub(crate) payload: Value,
    /// The verified external-archive blobs the answer asked the caller to
    /// keep. The caller removes them with `cleanup` once it is done.
    pub(crate) retained_archives: Vec<RestrictedArchiveDownload>,
}

/// Whatever answers one request. The resident answers it in production; a test
/// answers it from a scripted sequence.
pub(crate) trait SupplyChainEvalTransport {
    /// The resident's answer, or `None` when none was available. A transport
    /// that fails records its own failure.
    fn evaluate(&mut self, request: &SupplyChainEvalRequestV1) -> Option<SupplyChainEvalResultV1>;
}

/// The caller's own egress: it performs the exchanges one answer asks for,
/// keeps every outcome the next round must carry, and owns the archives the
/// evaluation may ask it to retain.
pub(crate) trait CallerEgress {
    /// Where a spooled body is written; the next request names it.
    fn spool_dir(&self) -> &Path;
    /// Perform one answer's needs.
    fn fulfil(&mut self, needs: &[EgressNeedV1]) -> Result<(), &'static str>;
    /// Every outcome so far, in the order asked.
    fn supplied(&self) -> &[EgressSuppliedV1];
    /// The retained blobs the settled answer names.
    fn claim_archives(
        &mut self,
        descriptors: Option<&Value>,
    ) -> Result<Vec<RestrictedArchiveDownload>, &'static str>;
}

impl CallerEgress for EgressFulfilment<'_> {
    fn spool_dir(&self) -> &Path {
        EgressFulfilment::spool_dir(self)
    }

    fn fulfil(&mut self, needs: &[EgressNeedV1]) -> Result<(), &'static str> {
        EgressFulfilment::fulfil(self, needs)
    }

    fn supplied(&self) -> &[EgressSuppliedV1] {
        EgressFulfilment::supplied(self)
    }

    fn claim_archives(
        &mut self,
        descriptors: Option<&Value>,
    ) -> Result<Vec<RestrictedArchiveDownload>, &'static str> {
        EgressFulfilment::claim_archives(self, descriptors)
    }
}

/// Reads the saved policy row that covers a cached Cloud validation error.
/// Hydration only: the resident decides what the row means.
pub(crate) trait SavedPolicyReader {
    /// The `lookup["decision"]` row, or `None` when none matched.
    fn lookup(&mut self, cached: &Value) -> Option<Value>;
}

/// Drive one package evaluation to a settled payload.
///
/// `request` carries everything the evaluation is about; the round fields
/// (`request_id`, `now`, `egress_supplied`, `egress_spool_dir`,
/// `saved_policy_probe`) are this function's to set.
pub(crate) fn evaluate_rounds(
    request: SupplyChainEvalRequestV1,
    transport: &mut dyn SupplyChainEvalTransport,
    egress: &mut dyn CallerEgress,
    probe: Option<&mut dyn SavedPolicyReader>,
) -> Result<SettledEvaluation, RoundsError> {
    let settled = settle(request, transport, egress, probe);
    if settled.is_err() {
        // Python discards the retained blobs from its exit stack on every
        // failed exit. A verified archive nobody claimed must not outlive the
        // evaluation it was downloaded for: claiming nothing removes the pool.
        let _ = egress.claim_archives(None);
    }
    settled
}

fn settle(
    mut request: SupplyChainEvalRequestV1,
    transport: &mut dyn SupplyChainEvalTransport,
    egress: &mut dyn CallerEgress,
    mut probe: Option<&mut dyn SavedPolicyReader>,
) -> Result<SettledEvaluation, RoundsError> {
    // `fixed_now`: the clock is read once. Every follow-up repeats this value,
    // so a round never sees a later time than the round before it.
    let pinned_now = request.now.clone().unwrap_or_else(utc_now_text);
    let mut probed = false;
    request.request_id = next_request_id();
    let mut response = send(&request, transport)?;
    // The first request plus at most `MAX_ROUNDS` follow-ups; the answer to the
    // last follow-up is inspected too, so a verdict reached on it still counts.
    for round_index in 0..=MAX_ROUNDS {
        let answered_ok = response.status == "ok";
        let needs_egress = answered_ok && response.code == EGRESS_REQUIRED_CODE;
        let cached_policy = response
            .payload
            .as_ref()
            .filter(|_| answered_ok && response.code == PROBE_REQUIRED_CODE && !probed)
            .filter(|payload| payload.is_object())
            .filter(|_| probe.is_some());
        if !needs_egress && cached_policy.is_none() {
            break;
        }
        if round_index == MAX_ROUNDS {
            return Err(RoundsError::ResidentFailure("did_not_settle"));
        }
        if needs_egress {
            // The resident cannot reach the network itself: perform what it
            // asked for under the caller's managed network policy and replay
            // with the outcomes.
            let asked = response
                .payload
                .as_ref()
                .and_then(|payload| {
                    serde_json::from_value::<EgressRequiredV1>(payload.clone()).ok()
                })
                .ok_or(RoundsError::ResidentFailure("egress_request_invalid"))?;
            egress
                .fulfil(&asked.needs)
                .map_err(RoundsError::ResidentFailure)?;
            let spool_dir = egress
                .spool_dir()
                .to_str()
                .ok_or(RoundsError::Unavailable("egress_spool_dir_invalid"))?
                .to_owned();
            request.egress_supplied = Some(egress.supplied().to_vec());
            request.egress_spool_dir = Some(spool_dir);
        } else if let Some(cached) = cached_policy {
            probed = true;
            let decision = probe
                .as_deref_mut()
                .and_then(|probe| probe.lookup(cached))
                .filter(Value::is_object);
            request.saved_policy_probe = Some(SavedPolicyProbeV1 { decision });
        }
        request.request_id = next_request_id();
        request.now = Some(pinned_now.clone());
        response = send(&request, transport)?;
    }
    if response.status != "ok" || response.code != "ok" {
        return Err(RoundsError::Unavailable("not_a_verdict"));
    }
    let payload = response
        .payload
        .filter(payload_is_complete)
        .ok_or(RoundsError::ResidentFailure("payload_invalid"))?;
    let retained_archives = if request.retain_external_archive_blob {
        egress
            .claim_archives(payload.get("external_archive_inspection"))
            .map_err(|_| RoundsError::ResidentFailure("archive_binding_invalid"))?
    } else {
        Vec::new()
    };
    Ok(SettledEvaluation {
        payload,
        retained_archives,
    })
}

/// Send one round and return only an answer bound to it.
///
/// `_send_eval_request` plus `_bound_response`: the digest is this caller's own
/// of the exact request it sent, so an answer carrying another round's id or
/// another request's digest is not this request answered.
fn send(
    request: &SupplyChainEvalRequestV1,
    transport: &mut dyn SupplyChainEvalTransport,
) -> Result<SupplyChainEvalResultV1, RoundsError> {
    let request_sha256 =
        crate::package_authority_op::request_digest_with_limit(request, MAX_REQUEST_BYTES)
            .map_err(|_| RoundsError::Unavailable("request_invalid"))?;
    let response = transport
        .evaluate(request)
        .ok_or(RoundsError::Unavailable("no_answer"))?;
    if response.schema != PACKAGE_AUTHORITY_RESULT_SCHEMA
        || response.request_id != request.request_id
        || response.request_sha256 != request_sha256
    {
        return Err(RoundsError::ResidentFailure("unbound_answer"));
    }
    Ok(response)
}

/// `_payload_is_complete`: a partial payload is not an evaluation, so the
/// caller fails closed instead of hydrating a decision out of defaults.
fn payload_is_complete(payload: &Value) -> bool {
    let Some(object) = payload.as_object() else {
        return false;
    };
    if !object
        .get("decision")
        .and_then(Value::as_str)
        .is_some_and(|decision| PAYLOAD_DECISIONS.contains(&decision))
    {
        return false;
    }
    if !PAYLOAD_TEXT_KEYS
        .iter()
        .all(|key| object.get(*key).is_some_and(Value::is_string))
    {
        return false;
    }
    if !["reasons", "packages"]
        .iter()
        .all(|key| object.get(*key).is_some_and(Value::is_array))
    {
        return false;
    }
    object
        .get("user_copy")
        .and_then(Value::as_object)
        .is_some_and(|copy| {
            ["title", "summary", "harness_message"]
                .iter()
                .all(|key| copy.get(*key).is_some_and(Value::is_string))
        })
}

/// `_request_id`: `package-authority-<counter>-<monotonic nanos>`. The id is
/// per round, so an answer to an earlier round cannot pass as an answer to this
/// one even when the rest of the request is identical.
fn next_request_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed) + 1;
    let nanos = process_start().elapsed().as_nanos();
    format!("package-authority-{counter}-{nanos}")
}

/// A monotonic origin for the request id, like `time.monotonic_ns`: the id
/// carries elapsed process time and never a wall-clock reading.
fn process_start() -> Instant {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    *START.get_or_init(Instant::now)
}

/// `_now_text`: `datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")`.
fn utc_now_text() -> String {
    let iso = guard_command::local_supply_chain::utc_now_iso();
    match iso.strip_suffix("+00:00") {
        Some(seconds) => format!("{seconds}Z"),
        None => iso,
    }
}

#[cfg(test)]
#[path = "supply_chain_eval_rounds_tests.rs"]
mod tests;
