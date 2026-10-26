//! The caller's `supply_chain_eval` transport over the resident lane.
//!
//! Port of `_send_eval_request` and the `_resident_request` envelope it sends
//! (`native_package_authority.py:50`). One round is one request on the lane the
//! caller already holds: the envelope names the operation and the budget the
//! resident must answer inside, the answer is read back as the result DTO, and
//! the runtime's health records what happened.
//!
//! This moves bytes and nothing else. The verdict is the resident's, the
//! binding of an answer to the request it answers belongs to the round loop
//! (`supply_chain_eval_rounds::send`), and an answer that is not available, not
//! readable or not the result schema leaves the caller with no verdict to act
//! on - never a weaker one.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use guard_contracts::{
    SupplyChainEvalRequestV1, SupplyChainEvalResultV1, PACKAGE_AUTHORITY_RESULT_SCHEMA,
};
use serde_json::{json, Value};

use crate::native_runtime_resilience::{
    native_record_resident_failure, native_record_resident_success,
};
use crate::supply_chain_eval_rounds::SupplyChainEvalTransport;

/// `_EVAL_TIMEOUT_SECONDS`: a package evaluation resolves ranges, reads
/// registries and verifies archives, so one round's budget is the evaluation's,
/// not a hook's.
const EVAL_TIMEOUT: Duration = Duration::from_secs(25);
/// `_EVAL_MAX_REQUEST_BYTES`: the replayed egress outcomes ride in every round.
/// The round loop digests a request under the same cap before it reaches a
/// transport; this is the cap on the frame this transport actually writes, so
/// an envelope is never sent past what the lane accepts.
const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;
/// The resident operation this transport calls.
const OPERATION: &str = "supply_chain_eval";
/// `native_<operation>_transport`: the lane had no answer.
const REASON_TRANSPORT: &str = "native_supply_chain_eval_transport";
/// `native_<operation>_malformed`: the answer was not JSON.
const REASON_MALFORMED: &str = "native_supply_chain_eval_malformed";
/// `native_<operation>_schema`: the answer was JSON of another shape.
const REASON_SCHEMA: &str = "native_supply_chain_eval_schema";
/// `native_supply_chain_eval_unbound`: the answer carried the result schema but
/// not a result (`_record_unbound_answer`).
const REASON_UNBOUND: &str = "native_supply_chain_eval_unbound";

/// The resident lane one request travels on.
///
/// The relay owns the lane - discovery, the direct-lane identity check and the
/// token - and this transport only borrows it for the length of an evaluation.
pub(crate) trait ResidentLane {
    /// Send one payload and read the answer, or `None` when the lane had none
    /// to give by `deadline`.
    fn exchange_until(&mut self, payload: &[u8], deadline: Instant) -> Option<Vec<u8>>;

    /// The digest of the runtime the lane last reached, which keys its health.
    /// `None` before any resident has been reached, when there is no runtime
    /// yet to record anything about.
    fn runtime_sha256(&self) -> Option<String>;
}

/// One evaluation's transport: the lane, and the home whose runtime health the
/// rounds are recorded against.
pub(crate) struct ResidentEvalTransport<'lane> {
    lane: &'lane mut dyn ResidentLane,
    guard_home: PathBuf,
}

impl<'lane> ResidentEvalTransport<'lane> {
    /// `guard_home` is the home the caller evaluates in; the request names the
    /// same one, and the resident's health is kept per home.
    pub(crate) fn new(lane: &'lane mut dyn ResidentLane, guard_home: &Path) -> Self {
        Self {
            lane,
            guard_home: guard_home.to_path_buf(),
        }
    }

    /// Record against the runtime this round was sent to.
    ///
    /// The lane reports the runtime it holds now; a round that tore the lane
    /// down leaves none, so `sent_to` - the runtime the lane held before the
    /// round - is what that failure is recorded against. When neither names a
    /// runtime, no resident was ever reached and there is nothing to record.
    fn record(&self, sent_to: Option<&str>, failure: Option<&str>) {
        let held = self.lane.runtime_sha256();
        let Some(digest) = held.as_deref().or(sent_to) else {
            return;
        };
        match failure {
            Some(reason) => native_record_resident_failure(digest, &self.guard_home, reason),
            None => native_record_resident_success(digest, &self.guard_home),
        }
    }
}

impl SupplyChainEvalTransport for ResidentEvalTransport<'_> {
    fn evaluate(&mut self, request: &SupplyChainEvalRequestV1) -> Option<SupplyChainEvalResultV1> {
        // `deadline_budget_ms`: what the resident has for this round. Python
        // gives every round the full evaluation timeout, and the round loop -
        // not a shared clock - is what bounds an evaluation.
        let budget = EVAL_TIMEOUT;
        // The runtime the round is sent to, read before the round so a
        // failure that tore the lane down is still recorded against it.
        let held_before = self.lane.runtime_sha256();
        let sent_to = held_before.as_deref();
        let payload = serde_json::to_vec(&json!({
            "operation": OPERATION,
            "request": request,
            "deadline_budget_ms": budget.as_millis().max(1),
        }))
        .ok()?;
        if payload.len() > MAX_REQUEST_BYTES {
            // A request this caller cannot send is its own failure, not the
            // resident's: there is nothing to record about the runtime.
            return None;
        }
        let Some(answer) = self.lane.exchange_until(&payload, Instant::now() + budget) else {
            self.record(sent_to, Some(REASON_TRANSPORT));
            return None;
        };
        let Ok(decoded) = serde_json::from_slice::<Value>(&answer) else {
            self.record(sent_to, Some(REASON_MALFORMED));
            return None;
        };
        if !decoded.is_object() {
            return None;
        }
        if decoded.get("schema").and_then(Value::as_str) != Some(PACKAGE_AUTHORITY_RESULT_SCHEMA) {
            self.record(sent_to, Some(REASON_SCHEMA));
            return None;
        }
        if decoded.get("status").and_then(Value::as_str) != Some("ok") {
            // The resident answered that it has no result. A caller must not
            // read that as permission to decide the request some other way, so
            // this is not a runtime failure and not a verdict either.
            return None;
        }
        // The result DTO refuses a field it does not know, exactly as Python
        // refuses keys outside `_RESULT_KEYS`: an answer carrying the result
        // schema and something else is a resident failure, recorded here so
        // the round loop reports it once.
        //
        // Duplicate member names are not rejected. Python reads the answer
        // with a duplicate-refusing hook, and that check only matters against
        // whoever writes the answer bytes - here, the resident that authenticated
        // on the direct lane and could simply answer `status: "ok"` instead.
        //
        // The round is recorded once the answer has been read, not when it
        // arrives: a success recorded first would clear the consecutive count
        // that an unbound answer then raises, and a resident answering nothing
        // but unbound results would never reach the circuit's threshold.
        match serde_json::from_value::<SupplyChainEvalResultV1>(decoded) {
            Ok(result) => {
                self.record(sent_to, None);
                Some(result)
            }
            Err(_) => {
                self.record(sent_to, Some(REASON_UNBOUND));
                None
            }
        }
    }
}

#[cfg(test)]
#[path = "supply_chain_eval_transport_tests.rs"]
mod tests;
