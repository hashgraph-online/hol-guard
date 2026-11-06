//! What the caller-side round loop enforces: binding, the pinned clock, the
//! replayed egress outcomes, the one-shot saved-policy probe, the round bound,
//! and the completeness of the payload it settles on.
//!
//! Every dependency that would otherwise reach a resident or the network is
//! injected, so these exercise the loop itself and nothing else.

use super::*;
use guard_contracts::{EgressOutcomeV1, PACKAGE_AUTHORITY_REQUEST_SCHEMA};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::PathBuf;

fn request() -> SupplyChainEvalRequestV1 {
    SupplyChainEvalRequestV1 {
        schema: PACKAGE_AUTHORITY_REQUEST_SCHEMA.to_owned(),
        request_id: String::new(),
        store_path: "/tmp/guard.db".to_owned(),
        guard_home: "/tmp/guard-home".to_owned(),
        artifact: json!({"kind": "package_request", "metadata": {}, "files": []}),
        workspace_dir: None,
        now: None,
        external_archive_network_authorized: false,
        retain_external_archive_blob: false,
        runtime_private_metadata: None,
        sync_auth_context_override: None,
        package_entitlement_override: None,
        registry_metadata_override: None,
        saved_policy_probe: None,
        egress_supplied: None,
        egress_spool_dir: None,
    }
}

fn complete_payload() -> Value {
    json!({
        "decision": "allow",
        "policy_action": "allow",
        "enforcement": "enforced",
        "entitlement_state": "entitled",
        "cache_status": "miss",
        "package_intent_hash": "sha256:abc",
        "policy_version": "1",
        "risk_summary": "none",
        "reasons": [],
        "packages": [],
        "user_copy": {"title": "t", "summary": "s", "harness_message": "h"},
    })
}

fn need(url: &str) -> EgressNeedV1 {
    EgressNeedV1 {
        class: "registry_metadata".to_owned(),
        method: "GET".to_owned(),
        url: url.to_owned(),
        headers: BTreeMap::new(),
        body: None,
        body_sha256: String::new(),
        occurrence: 1,
        timeout_seconds: 5.0,
        max_redirects: 2,
        max_response_bytes: 1024,
        delay_seconds: 0.0,
        inspect: None,
    }
}

/// One scripted answer, built against the request it answers so the binding is
/// correct unless a case deliberately breaks it.
struct Answer {
    status: &'static str,
    code: &'static str,
    payload: Option<Value>,
    /// Replaces the echoed request id, for the unbound cases.
    request_id: Option<&'static str>,
    /// Replaces the echoed request digest.
    request_sha256: Option<&'static str>,
    /// Replaces the echoed schema.
    schema: Option<&'static str>,
    /// No answer at all.
    silent: bool,
}

impl Answer {
    fn ok(code: &'static str, payload: Option<Value>) -> Self {
        Self {
            status: "ok",
            code,
            payload,
            request_id: None,
            request_sha256: None,
            schema: None,
            silent: false,
        }
    }

    fn verdict() -> Self {
        Self::ok("ok", Some(complete_payload()))
    }

    fn egress(urls: &[&str]) -> Self {
        let needs: Vec<EgressNeedV1> = urls.iter().map(|url| need(url)).collect();
        Self::ok(
            EGRESS_REQUIRED_CODE,
            Some(serde_json::to_value(EgressRequiredV1 { needs }).expect("needs serialize")),
        )
    }

    fn probe_required() -> Self {
        Self::ok(
            PROBE_REQUIRED_CODE,
            Some(json!({"error": "cloud_validation_cached", "package": "left-pad"})),
        )
    }
}

/// Answers from a script and records every request it was handed.
struct ScriptedTransport {
    answers: Vec<Answer>,
    /// Keeps answering with the last scripted answer once the script runs out.
    repeat_last: bool,
    seen: Vec<SupplyChainEvalRequestV1>,
}

impl ScriptedTransport {
    fn new(answers: Vec<Answer>) -> Self {
        Self {
            answers,
            repeat_last: false,
            seen: Vec::new(),
        }
    }

    fn repeating(answers: Vec<Answer>) -> Self {
        Self {
            repeat_last: true,
            ..Self::new(answers)
        }
    }
}

impl SupplyChainEvalTransport for ScriptedTransport {
    fn evaluate(&mut self, request: &SupplyChainEvalRequestV1) -> Option<SupplyChainEvalResultV1> {
        self.seen.push(request.clone());
        let answer = if self.answers.len() > 1 || !self.repeat_last {
            self.answers.remove(0)
        } else {
            let last = self.answers.first().expect("script exhausted");
            Answer {
                status: last.status,
                code: last.code,
                payload: last.payload.clone(),
                request_id: last.request_id,
                request_sha256: last.request_sha256,
                schema: last.schema,
                silent: last.silent,
            }
        };
        if answer.silent {
            return None;
        }
        let digest =
            crate::package_authority_op::request_digest_with_limit(request, MAX_REQUEST_BYTES)
                .expect("digest");
        Some(SupplyChainEvalResultV1 {
            schema: answer
                .schema
                .unwrap_or(PACKAGE_AUTHORITY_RESULT_SCHEMA)
                .to_owned(),
            request_id: answer
                .request_id
                .map(str::to_owned)
                .unwrap_or_else(|| request.request_id.clone()),
            request_sha256: answer.request_sha256.map(str::to_owned).unwrap_or(digest),
            status: answer.status.to_owned(),
            code: answer.code.to_owned(),
            payload: answer.payload,
        })
    }
}

/// An egress that records what it was asked for and performs nothing.
struct StubEgress {
    spool: PathBuf,
    supplied: Vec<EgressSuppliedV1>,
    asked: Vec<Vec<EgressNeedV1>>,
    fulfil_error: Option<&'static str>,
    claim_error: Option<&'static str>,
    claimed: Vec<Option<Value>>,
}

impl StubEgress {
    fn new() -> Self {
        Self {
            spool: PathBuf::from("/tmp/hol-guard-egress-test"),
            supplied: Vec::new(),
            asked: Vec::new(),
            fulfil_error: None,
            claim_error: None,
            claimed: Vec::new(),
        }
    }
}

impl CallerEgress for StubEgress {
    fn spool_dir(&self) -> &Path {
        &self.spool
    }

    fn fulfil(&mut self, needs: &[EgressNeedV1]) -> Result<(), &'static str> {
        self.asked.push(needs.to_vec());
        if let Some(error) = self.fulfil_error {
            return Err(error);
        }
        for need in needs {
            self.supplied.push(EgressSuppliedV1 {
                class: need.class.clone(),
                method: need.method.clone(),
                url: need.url.clone(),
                body_sha256: need.body_sha256.clone(),
                occurrence: need.occurrence,
                outcome: EgressOutcomeV1::Response {
                    status: 200,
                    headers: BTreeMap::new(),
                    body: Some("{}".to_owned()),
                    body_file: None,
                },
            });
        }
        Ok(())
    }

    fn supplied(&self) -> &[EgressSuppliedV1] {
        &self.supplied
    }

    fn claim_archives(
        &mut self,
        descriptors: Option<&Value>,
    ) -> Result<Vec<RestrictedArchiveDownload>, &'static str> {
        self.claimed.push(descriptors.cloned());
        match self.claim_error {
            Some(error) => Err(error),
            None => Ok(Vec::new()),
        }
    }
}

/// Answers the probe from a fixed row and counts how often it was asked.
struct StubProbe {
    decision: Option<Value>,
    asked: Vec<Value>,
}

impl StubProbe {
    fn new(decision: Option<Value>) -> Self {
        Self {
            decision,
            asked: Vec::new(),
        }
    }
}

impl SavedPolicyReader for StubProbe {
    fn lookup(&mut self, cached: &Value) -> Option<Value> {
        self.asked.push(cached.clone());
        self.decision.clone()
    }
}

#[test]
fn a_bound_verdict_settles_in_one_round() {
    let mut transport = ScriptedTransport::new(vec![Answer::verdict()]);
    let mut egress = StubEgress::new();
    let settled = evaluate_rounds(request(), &mut transport, &mut egress, None).expect("settles");
    assert_eq!(settled.payload, complete_payload());
    assert!(settled.retained_archives.is_empty());
    assert_eq!(transport.seen.len(), 1);
    // A request the caller never named cannot be answered: the loop sets one.
    assert!(transport.seen[0]
        .request_id
        .starts_with("package-authority-"));
    assert!(egress.asked.is_empty());
    // Nothing was claimed, because nothing was retained.
    assert!(egress.claimed.is_empty());
}

#[test]
fn an_answer_naming_another_request_is_a_resident_failure() {
    let mut transport = ScriptedTransport::new(vec![Answer {
        request_id: Some("package-authority-999-1"),
        ..Answer::verdict()
    }]);
    let mut egress = StubEgress::new();
    let error = evaluate_rounds(request(), &mut transport, &mut egress, None).expect_err("unbound");
    assert_eq!(error, RoundsError::ResidentFailure("unbound_answer"));
    assert!(error.records_resident_failure());
}

#[test]
fn an_answer_carrying_another_requests_digest_is_a_resident_failure() {
    let mut transport = ScriptedTransport::new(vec![Answer {
        request_sha256: Some("sha256:0000"),
        ..Answer::verdict()
    }]);
    let mut egress = StubEgress::new();
    let error = evaluate_rounds(request(), &mut transport, &mut egress, None).expect_err("unbound");
    assert_eq!(error, RoundsError::ResidentFailure("unbound_answer"));
}

#[test]
fn an_answer_on_another_schema_is_a_resident_failure() {
    let mut transport = ScriptedTransport::new(vec![Answer {
        schema: Some("guard-something-else.v1"),
        ..Answer::verdict()
    }]);
    let mut egress = StubEgress::new();
    let error = evaluate_rounds(request(), &mut transport, &mut egress, None).expect_err("unbound");
    assert_eq!(error, RoundsError::ResidentFailure("unbound_answer"));
}

#[test]
fn no_answer_is_unavailable_and_not_a_resident_failure() {
    let mut transport = ScriptedTransport::new(vec![Answer {
        silent: true,
        ..Answer::verdict()
    }]);
    let mut egress = StubEgress::new();
    let error = evaluate_rounds(request(), &mut transport, &mut egress, None).expect_err("silent");
    assert_eq!(error, RoundsError::Unavailable("no_answer"));
    assert!(!error.records_resident_failure());
}

#[test]
fn an_egress_round_replays_the_outcomes_and_names_the_spool_directory() {
    let mut transport = ScriptedTransport::new(vec![
        Answer::egress(&["https://registry.npmjs.org/left-pad"]),
        Answer::verdict(),
    ]);
    let mut egress = StubEgress::new();
    evaluate_rounds(request(), &mut transport, &mut egress, None).expect("settles");
    assert_eq!(transport.seen.len(), 2);
    assert_eq!(egress.asked.len(), 1);
    assert_eq!(
        egress.asked[0][0].url,
        "https://registry.npmjs.org/left-pad"
    );
    let replay = &transport.seen[1];
    assert_eq!(
        replay.egress_supplied.as_ref().map(Vec::len),
        Some(1),
        "the round carries the outcome the caller performed"
    );
    assert_eq!(
        replay.egress_spool_dir.as_deref(),
        Some("/tmp/hol-guard-egress-test")
    );
    // The resident must not read the first round's id on the second round.
    assert_ne!(transport.seen[0].request_id, replay.request_id);
}

#[test]
fn every_round_after_the_first_reads_one_pinned_clock() {
    let mut transport = ScriptedTransport::new(vec![
        Answer::egress(&["https://registry.npmjs.org/left-pad"]),
        Answer::egress(&["https://registry.npmjs.org/right-pad"]),
        Answer::verdict(),
    ]);
    let mut egress = StubEgress::new();
    evaluate_rounds(request(), &mut transport, &mut egress, None).expect("settles");
    let second = transport.seen[1].now.clone().expect("pinned now");
    assert_eq!(transport.seen[2].now.as_deref(), Some(second.as_str()));
    assert!(second.ends_with('Z'), "{second}");
    assert!(!second.contains('+'), "{second}");
}

#[test]
fn a_callers_own_timestamp_is_the_pinned_one() {
    let mut given = request();
    given.now = Some("2026-01-02T03:04:05Z".to_owned());
    let mut transport = ScriptedTransport::new(vec![
        Answer::egress(&["https://registry.npmjs.org/left-pad"]),
        Answer::verdict(),
    ]);
    let mut egress = StubEgress::new();
    evaluate_rounds(given, &mut transport, &mut egress, None).expect("settles");
    assert_eq!(
        transport.seen[1].now.as_deref(),
        Some("2026-01-02T03:04:05Z")
    );
}

#[test]
fn an_unreadable_egress_request_is_a_resident_failure() {
    let mut transport = ScriptedTransport::new(vec![Answer::ok(
        EGRESS_REQUIRED_CODE,
        Some(json!({"needs": "not-a-list"})),
    )]);
    let mut egress = StubEgress::new();
    let error = evaluate_rounds(request(), &mut transport, &mut egress, None).expect_err("invalid");
    assert_eq!(
        error,
        RoundsError::ResidentFailure("egress_request_invalid")
    );
    assert!(egress.asked.is_empty());
}

#[test]
fn an_egress_the_caller_refuses_stops_the_evaluation() {
    let mut transport = ScriptedTransport::new(vec![
        Answer::egress(&["https://registry.npmjs.org/left-pad"]),
        Answer::verdict(),
    ]);
    let mut egress = StubEgress::new();
    egress.fulfil_error = Some("egress_needs_too_many");
    let error = evaluate_rounds(request(), &mut transport, &mut egress, None).expect_err("refused");
    assert_eq!(
        error,
        RoundsError::ResidentFailure("egress_needs_too_many"),
        "a caller that cannot perform the exchange never replays a round"
    );
    assert_eq!(transport.seen.len(), 1);
}

#[test]
fn the_saved_policy_probe_is_answered_once() {
    let mut transport = ScriptedTransport::new(vec![
        Answer::probe_required(),
        Answer::probe_required(),
        Answer::verdict(),
    ]);
    let mut egress = StubEgress::new();
    let mut probe = StubProbe::new(Some(json!({"decision": "block"})));
    let error = evaluate_rounds(request(), &mut transport, &mut egress, Some(&mut probe))
        .expect_err("a second probe question is not a verdict");
    assert_eq!(error, RoundsError::Unavailable("not_a_verdict"));
    assert_eq!(probe.asked.len(), 1, "the caller answers the probe once");
    assert_eq!(transport.seen.len(), 2);
    assert_eq!(
        transport.seen[1].saved_policy_probe,
        Some(SavedPolicyProbeV1 {
            decision: Some(json!({"decision": "block"})),
        })
    );
}

#[test]
fn an_unmatched_saved_policy_row_is_still_answered() {
    let mut transport = ScriptedTransport::new(vec![Answer::probe_required(), Answer::verdict()]);
    let mut egress = StubEgress::new();
    let mut probe = StubProbe::new(None);
    evaluate_rounds(request(), &mut transport, &mut egress, Some(&mut probe)).expect("settles");
    assert_eq!(
        transport.seen[1].saved_policy_probe,
        Some(SavedPolicyProbeV1 { decision: None }),
        "the resident is told no row matched rather than left waiting"
    );
}

#[test]
fn a_probe_question_no_caller_can_answer_is_not_a_verdict() {
    let mut transport = ScriptedTransport::new(vec![Answer::probe_required()]);
    let mut egress = StubEgress::new();
    let error =
        evaluate_rounds(request(), &mut transport, &mut egress, None).expect_err("no probe");
    assert_eq!(error, RoundsError::Unavailable("not_a_verdict"));
    assert_eq!(transport.seen.len(), 1);
}

#[test]
fn an_evaluation_that_never_settles_fails_on_the_round_bound() {
    let mut transport = ScriptedTransport::repeating(vec![Answer::egress(&[
        "https://registry.npmjs.org/left-pad",
    ])]);
    let mut egress = StubEgress::new();
    let error =
        evaluate_rounds(request(), &mut transport, &mut egress, None).expect_err("never settles");
    assert_eq!(error, RoundsError::ResidentFailure("did_not_settle"));
    assert_eq!(
        transport.seen.len(),
        MAX_ROUNDS + 1,
        "the first request plus MAX_ROUNDS follow-ups, and no more"
    );
}

#[test]
fn an_error_answer_is_not_a_verdict() {
    let mut transport = ScriptedTransport::new(vec![Answer {
        status: "error",
        code: "native_supply_chain_eval_failed",
        payload: None,
        request_id: None,
        request_sha256: None,
        schema: None,
        silent: false,
    }]);
    let mut egress = StubEgress::new();
    let error = evaluate_rounds(request(), &mut transport, &mut egress, None).expect_err("error");
    assert_eq!(error, RoundsError::Unavailable("not_a_verdict"));
}

#[test]
fn a_partial_payload_is_not_an_evaluation() {
    let mut incomplete = complete_payload();
    incomplete
        .as_object_mut()
        .expect("object")
        .remove("user_copy");
    let mut transport = ScriptedTransport::new(vec![Answer::ok("ok", Some(incomplete))]);
    let mut egress = StubEgress::new();
    let error = evaluate_rounds(request(), &mut transport, &mut egress, None).expect_err("partial");
    assert_eq!(error, RoundsError::ResidentFailure("payload_invalid"));
}

#[test]
fn a_payload_deciding_something_the_harness_cannot_apply_is_rejected() {
    let mut payload = complete_payload();
    payload["decision"] = json!("escalate");
    let mut transport = ScriptedTransport::new(vec![Answer::ok("ok", Some(payload))]);
    let mut egress = StubEgress::new();
    let error =
        evaluate_rounds(request(), &mut transport, &mut egress, None).expect_err("decision");
    assert_eq!(error, RoundsError::ResidentFailure("payload_invalid"));
}

#[test]
fn retained_archives_are_claimed_against_the_answers_descriptors() {
    let mut payload = complete_payload();
    payload["external_archive_inspection"] = json!([{"sha256": "sha256:abc"}]);
    let mut transport = ScriptedTransport::new(vec![Answer::ok("ok", Some(payload))]);
    let mut egress = StubEgress::new();
    let mut retaining = request();
    retaining.retain_external_archive_blob = true;
    evaluate_rounds(retaining, &mut transport, &mut egress, None).expect("settles");
    assert_eq!(
        egress.claimed,
        vec![Some(json!([{"sha256": "sha256:abc"}]))]
    );
}

#[test]
fn an_answer_naming_a_blob_the_caller_does_not_hold_is_a_resident_failure() {
    let mut payload = complete_payload();
    payload["external_archive_inspection"] = json!([{"sha256": "sha256:abc"}]);
    let mut transport = ScriptedTransport::new(vec![Answer::ok("ok", Some(payload))]);
    let mut egress = StubEgress::new();
    egress.claim_error = Some("unheld_archive");
    let mut retaining = request();
    retaining.retain_external_archive_blob = true;
    let error =
        evaluate_rounds(retaining, &mut transport, &mut egress, None).expect_err("unheld blob");
    assert_eq!(
        error,
        RoundsError::ResidentFailure("archive_binding_invalid")
    );
}

#[test]
fn a_caller_that_retains_nothing_claims_nothing() {
    let mut payload = complete_payload();
    payload["external_archive_inspection"] = json!([{"sha256": "sha256:abc"}]);
    let mut transport = ScriptedTransport::new(vec![Answer::ok("ok", Some(payload))]);
    let mut egress = StubEgress::new();
    egress.claim_error = Some("unheld_archive");
    evaluate_rounds(request(), &mut transport, &mut egress, None).expect("settles");
    assert!(egress.claimed.is_empty());
}

#[test]
fn a_failed_evaluation_releases_what_it_retained() {
    let mut incomplete = complete_payload();
    incomplete
        .as_object_mut()
        .expect("object")
        .remove("user_copy");
    let mut transport = ScriptedTransport::new(vec![Answer::ok("ok", Some(incomplete))]);
    let mut egress = StubEgress::new();
    let mut retaining = request();
    retaining.retain_external_archive_blob = true;
    let error = evaluate_rounds(retaining, &mut transport, &mut egress, None).expect_err("partial");
    assert_eq!(error, RoundsError::ResidentFailure("payload_invalid"));
    // Claiming nothing is how the caller discards a verified blob no answer
    // ever bound, the way Python's exit stack discards it on a failed exit.
    assert_eq!(egress.claimed, vec![None]);
}

#[test]
fn each_round_carries_its_own_request_id() {
    let mut transport = ScriptedTransport::new(vec![
        Answer::egress(&["https://registry.npmjs.org/left-pad"]),
        Answer::egress(&["https://registry.npmjs.org/right-pad"]),
        Answer::verdict(),
    ]);
    let mut egress = StubEgress::new();
    evaluate_rounds(request(), &mut transport, &mut egress, None).expect("settles");
    let ids: Vec<&str> = transport
        .seen
        .iter()
        .map(|request| request.request_id.as_str())
        .collect();
    assert_eq!(ids.len(), 3);
    for id in &ids {
        assert!(id.starts_with("package-authority-"), "{id}");
        assert_eq!(id.split('-').count(), 4, "{id}");
    }
    let mut unique = ids.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), ids.len(), "{ids:?}");
}
