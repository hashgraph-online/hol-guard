//! What one round on the lane carries, and what each kind of non-answer leaves
//! the caller with: no verdict, and the runtime health that says why.
//!
//! The lane itself is scripted, so these exercise the envelope, the reads of
//! the answer and the recording - not a resident.

use super::*;

use guard_contracts::PACKAGE_AUTHORITY_REQUEST_SCHEMA;
use serde_json::json;

use crate::native_runtime_resilience::native_runtime_health_snapshot;

/// A lane that answers from a script and keeps what it was asked.
struct ScriptedLane {
    answers: Vec<Option<Vec<u8>>>,
    sent: Vec<Vec<u8>>,
    digest: Option<String>,
    /// A round with no answer leaves the lane holding no runtime, as a real
    /// teardown with no resident to rediscover does.
    forgets: bool,
}

impl ScriptedLane {
    fn new(digest: Option<&str>, answers: Vec<Option<Vec<u8>>>) -> Self {
        Self {
            answers,
            sent: Vec::new(),
            digest: digest.map(str::to_owned),
            forgets: false,
        }
    }

    fn forgetting(digest: &str, answers: Vec<Option<Vec<u8>>>) -> Self {
        Self {
            forgets: true,
            ..Self::new(Some(digest), answers)
        }
    }
}

impl ResidentLane for ScriptedLane {
    fn exchange_until(&mut self, payload: &[u8], deadline: Instant) -> Option<Vec<u8>> {
        assert!(
            deadline > Instant::now(),
            "a round is sent with the budget still open"
        );
        self.sent.push(payload.to_vec());
        let answer = if self.answers.is_empty() {
            None
        } else {
            self.answers.remove(0)
        };
        if answer.is_none() && self.forgets {
            self.digest = None;
        }
        answer
    }

    fn runtime_sha256(&self) -> Option<String> {
        self.digest.clone()
    }
}

fn request() -> SupplyChainEvalRequestV1 {
    SupplyChainEvalRequestV1 {
        schema: PACKAGE_AUTHORITY_REQUEST_SCHEMA.to_owned(),
        request_id: "eval-1".to_owned(),
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

fn answer(body: Value) -> Option<Vec<u8>> {
    Some(serde_json::to_vec(&body).expect("answer"))
}

fn result_body() -> Value {
    json!({
        "schema": PACKAGE_AUTHORITY_RESULT_SCHEMA,
        "request_id": "eval-1",
        "request_sha256": "sha256:abc",
        "status": "ok",
        "code": "ok",
        "payload": {"decision": "allow"},
    })
}

/// Health is kept per runtime and home, so every test reads its own.
fn health(
    digest: &str,
    home: &str,
) -> crate::native_runtime_resilience::NativeRuntimeHealthSnapshot {
    native_runtime_health_snapshot(digest, Path::new(home))
}

#[test]
fn one_round_travels_as_the_envelope_the_resident_reads() {
    let home = "/tmp/guard-eval-envelope";
    let mut lane = ScriptedLane::new(Some("digest-envelope"), vec![answer(result_body())]);
    let mut transport = ResidentEvalTransport::new(&mut lane, Path::new(home));

    let result = transport.evaluate(&request()).expect("result");

    assert_eq!(result.status, "ok");
    assert_eq!(result.payload, Some(json!({"decision": "allow"})));
    let sent: Value = serde_json::from_slice(&lane.sent[0]).expect("envelope");
    assert_eq!(sent["operation"], json!(OPERATION));
    assert_eq!(sent["request"]["request_id"], json!("eval-1"));
    assert_eq!(sent["request"]["guard_home"], json!("/tmp/guard-home"));
    // The resident answers inside the evaluation's own budget, not a hook's.
    assert_eq!(sent["deadline_budget_ms"], json!(25_000));
    let state = health("digest-envelope", home);
    assert_eq!(state.state, "healthy");
    assert_eq!(state.resident_failures, 0);
}

#[test]
fn a_request_over_the_byte_cap_never_reaches_the_lane() {
    let home = "/tmp/guard-eval-oversized";
    let mut over = request();
    over.artifact = json!({"blob": "a".repeat(MAX_REQUEST_BYTES)});
    let mut lane = ScriptedLane::new(Some("digest-oversized"), vec![answer(result_body())]);
    let mut transport = ResidentEvalTransport::new(&mut lane, Path::new(home));

    assert!(transport.evaluate(&over).is_none());

    assert!(lane.sent.is_empty(), "nothing is sent past the cap");
    // The caller could not frame its own request; the runtime did nothing wrong.
    let state = health("digest-oversized", home);
    assert_eq!(state.state, "unknown");
    assert_eq!(state.consecutive_failures, 0);
}

#[test]
fn a_lane_with_no_answer_records_a_transport_failure() {
    let home = "/tmp/guard-eval-transport";
    let mut lane = ScriptedLane::new(Some("digest-transport"), vec![None]);
    let mut transport = ResidentEvalTransport::new(&mut lane, Path::new(home));

    assert!(transport.evaluate(&request()).is_none());

    let state = health("digest-transport", home);
    assert_eq!(state.reason, REASON_TRANSPORT);
    assert_eq!(state.resident_failures, 1);
}

#[test]
fn an_answer_that_is_not_json_records_a_malformed_failure() {
    let home = "/tmp/guard-eval-malformed";
    let mut lane = ScriptedLane::new(Some("digest-malformed"), vec![Some(b"{not json".to_vec())]);
    let mut transport = ResidentEvalTransport::new(&mut lane, Path::new(home));

    assert!(transport.evaluate(&request()).is_none());

    let state = health("digest-malformed", home);
    assert_eq!(state.reason, REASON_MALFORMED);
    assert_eq!(state.resident_failures, 1);
}

#[test]
fn an_answer_of_another_schema_records_a_schema_failure() {
    let home = "/tmp/guard-eval-schema";
    let mut body = result_body();
    body["schema"] = json!("guard-package-authority-result.v2");
    let mut lane = ScriptedLane::new(Some("digest-schema"), vec![answer(body)]);
    let mut transport = ResidentEvalTransport::new(&mut lane, Path::new(home));

    assert!(transport.evaluate(&request()).is_none());

    let state = health("digest-schema", home);
    assert_eq!(state.reason, REASON_SCHEMA);
    assert_eq!(state.resident_failures, 1);
}

#[test]
fn an_answer_that_is_not_an_object_is_no_verdict() {
    let home = "/tmp/guard-eval-scalar";
    let mut lane = ScriptedLane::new(Some("digest-scalar"), vec![answer(json!("ok"))]);
    let mut transport = ResidentEvalTransport::new(&mut lane, Path::new(home));

    assert!(transport.evaluate(&request()).is_none());

    let state = health("digest-scalar", home);
    assert_eq!(state.consecutive_failures, 0);
}

#[test]
fn a_resident_that_reports_no_result_is_not_a_runtime_failure() {
    let home = "/tmp/guard-eval-refused";
    let mut body = result_body();
    body["status"] = json!("error");
    body["code"] = json!("native_supply_chain_eval_failed");
    let mut lane = ScriptedLane::new(Some("digest-refused"), vec![answer(body)]);
    let mut transport = ResidentEvalTransport::new(&mut lane, Path::new(home));

    // No verdict comes back, and the caller may not substitute one; the
    // resident answered, so nothing is recorded against it.
    assert!(transport.evaluate(&request()).is_none());

    let state = health("digest-refused", home);
    assert_eq!(state.consecutive_failures, 0);
    assert_eq!(state.resident_failures, 0);
}

#[test]
fn an_answer_carrying_more_than_a_result_is_recorded_as_unbound() {
    let home = "/tmp/guard-eval-unbound";
    let mut body = result_body();
    body["decision"] = json!("allow");
    let mut lane = ScriptedLane::new(Some("digest-unbound"), vec![answer(body)]);
    let mut transport = ResidentEvalTransport::new(&mut lane, Path::new(home));

    assert!(transport.evaluate(&request()).is_none());

    // Recorded once, by the transport, so the round loop does not count it
    // again as a resident failure of its own.
    let state = health("digest-unbound", home);
    assert_eq!(state.reason, REASON_UNBOUND);
    assert_eq!(state.resident_failures, 1);
}

/// A resident that answers nothing but unbound results is a resident the
/// circuit has to be able to open on, so the round is recorded once the answer
/// has been read rather than when it arrives.
#[test]
fn a_run_of_unbound_answers_reaches_the_circuit() {
    let home = "/tmp/guard-eval-unbound-run";
    let mut body = result_body();
    body["decision"] = json!("allow");
    let answers = vec![answer(body.clone()), answer(body.clone()), answer(body)];
    let mut lane = ScriptedLane::new(Some("digest-unbound-run"), answers);
    let mut transport = ResidentEvalTransport::new(&mut lane, Path::new(home));

    for _ in 0..3 {
        assert!(transport.evaluate(&request()).is_none());
    }

    let state = health("digest-unbound-run", home);
    assert_eq!(state.resident_failures, 3);
    assert_eq!(state.consecutive_failures, 3);
    assert_eq!(state.state, "circuit_open");
}

#[test]
fn a_round_that_tore_the_lane_down_is_recorded_against_the_runtime_it_went_to() {
    let home = "/tmp/guard-eval-torn";
    let mut lane = ScriptedLane::forgetting("digest-torn", vec![None]);
    let mut transport = ResidentEvalTransport::new(&mut lane, Path::new(home));

    assert!(transport.evaluate(&request()).is_none());

    assert!(lane.runtime_sha256().is_none(), "the lane holds none now");
    let state = health("digest-torn", home);
    assert_eq!(state.reason, REASON_TRANSPORT);
    assert_eq!(state.resident_failures, 1);
}

#[test]
fn a_lane_that_reached_no_resident_has_no_runtime_to_record() {
    let home = "/tmp/guard-eval-undiscovered";
    let mut lane = ScriptedLane::new(None, vec![None]);
    let mut transport = ResidentEvalTransport::new(&mut lane, Path::new(home));

    assert!(transport.evaluate(&request()).is_none());

    assert_eq!(lane.sent.len(), 1, "the lane was asked");
    let state = health("digest-undiscovered", home);
    assert_eq!(state.consecutive_failures, 0);
}
