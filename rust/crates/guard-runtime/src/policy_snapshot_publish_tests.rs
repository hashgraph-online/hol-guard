use super::*;
use crate::policy_store::tests::{fixture_directory, test_root};
use crate::policy_store::{VERIFIER_KEY_BYTES, VERIFIER_KEY_FILE_NAME};
use std::cell::RefCell;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

const KEY: [u8; VERIFIER_KEY_BYTES] = [7; VERIFIER_KEY_BYTES];

fn home(label: &str) -> PathBuf {
    let root = test_root(&format!("publish-{label}"));
    let runtime = runtime_directory(&root);
    fixture_directory(&runtime);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    root
}

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

fn request(root: &Path) -> Value {
    let now = now_ms();
    json!({
        "schema": "guard-native-policy-materialize.v1", "version": 1, "verifier_key": KEY.to_vec(),
        "guard_home": root, "lock_wait_ms": 0,
        "runtime_identity": "a".repeat(64), "rule_digest": "b".repeat(64),
        "mode": "enforce", "issued_at_ms": now, "expires_at_ms": now + 60_000,
        "scope_contract": {"schema":"guard-native-scope.v1","kind":"guard-home",
            "scope_digest":"c".repeat(64),"workspace_binding":"request-source"},
        "effective_policy": {
            "protection_posture":"protected","security_level":"balanced","default_action":"warn",
            "unknown_publisher_action":"review","changed_hash_action":"require-reapproval",
            "new_network_domain_action":"warn","subprocess_action":"warn","risk_actions":{},
            "harness_risk_actions":{},"harness_actions":{},"publisher_actions":{},"artifact_actions":{},
            "sandbox_analysis":"off","receipt_redaction_level":"full"
        }
    })
}

fn business(mut value: Value) -> Value {
    value["business_policy"] = json!({"schema":"guard.native-business-policy.v1","version":1,
        "defaultAction":"allow","rules":[{"id":"mail.external","action":"block",
        "match":{"schema":"guard.business-policy-match.v1","version":1,
            "services":["google_gmail"],"operations":["mail_send"]}}]});
    value
}

fn settings(direct_lane: Option<Value>) -> Value {
    json!({
        "schema": SCHEMA, "version": 1, "build_budget_ms": 5_000,
        "publish_timeout_ms": 2_000, "startup_timeout_ms": 9_000, "direct_lane": direct_lane,
    })
}

/// Plays the publisher's side: each push the command writes is answered by
/// `resident`, which sees the decoded envelope.
struct Relay<F> {
    written: Rc<RefCell<Vec<u8>>>,
    read_upto: usize,
    pending: Vec<u8>,
    offset: usize,
    resident: F,
    pushes: Rc<RefCell<Vec<Value>>>,
}

impl<F: FnMut(&Value) -> Value> Read for Relay<F> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let available = self.fill_buf()?;
        let count = available.len().min(buf.len());
        buf[..count].copy_from_slice(&available[..count]);
        self.consume(count);
        Ok(count)
    }
}

impl<F: FnMut(&Value) -> Value> BufRead for Relay<F> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        if self.offset >= self.pending.len() {
            let written = self.written.borrow();
            let Some(end) = written[self.read_upto..]
                .iter()
                .position(|byte| *byte == b'\n')
            else {
                return Ok(&[]);
            };
            let line: Value =
                serde_json::from_slice(&written[self.read_upto..self.read_upto + end]).unwrap();
            drop(written);
            self.read_upto += end + 1;
            let envelope: Value = serde_json::from_str(line["push"].as_str().unwrap()).unwrap();
            let reply = (self.resident)(&envelope);
            self.pushes.borrow_mut().push(envelope);
            self.pending = serde_json::to_vec(&reply).unwrap();
            self.pending.push(b'\n');
            self.offset = 0;
        }
        Ok(&self.pending[self.offset..])
    }

    fn consume(&mut self, amount: usize) {
        self.offset += amount;
    }
}

struct Sink(Rc<RefCell<Vec<u8>>>);

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Run the command against a scripted resident and return its last answer
/// and every envelope it pushed.
fn run_with(
    settings: &Value,
    request: &Value,
    resident: impl FnMut(&Value) -> Value,
) -> (Value, Vec<Value>) {
    let written = Rc::new(RefCell::new(Vec::new()));
    let pushes = Rc::new(RefCell::new(Vec::new()));
    let mut head = serde_json::to_vec(settings).unwrap();
    head.push(b'\n');
    head.extend(serde_json::to_vec(request).unwrap());
    head.push(b'\n');
    let relay = Relay {
        written: Rc::clone(&written),
        read_upto: 0,
        pending: head,
        offset: 0,
        resident,
        pushes: Rc::clone(&pushes),
    };
    run(relay, Sink(Rc::clone(&written))).unwrap();
    let written = written.borrow();
    let last = written[..written.len() - 1]
        .rsplit(|byte| *byte == b'\n')
        .next()
        .unwrap();
    let pushes = pushes.borrow().clone();
    (serde_json::from_slice(last).unwrap(), pushes)
}

fn ack(envelope: &Value, status: &str, generation: Option<u64>) -> Value {
    let snapshot = &envelope["request"]["snapshot"];
    let ack = json!({
        "status": status,
        "generation": generation.unwrap_or_else(|| snapshot["generation"].as_u64().unwrap()),
        "policy_digest": snapshot["policy_digest"],
        "idempotent": false,
        "resident_generation": 3,
    });
    json!({"output": ack.to_string(), "failure": null})
}

#[test]
fn an_accepted_push_returns_the_snapshot_and_resident_generation() {
    let root = home("accepted");
    let lane = json!({"schema": "lane"});
    let (answer, pushes) = run_with(&settings(Some(lane.clone())), &request(&root), |envelope| {
        ack(envelope, "accepted", None)
    });
    assert_eq!(answer["published"]["resident_generation"], 3);
    assert_eq!(pushes.len(), 1);
    assert_eq!(pushes[0]["operation"], "policy_snapshot_push");
    assert_eq!(pushes[0]["deadline_budget_ms"], 2_000);
    assert_eq!(pushes[0]["request"]["direct_lane"], lane);
    assert_eq!(
        answer["published"]["snapshot"],
        pushes[0]["request"]["snapshot"]
    );
}

#[test]
fn a_renewal_request_republishes_past_the_resident_floor() {
    let root = home("renewal");
    let mut floor = None;
    let (answer, pushes) = run_with(&settings(None), &request(&root), |envelope| {
        let generation = envelope["request"]["snapshot"]["generation"]
            .as_u64()
            .unwrap();
        match floor {
            None => {
                floor = Some(generation + 4);
                ack(envelope, POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION, floor)
            }
            Some(_) => ack(envelope, "accepted", None),
        }
    });
    assert_eq!(pushes.len(), 2);
    assert!(pushes[1]["request"]["snapshot"]["generation"].as_u64() > floor);
    // A renewal may restart the resident, so it pushes with the startup window.
    assert_eq!(pushes[1]["deadline_budget_ms"], 9_000);
    assert_eq!(answer["published"]["resident_generation"], 3);
}

#[test]
fn a_second_renewal_request_is_a_mismatch() {
    let root = home("second-renewal");
    let (answer, pushes) = run_with(&settings(None), &request(&root), |envelope| {
        let generation = envelope["request"]["snapshot"]["generation"]
            .as_u64()
            .unwrap();
        ack(
            envelope,
            POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION,
            Some(generation + 1),
        )
    });
    assert_eq!(pushes.len(), 2);
    assert_eq!(answer, json!({"error": ACK_MISMATCH}));
}

#[test]
fn a_renewal_floor_below_the_candidate_is_a_mismatch() {
    let root = home("low-floor");
    let mut value = request(&root);
    value["renew_after_generation"] = json!(5);
    let (answer, pushes) = run_with(&settings(None), &value, |envelope| {
        let generation = envelope["request"]["snapshot"]["generation"]
            .as_u64()
            .unwrap();
        ack(
            envelope,
            POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION,
            Some(generation - 1),
        )
    });
    assert_eq!(pushes.len(), 1);
    assert_eq!(answer, json!({"error": ACK_MISMATCH}));
}

#[test]
fn an_ack_for_another_generation_is_a_mismatch() {
    let root = home("other-generation");
    let (answer, _) = run_with(&settings(None), &request(&root), |envelope| {
        let generation = envelope["request"]["snapshot"]["generation"]
            .as_u64()
            .unwrap();
        ack(envelope, "accepted", Some(generation + 1))
    });
    assert_eq!(answer, json!({"error": ACK_MISMATCH}));
}

#[test]
fn a_resident_error_frame_is_the_answer() {
    let root = home("error-frame");
    let (answer, _) = run_with(
        &settings(None),
        &request(&root),
        |_| json!({"output": r#"{"error":"native_policy_snapshot_stale","retryable":false}"#}),
    );
    assert_eq!(answer, json!({"error": "native_policy_snapshot_stale"}));
}

#[test]
fn a_missing_resident_answer_reports_the_relay_failure() {
    let root = home("relay-failure");
    let (answer, _) = run_with(
        &settings(None),
        &request(&root),
        |_| json!({"output": null, "failure": "native_client_pool_exhausted"}),
    );
    assert_eq!(answer, json!({"error": "native_client_pool_exhausted"}));
    let root = home("relay-garbage");
    let (answer, _) = run_with(
        &settings(None),
        &request(&root),
        |_| json!({"output": null, "failure": "Not A Code"}),
    );
    assert_eq!(answer, json!({"error": ACK_INVALID}));
}

#[test]
fn an_ack_with_extra_fields_is_invalid() {
    let root = home("extra-field");
    let (answer, _) = run_with(&settings(None), &request(&root), |envelope| {
        let mut reply = ack(envelope, "accepted", None);
        let mut value: Value = serde_json::from_str(reply["output"].as_str().unwrap()).unwrap();
        value["extra"] = json!(1);
        reply["output"] = json!(value.to_string());
        reply
    });
    assert_eq!(answer, json!({"error": ACK_INVALID}));
}

#[test]
fn an_oversized_direct_lane_is_dropped_from_the_push() {
    let root = home("oversized-lane");
    let lane = json!({"padding": "x".repeat(POLICY_SNAPSHOT_MAX_BYTES - 1024)});
    let (answer, pushes) = run_with(&settings(Some(lane)), &request(&root), |envelope| {
        ack(envelope, "accepted", None)
    });
    assert!(pushes[0]["request"].get("direct_lane").is_none());
    assert_eq!(answer["published"]["resident_generation"], 3);
}

#[test]
fn a_business_publication_provisions_the_key_after_materializing() {
    let root = home("business");
    let key_path = runtime_directory(&root).join(VERIFIER_KEY_FILE_NAME);
    let (answer, _) = run_with(&settings(None), &business(request(&root)), |envelope| {
        // The key is provisioned once the content is accepted, before the push.
        assert!(key_path.exists());
        ack(envelope, "accepted", None)
    });
    assert_eq!(answer["published"]["resident_generation"], 3);
    assert_eq!(std::fs::read(&key_path).unwrap(), KEY);
}

#[test]
fn an_unknown_settings_schema_is_refused() {
    let root = home("schema");
    let mut value = settings(None);
    value["schema"] = json!("other");
    let mut input = serde_json::to_vec(&value).unwrap();
    input.push(b'\n');
    input.extend(serde_json::to_vec(&request(&root)).unwrap());
    assert_eq!(run(input.as_slice(), Vec::new()), Err(ERROR.to_owned()));
}
