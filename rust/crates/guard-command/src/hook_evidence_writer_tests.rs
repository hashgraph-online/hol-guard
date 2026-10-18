//! Persistence parity for `RuntimeHookEvidenceWriter`.
//!
//! A Pre event carries the verdict Rust already reached, so the writer builds
//! the evidence and the store only stores it. A post event carries no verdict,
//! so it may only promote a stored pre-hook row or be written as explicitly
//! unpaired. These cover both branches of the drain loop and the pairing rules
//! in `cli/commands_support_command_activity.py:208-246`.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};

use serde_json::{json, Map, Value};

use crate::hook_evidence_writer::{
    ComposioActionSchema, ComposioWorkflowProposal, CorrelationApi, CorrelationHandle,
    EvidenceJournalApi, EvidenceRecord, EvidenceStoreApi, EvidenceWriterDeps,
    InstallationCorrelationKey, ObservedMcpTool, ReceiptValidationApi, RuntimeHookEvidenceWriter,
    SqliteTimeoutApi,
};

/// The correlation digest every fixture starts from, before a prevented
/// attempt rewrites it.
const BASE_DIGEST: &str = "9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f";

/// What the store was asked to do, in call order.
#[derive(Debug, Clone, PartialEq)]
enum StoreCall {
    PreReplayProbe(Map<String, Value>),
    RecordCommandActivity {
        evidence: Map<String, Value>,
        invocation_preview: Option<String>,
    },
    ActivityLookup(String),
    Transition(Map<String, Value>),
    ObservationConflict(String),
}

#[derive(Default)]
struct StubStoreState {
    calls: Vec<StoreCall>,
    pre_replay: bool,
    /// The row the lookup finds, if a pre-hook event already stored one.
    previous: Option<Map<String, Value>>,
}

struct StubStore {
    guard_home: PathBuf,
    state: Mutex<StubStoreState>,
    receipt_behaviour: ReceiptBehaviour,
}

/// What the stubbed store does when the writer hands it a receipt.
enum ReceiptBehaviour {
    /// Write it and report a new row, the ordinary path.
    Accept,
    /// Park the worker thread here until the test releases the gate, so a
    /// test can read the queue while a store write is still outstanding.
    Park(Arc<Gate>),
    /// Fail every write, the way a locked SQLite file does.
    Fail,
}

impl StubStore {
    fn new(guard_home: PathBuf, pre_replay: bool) -> Arc<Self> {
        Arc::new(Self {
            guard_home,
            state: Mutex::new(StubStoreState {
                calls: Vec::new(),
                pre_replay,
                previous: None,
            }),
            receipt_behaviour: ReceiptBehaviour::Accept,
        })
    }

    /// A store whose receipt write only returns once the test releases `gate`.
    fn gated(guard_home: PathBuf, gate: Arc<Gate>) -> Arc<Self> {
        Self::with_receipts(guard_home, ReceiptBehaviour::Park(gate))
    }

    /// A store whose receipt write always fails.
    fn failing_receipts(guard_home: PathBuf) -> Arc<Self> {
        Self::with_receipts(guard_home, ReceiptBehaviour::Fail)
    }

    fn with_receipts(guard_home: PathBuf, receipt_behaviour: ReceiptBehaviour) -> Arc<Self> {
        Arc::new(Self {
            guard_home,
            state: Mutex::new(StubStoreState {
                calls: Vec::new(),
                pre_replay: false,
                previous: None,
            }),
            receipt_behaviour,
        })
    }

    fn calls(&self) -> Vec<StoreCall> {
        self.state.lock().expect("state").calls.clone()
    }

    fn push(&self, call: StoreCall) {
        self.state.lock().expect("state").calls.push(call);
    }

    fn set_previous(&self, previous: Map<String, Value>) {
        self.state.lock().expect("state").previous = Some(previous);
    }
}

impl EvidenceStoreApi for StubStore {
    fn guard_home(&self) -> PathBuf {
        self.guard_home.clone()
    }

    fn is_exact_command_activity_pre_replay(
        &self,
        evidence: &Map<String, Value>,
    ) -> Result<bool, io::Error> {
        self.push(StoreCall::PreReplayProbe(evidence.clone()));
        Ok(self.state.lock().expect("state").pre_replay)
    }

    fn record_command_activity(
        &self,
        evidence: &Map<String, Value>,
        invocation_preview: Option<&str>,
    ) -> Result<bool, io::Error> {
        self.push(StoreCall::RecordCommandActivity {
            evidence: evidence.clone(),
            invocation_preview: invocation_preview.map(str::to_owned),
        });
        Ok(true)
    }

    fn record_composio_discovery(
        &self,
        _source: &ObservedMcpTool,
        _actions: &[ComposioActionSchema],
        _seen_at: &str,
        _proposals: &[ComposioWorkflowProposal],
    ) -> Result<(), io::Error> {
        Ok(())
    }

    fn record_native_decision_receipt(
        &self,
        _receipt: &Map<String, Value>,
    ) -> Result<bool, io::Error> {
        match &self.receipt_behaviour {
            ReceiptBehaviour::Accept => Ok(true),
            ReceiptBehaviour::Park(gate) => {
                gate.enter();
                Ok(true)
            }
            ReceiptBehaviour::Fail => Err(io::Error::other("database is locked")),
        }
    }

    fn command_activity_by_request_correlation(
        &self,
        correlation: &CorrelationHandle,
    ) -> Result<Option<Map<String, Value>>, io::Error> {
        self.push(StoreCall::ActivityLookup(correlation.digest.clone()));
        Ok(self.state.lock().expect("state").previous.clone())
    }

    fn transition_command_activity(&self, current: &Map<String, Value>) -> Result<bool, io::Error> {
        self.push(StoreCall::Transition(current.clone()));
        Ok(true)
    }

    fn record_command_activity_observation_conflict(
        &self,
        occurred_at: &str,
    ) -> Result<(), io::Error> {
        self.push(StoreCall::ObservationConflict(occurred_at.to_owned()));
        Ok(())
    }
}

/// Echoes the arguments it was handed so a test can read the evidence the
/// writer decided on, rather than the shape the lifecycle module would build.
struct StubCorrelation;

impl CorrelationApi for StubCorrelation {
    fn load_or_create_installation_correlation_key(
        &self,
    ) -> Result<Option<InstallationCorrelationKey>, io::Error> {
        Ok(Some(InstallationCorrelationKey::new("key-1", &[7u8; 32])?))
    }

    fn derive_proven_request_correlation(
        &self,
        harness: &str,
        _event: &str,
        _payload: &Map<String, Value>,
        key: &InstallationCorrelationKey,
    ) -> Result<Option<CorrelationHandle>, io::Error> {
        Ok(Some(CorrelationHandle {
            kind: "command_execution".to_owned(),
            harness: harness.to_owned(),
            key_id: key.key_id.clone(),
            digest: BASE_DIGEST.to_owned(),
        }))
    }

    fn build_invocation_preview_from_payload(
        &self,
        _payload: &Map<String, Value>,
    ) -> Result<Option<String>, io::Error> {
        Ok(Some("rm -rf …".to_owned()))
    }

    fn build_policy_only_pre_hook_evidence(
        &self,
        activity_id: &str,
        occurred_at: &str,
        harness: &str,
        policy_action: &str,
        request_correlation: Option<&CorrelationHandle>,
        receipt_id: Option<&str>,
        prompted: bool,
        approval_reuse_status: &str,
    ) -> Result<Map<String, Value>, io::Error> {
        let Value::Object(evidence) = json!({
            "activity_id": activity_id,
            "occurred_at": occurred_at,
            "harness": harness,
            "policy_action": policy_action,
            "correlation_digest": request_correlation.map(|handle| handle.digest.clone()),
            "receipt_id": receipt_id,
            "interaction_observed": prompted,
            "approval_reuse_status": approval_reuse_status,
        }) else {
            unreachable!("object literal");
        };
        Ok(evidence)
    }

    fn build_unpaired_post_evidence(
        &self,
        activity_id: &str,
        occurred_at: &str,
        harness: &str,
        succeeded: bool,
    ) -> Result<Map<String, Value>, io::Error> {
        let Value::Object(evidence) = json!({
            "activity_id": activity_id,
            "occurred_at": occurred_at,
            "harness": harness,
            "execution_status": "unpaired_post",
            "succeeded": succeeded,
        }) else {
            unreachable!("object literal");
        };
        Ok(evidence)
    }

    fn build_correlated_post_activity(
        &self,
        previous: &Map<String, Value>,
        request_correlation: &CorrelationHandle,
        succeeded: bool,
    ) -> Result<Map<String, Value>, io::Error> {
        let mut current = previous.clone();
        current.insert(
            "execution_status".to_owned(),
            Value::from(if succeeded {
                "confirmed_success"
            } else {
                "confirmed_failure"
            }),
        );
        current.insert(
            "correlation_digest".to_owned(),
            Value::from(request_correlation.digest.as_str()),
        );
        Ok(current)
    }
}

struct StubReceipts;

impl ReceiptValidationApi for StubReceipts {
    fn validate_native_decision_receipt(
        &self,
        value: &Map<String, Value>,
    ) -> Option<Map<String, Value>> {
        Some(value.clone())
    }
}

struct StubComposio;

impl crate::hook_evidence_writer::ComposioApi for StubComposio {
    fn observed_mcp_tool(&self, _harness: &str, _tool_name: &str) -> Option<ObservedMcpTool> {
        None
    }

    fn composio_discovered_actions(
        &self,
        _tool_name: &str,
        _response: &Value,
    ) -> Option<Vec<ComposioActionSchema>> {
        None
    }

    fn composio_workflow_proposals(
        &self,
        _tool_name: &str,
        _response: &Value,
    ) -> Option<Vec<ComposioWorkflowProposal>> {
        None
    }
}

/// Accepts every append without touching the filesystem; journal durability
/// has its own coverage and would only add I/O here.
struct StubJournal;

impl EvidenceJournalApi for StubJournal {
    fn append_journal(&self, _path: &Path, _record: &EvidenceRecord) -> Result<(), io::Error> {
        Ok(())
    }

    fn rewrite_journal(
        &self,
        _path: &Path,
        _remove_record_id: &str,
        _max_bytes: usize,
    ) -> Result<u64, io::Error> {
        Ok(0)
    }

    fn recover_journal_records(
        &self,
        _path: &Path,
        _max_bytes: usize,
    ) -> Result<(Vec<Map<String, Value>>, u64), io::Error> {
        Ok((Vec::new(), 0))
    }

    fn now_utc_iso(&self) -> String {
        "2026-10-17T00:00:00+00:00".to_owned()
    }
}

struct StubSqliteTimeout;

impl SqliteTimeoutApi for StubSqliteTimeout {
    fn sqlite_timeout_override(
        &self,
        _timeout_ms: std::num::NonZeroU32,
    ) -> Box<dyn std::any::Any + Send> {
        Box::new(())
    }
}

fn deps() -> EvidenceWriterDeps {
    EvidenceWriterDeps {
        correlation: Box::new(StubCorrelation),
        receipts: Arc::new(StubReceipts),
        composio: Arc::new(StubComposio),
        journal: Box::new(StubJournal),
        sqlite_timeout: Box::new(StubSqliteTimeout),
    }
}

fn writer(store: Arc<StubStore>, journal_path: PathBuf) -> RuntimeHookEvidenceWriter {
    RuntimeHookEvidenceWriter::new(store, deps(), 64, 1 << 20, 8, 0.01, Some(journal_path))
        .expect("writer")
}

fn command_payload() -> Map<String, Value> {
    let Value::Object(payload) = json!({
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /tmp/scratch"},
    }) else {
        unreachable!("object literal");
    };
    payload
}

/// A fresh store plus the writer wired to it. The journal seam is stubbed, so
/// the home below is only ever a path, never a directory anything writes to.
fn fixture(pre_replay: bool) -> (Arc<StubStore>, RuntimeHookEvidenceWriter) {
    let home = PathBuf::from("/hol-guard-evidence-writer-tests");
    let store = StubStore::new(home.clone(), pre_replay);
    let writer = writer(Arc::clone(&store), home.join("runtime-hook-evidence.jsonl"));
    (store, writer)
}

#[test]
fn an_allowed_pre_event_records_the_evidence_under_its_own_correlation() {
    let (store, writer) = fixture(false);
    assert!(writer.submit_command_activity(
        "claude-code",
        "PreToolUse",
        &command_payload(),
        true,
        Some("allow"),
        None,
        false,
        "not-applicable",
    ));
    assert!(writer.stop(5.0), "writer drained");

    let calls = store.calls();
    assert!(
        matches!(calls.first(), Some(StoreCall::PreReplayProbe(_))),
        "{calls:?}"
    );
    let Some(StoreCall::RecordCommandActivity {
        evidence,
        invocation_preview,
    }) = calls.get(1)
    else {
        panic!("expected a command-activity write, got {calls:?}");
    };
    assert_eq!(
        evidence.get("correlation_digest").and_then(Value::as_str),
        Some(BASE_DIGEST),
        "an allowed call keeps the correlation its post event will carry"
    );
    assert_eq!(
        evidence.get("policy_action").and_then(Value::as_str),
        Some("allow")
    );
    assert_eq!(invocation_preview.as_deref(), Some("rm -rf …"));
}

#[test]
fn a_prevented_pre_event_rewrites_the_correlation_digest() {
    let (store, writer) = fixture(false);
    assert!(writer.submit_command_activity(
        "claude-code",
        "PreToolUse",
        &command_payload(),
        false,
        Some("block"),
        Some("receipt-1"),
        true,
        "rejected",
    ));
    assert!(writer.stop(5.0), "writer drained");

    let calls = store.calls();
    let Some(StoreCall::RecordCommandActivity { evidence, .. }) = calls.get(1) else {
        panic!("expected a command-activity write, got {calls:?}");
    };
    // The vector is `hashlib.sha256(json.dumps([...]))` over the same tuple:
    // the digest is a join key, so both runtimes must land on these bytes.
    assert_eq!(
        evidence.get("correlation_digest").and_then(Value::as_str),
        Some("578c87b78323942aa15c359c1a55620413cb0b5714b840d4d5d47c7497de44c0"),
        "a prevented attempt cannot pair with a post event, so it gets its own key"
    );
}

#[test]
fn metadata_the_journal_would_refuse_never_reaches_the_queue() {
    let (store, writer) = fixture(false);
    // A prompt and an accepted reuse contradict each other: either the saved
    // approval carried the call or the user was asked, never both.
    assert!(!writer.submit_command_activity(
        "claude-code",
        "PreToolUse",
        &command_payload(),
        true,
        Some("allow"),
        None,
        true,
        "accepted",
    ));
    // A receipt id outside `_SAFE_IDENTIFIER` is refused at submission, not
    // carried until the journal drops it where no caller is left to see.
    assert!(!writer.submit_command_activity(
        "claude-code",
        "PreToolUse",
        &command_payload(),
        true,
        Some("allow"),
        Some("receipt 1/../etc"),
        false,
        "not-applicable",
    ));
    assert!(writer.stop(5.0), "writer drained");

    let calls = store.calls();
    assert!(
        !calls
            .iter()
            .any(|call| matches!(call, StoreCall::RecordCommandActivity { .. })),
        "{calls:?}"
    );
}

#[test]
fn a_review_pre_event_without_a_receipt_still_matches_the_python_digest() {
    let (store, writer) = fixture(false);
    assert!(writer.submit_command_activity(
        "claude-code",
        "PreToolUse",
        &command_payload(),
        false,
        Some("review"),
        None,
        false,
        "not-applicable",
    ));
    assert!(writer.stop(5.0), "writer drained");

    let calls = store.calls();
    let Some(StoreCall::RecordCommandActivity { evidence, .. }) = calls.get(1) else {
        panic!("expected a command-activity write, got {calls:?}");
    };
    assert_eq!(
        evidence.get("correlation_digest").and_then(Value::as_str),
        Some("ef7096bc78457c3d3815d685e38f3bc4d9cb14cd13c9c9e556d70901efa9fcfc"),
        "a missing receipt id hashes as JSON null, not as an empty string"
    );
}

#[test]
fn an_exact_pre_replay_is_probed_and_then_dropped() {
    let (store, writer) = fixture(true);
    assert!(writer.submit_command_activity(
        "claude-code",
        "PreToolUse",
        &command_payload(),
        true,
        Some("allow"),
        None,
        false,
        "not-applicable",
    ));
    assert!(writer.stop(5.0), "writer drained");

    let calls = store.calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert!(matches!(calls[0], StoreCall::PreReplayProbe(_)));
}

/// A stored pre-hook row in the state the lookup would return it.
fn stored_row(execution_status: &str) -> Map<String, Value> {
    let Value::Object(row) = json!({
        "activity_id": "activity:stored",
        "harness": "claude-code",
        "execution_status": execution_status,
    }) else {
        unreachable!("object literal");
    };
    row
}

/// Submit one post event and return the calls it produced.
fn post_event_calls(store: &Arc<StubStore>, writer: RuntimeHookEvidenceWriter) -> Vec<StoreCall> {
    assert!(writer.submit_command_activity(
        "claude-code",
        "PostToolUse",
        &command_payload(),
        true,
        None,
        None,
        false,
        "not-applicable",
    ));
    assert!(writer.stop(5.0), "writer drained");
    store.calls()
}

#[test]
fn an_unpaired_post_event_is_recorded_as_claiming_no_decision() {
    let (store, writer) = fixture(false);

    let calls = post_event_calls(&store, writer);
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert_eq!(calls[0], StoreCall::ActivityLookup(BASE_DIGEST.to_owned()));
    let Some(StoreCall::RecordCommandActivity {
        evidence,
        invocation_preview,
    }) = calls.get(1)
    else {
        panic!("{calls:?}");
    };
    assert_eq!(evidence["execution_status"], json!("unpaired_post"));
    assert_eq!(evidence["harness"], json!("claude-code"));
    assert_eq!(evidence["succeeded"], json!(true));
    let activity_id = evidence["activity_id"].as_str().expect("activity id");
    assert!(activity_id.starts_with("activity:"), "{activity_id}");
    assert_eq!(activity_id.len(), "activity:".len() + 32, "{activity_id}");
    assert_eq!(invocation_preview.as_deref(), Some("rm -rf …"));
}

#[test]
fn a_post_event_promotes_the_pre_hook_row_it_pairs_with() {
    let (store, writer) = fixture(false);
    store.set_previous(stored_row("allowed_unconfirmed"));

    let calls = post_event_calls(&store, writer);
    assert_eq!(calls.len(), 2, "{calls:?}");
    let Some(StoreCall::Transition(current)) = calls.get(1) else {
        panic!("{calls:?}");
    };
    assert_eq!(current["activity_id"], json!("activity:stored"));
    assert_eq!(current["execution_status"], json!("confirmed_success"));
}

#[test]
fn a_post_event_never_overwrites_a_prevented_row() {
    let (store, writer) = fixture(false);
    store.set_previous(stored_row("prevented"));

    assert_eq!(
        post_event_calls(&store, writer),
        vec![StoreCall::ActivityLookup(BASE_DIGEST.to_owned())]
    );
}

#[test]
fn a_repeated_post_event_leaves_the_confirmed_row_alone() {
    let (store, writer) = fixture(false);
    store.set_previous(stored_row("confirmed_success"));

    assert_eq!(
        post_event_calls(&store, writer),
        vec![StoreCall::ActivityLookup(BASE_DIGEST.to_owned())]
    );
}

#[test]
fn a_post_event_against_an_unexpected_status_records_a_conflict() {
    let (store, writer) = fixture(false);
    store.set_previous(stored_row("attempted"));

    let calls = post_event_calls(&store, writer);
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert_eq!(
        calls[1],
        StoreCall::ObservationConflict("2026-10-17T00:00:00+00:00".to_owned())
    );
}

#[test]
fn a_pre_event_without_a_command_never_reaches_the_store() {
    let (store, writer) = fixture(false);
    let Value::Object(payload) =
        json!({"tool_name": "Read", "tool_input": {"file_path": "/etc/hosts"}})
    else {
        unreachable!("object literal");
    };
    assert!(writer.submit_command_activity(
        "claude-code",
        "PreToolUse",
        &payload,
        true,
        Some("allow"),
        None,
        false,
        "not-applicable",
    ));
    assert!(writer.stop(5.0), "writer drained");

    assert!(store.calls().is_empty(), "{:?}", store.calls());
}

// ---------------------------------------------------------------------------
// Queue, drain and recovery scaffolding. The writer runs its own thread, so
// every wait below is a handshake with that thread rather than a sleep.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct GateState {
    entered: bool,
    released: bool,
}

/// A rendezvous between the test thread and the writer's worker thread.
/// `enter` parks the worker inside a seam, `wait_for_entry` lets the test
/// proceed only once the worker is parked there, and `release` lets it out.
struct Gate {
    state: Mutex<GateState>,
    changed: Condvar,
}

impl Gate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(GateState::default()),
            changed: Condvar::new(),
        })
    }

    fn enter(&self) {
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        state.entered = true;
        self.changed.notify_all();
        while !state.released {
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(|err| err.into_inner());
        }
    }

    fn wait_for_entry(&self) {
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        while !state.entered {
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(|err| err.into_inner());
        }
    }

    fn release(&self) {
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        state.released = true;
        self.changed.notify_all();
    }
}

/// The durability seam held in memory, so a test can seed a journal the way a
/// previous writer would have left it and read what a drain removed.
#[derive(Default)]
struct RecordingJournal {
    records: Mutex<Vec<Map<String, Value>>>,
}

impl RecordingJournal {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// A journal holding `records`, as a writer that stopped mid-drain leaves
    /// behind for the next one to recover.
    fn holding(records: Vec<Map<String, Value>>) -> Arc<Self> {
        Arc::new(Self {
            records: Mutex::new(records),
        })
    }

    fn records(&self) -> Vec<Map<String, Value>> {
        self.records
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .clone()
    }
}

/// The record id a journal line carries: a receipt is keyed by its decision,
/// every other record by its own `record_id`.
fn journaled_record_id(raw: &Map<String, Value>) -> String {
    for key in ["decision_id", "record_id"] {
        match raw.get(key) {
            Some(Value::String(id)) => return id.clone(),
            Some(value) => return value.to_string(),
            None => continue,
        }
    }
    String::new()
}

impl EvidenceJournalApi for Arc<RecordingJournal> {
    fn append_journal(&self, _path: &Path, record: &EvidenceRecord) -> Result<(), io::Error> {
        let Ok(Value::Object(raw)) = serde_json::from_slice::<Value>(&record.serialized()) else {
            return Err(io::Error::other("record is not a JSON object"));
        };
        self.records
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .push(raw);
        Ok(())
    }

    fn rewrite_journal(
        &self,
        _path: &Path,
        remove_record_id: &str,
        _max_bytes: usize,
    ) -> Result<u64, io::Error> {
        self.records
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .retain(|raw| journaled_record_id(raw) != remove_record_id);
        Ok(0)
    }

    fn recover_journal_records(
        &self,
        _path: &Path,
        _max_bytes: usize,
    ) -> Result<(Vec<Map<String, Value>>, u64), io::Error> {
        Ok((self.records(), 0))
    }

    fn now_utc_iso(&self) -> String {
        "2026-10-17T00:00:00+00:00".to_owned()
    }
}

fn deps_with_journal(journal: Arc<RecordingJournal>) -> EvidenceWriterDeps {
    EvidenceWriterDeps {
        correlation: Box::new(StubCorrelation),
        receipts: Arc::new(StubReceipts),
        composio: Arc::new(StubComposio),
        journal: Box::new(journal),
        sqlite_timeout: Box::new(StubSqliteTimeout),
    }
}

/// A drain budget far larger than an in-memory stub needs, so that no
/// assertion after a `stop` depends on how loaded the host is.
const DRAIN_BUDGET_SECONDS: f64 = 30.0;

fn queue_home() -> PathBuf {
    PathBuf::from("/hol-guard-evidence-writer-queue-tests")
}

fn queue_writer(
    store: Arc<StubStore>,
    journal: Arc<RecordingJournal>,
    max_records: usize,
) -> RuntimeHookEvidenceWriter {
    RuntimeHookEvidenceWriter::new(
        store,
        deps_with_journal(journal),
        max_records,
        1 << 20,
        8,
        0.01,
        Some(queue_home().join("runtime-hook-evidence.jsonl")),
    )
    .expect("writer")
}

/// The smallest receipt the writer accepts: `StubReceipts` validates whatever
/// it is handed, and the schema is what `EvidenceRecord::from_json` recovers by.
fn receipt(decision_id: &str) -> Map<String, Value> {
    let Value::Object(receipt) = json!({
        "schema": "hol-native-decision-receipt.v1",
        "decision_id": decision_id,
    }) else {
        unreachable!("object literal");
    };
    receipt
}

#[test]
fn a_receipt_handoff_returns_before_the_store_has_written_it() {
    let gate = Gate::new();
    let journal = RecordingJournal::new();
    let store = StubStore::gated(queue_home(), Arc::clone(&gate));
    let writer = queue_writer(store, Arc::clone(&journal), 64);

    // The handoff is what a decision pays for, so it returns while the store
    // write is still outstanding.
    assert!(writer.submit_native_decision_receipt(&receipt("decision-1")));
    gate.wait_for_entry();
    let handed_off = writer.stats();
    assert_eq!(handed_off.receipt_accepted, 1);
    assert_eq!(handed_off.receipt_processed, 0);
    // Durable first: the record is in the journal before the store sees it.
    assert_eq!(handed_off.receipt_durable_pending, 1);
    assert_eq!(journal.records().len(), 1);

    gate.release();
    assert!(writer.stop(DRAIN_BUDGET_SECONDS));
    let drained = writer.stats();
    assert_eq!(drained.receipt_processed, 1);
    assert_eq!(drained.receipt_durable_pending, 0);
    assert!(journal.records().is_empty());
}

/// A worker inside a store write cannot see its drain deadline pass, and a
/// stop that joined it unconditionally would wait for that write however long
/// it took — past the budget it was given and past the caller's transport
/// timeout, with every request serialised behind it still waiting.
#[test]
fn a_stop_gives_up_on_a_worker_that_outlasts_its_drain_budget() {
    let gate = Gate::new();
    let journal = RecordingJournal::new();
    let store = StubStore::gated(queue_home(), Arc::clone(&gate));
    let writer = queue_writer(store, Arc::clone(&journal), 64);

    assert!(writer.submit_native_decision_receipt(&receipt("decision-1")));
    gate.wait_for_entry();

    // The worker is parked in the store write and never reads the deadline.
    assert!(!writer.stop(0.0));
    assert!(!writer.has_exited());

    // It is still the journal's owner until it leaves, and it finishes the
    // write it was in the middle of.
    gate.release();
    assert!(writer.stop(DRAIN_BUDGET_SECONDS));
    assert!(writer.has_exited());
    assert_eq!(writer.stats().receipt_processed, 1);
}

/// A writer whose drain ran out of time still owns the journal it was
/// draining. The slot that holds it has to be able to tell that apart from a
/// writer that has left, or it would build a second writer for the same home
/// and let two workers append to one file.
#[test]
fn a_writer_that_outlasts_its_drain_reports_that_it_is_still_stopping() {
    let gate = Gate::new();
    let journal = RecordingJournal::new();
    let store = StubStore::gated(queue_home(), Arc::clone(&gate));
    let writer = queue_writer(store, Arc::clone(&journal), 64);

    assert!(writer.submit_native_decision_receipt(&receipt("decision-1")));
    gate.wait_for_entry();
    assert!(!writer.is_stopping(), "no stop has been asked for yet");

    assert!(!writer.stop(0.0));
    assert!(writer.is_stopping(), "the worker has not left the loop");

    gate.release();
    assert!(writer.stop(DRAIN_BUDGET_SECONDS));
    assert!(
        !writer.is_stopping(),
        "the worker has left, so the journal is free"
    );
}

#[test]
fn a_repeated_receipt_is_deduplicated_rather_than_queued_twice() {
    let gate = Gate::new();
    let journal = RecordingJournal::new();
    let store = StubStore::gated(queue_home(), Arc::clone(&gate));
    let writer = queue_writer(store, Arc::clone(&journal), 64);

    // A hook that reports the same decision twice must not persist it twice,
    // and the repeat is accepted rather than reported as a drop: nothing was
    // lost.
    assert!(writer.submit_native_decision_receipt(&receipt("decision-1")));
    gate.wait_for_entry();
    assert!(writer.submit_native_decision_receipt(&receipt("decision-1")));

    let deduped = writer.stats();
    assert_eq!(deduped.receipt_accepted, 1);
    assert_eq!(deduped.receipt_deduped, 1);
    assert_eq!(deduped.receipt_dropped, 0);
    assert!(!deduped.degraded);

    gate.release();
    assert!(writer.stop(DRAIN_BUDGET_SECONDS));
    let drained = writer.stats();
    assert_eq!(drained.receipt_processed, 1);
    assert!(journal.records().is_empty());
}

#[test]
fn a_full_receipt_queue_drops_the_overflow_instead_of_blocking() {
    let gate = Gate::new();
    let journal = RecordingJournal::new();
    let store = StubStore::gated(queue_home(), Arc::clone(&gate));
    let writer = queue_writer(store, Arc::clone(&journal), 1);

    assert!(writer.submit_native_decision_receipt(&receipt("decision-1")));
    // Parked inside the store, the worker has taken the first receipt off the
    // queue, so the one place the queue holds is free again.
    gate.wait_for_entry();
    assert!(writer.submit_native_decision_receipt(&receipt("decision-2")));
    // The queue is full now. A third receipt is refused rather than made to
    // wait, because a decision must not block on evidence.
    assert!(!writer.submit_native_decision_receipt(&receipt("decision-3")));

    let overflowed = writer.stats();
    assert_eq!(overflowed.receipt_accepted, 2);
    assert_eq!(overflowed.receipt_dropped, 1);
    assert_eq!(overflowed.dropped, 1);
    assert!(overflowed.degraded);

    gate.release();
    assert!(writer.stop(DRAIN_BUDGET_SECONDS));
}

#[test]
fn a_receipt_left_in_the_journal_is_recovered_by_the_next_writer() {
    let gate = Gate::new();
    let journal = RecordingJournal::holding(vec![receipt("left-behind")]);
    let store = StubStore::gated(queue_home(), Arc::clone(&gate));
    // A writer that stopped before its drain finished leaves the record in the
    // journal; the next writer over that journal replays it.
    let writer = queue_writer(store, Arc::clone(&journal), 64);

    gate.wait_for_entry();
    let recovered = writer.stats();
    assert_eq!(recovered.recovered, 1);
    assert_eq!(recovered.receipt_durable_pending, 1);

    gate.release();
    assert!(writer.stop(DRAIN_BUDGET_SECONDS));
    let drained = writer.stats();
    assert_eq!(drained.receipt_processed, 1);
    assert_eq!(drained.receipt_durable_pending, 0);
    assert!(journal.records().is_empty());
}

#[test]
fn a_store_that_keeps_failing_drops_a_receipt_after_bounded_retries() {
    let journal = RecordingJournal::new();
    let store = StubStore::failing_receipts(queue_home());
    let writer = queue_writer(store, Arc::clone(&journal), 64);

    assert!(writer.submit_native_decision_receipt(&receipt("decision-1")));
    assert!(writer.stop(DRAIN_BUDGET_SECONDS));

    // A store that never recovers must not keep the record forever: the
    // retries are bounded, and the journal is cleared with the queue.
    let stats = writer.stats();
    assert_eq!(stats.receipt_processed, 0);
    assert_eq!(stats.receipt_dropped, 1);
    assert_eq!(stats.receipt_failures, 1);
    assert_eq!(stats.dropped, 1);
    assert!(stats.degraded);
    assert_eq!(stats.receipt_durable_pending, 0);
    assert!(journal.records().is_empty());
}

/// A journal whose rewrite always reports invalid lines it dropped.
struct InvalidLineJournal;

impl EvidenceJournalApi for InvalidLineJournal {
    fn append_journal(&self, _path: &Path, _record: &EvidenceRecord) -> Result<(), io::Error> {
        Ok(())
    }

    fn rewrite_journal(
        &self,
        _path: &Path,
        _remove_record_id: &str,
        _max_bytes: usize,
    ) -> Result<u64, io::Error> {
        Ok(2)
    }

    fn recover_journal_records(
        &self,
        _path: &Path,
        _max_bytes: usize,
    ) -> Result<(Vec<Map<String, Value>>, u64), io::Error> {
        Ok((Vec::new(), 0))
    }

    fn now_utc_iso(&self) -> String {
        "2026-10-17T00:00:00+00:00".to_owned()
    }
}

/// The worker records the lines a rewrite dropped while it already holds the
/// shared state. Counting them through a second lock would wedge the worker
/// on its own mutex, holding the lock a stop waits for, and every request
/// serialised behind that stop with it.
#[test]
fn a_rewrite_that_drops_invalid_lines_still_lets_the_writer_stop() {
    let home = PathBuf::from("/hol-guard-evidence-writer-tests");
    let store = StubStore::new(home.clone(), false);
    let mut writer_deps = deps();
    writer_deps.journal = Box::new(InvalidLineJournal);
    let writer = RuntimeHookEvidenceWriter::new(
        store,
        writer_deps,
        64,
        1 << 20,
        8,
        0.01,
        Some(home.join("runtime-hook-evidence.jsonl")),
    )
    .expect("writer");

    assert!(writer.submit_command_activity(
        "claude-code",
        "PreToolUse",
        &command_payload(),
        true,
        Some("allow"),
        None,
        false,
        "not-applicable",
    ));
    assert!(writer.stop(5.0), "writer drained");

    let stats = writer.stats();
    assert_eq!(stats.processed, 1);
    assert_eq!(stats.failures, 2);
    assert!(stats.degraded);
}
