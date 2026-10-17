//! Pre-hook persistence parity for `RuntimeHookEvidenceWriter`.
//!
//! A Pre event carries the verdict Rust already reached, so the writer builds
//! the evidence and the store only stores it. These cover the branch the
//! Python drain loop takes at `runtime_hook_evidence_writer.py:410-455`.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

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
    DeferredPost {
        harness: String,
        correlation_digest: Option<String>,
        succeeded: bool,
        has_command: bool,
        invocation_preview: Option<String>,
    },
}

#[derive(Default)]
struct StubStoreState {
    calls: Vec<StoreCall>,
    pre_replay: bool,
}

struct StubStore {
    guard_home: PathBuf,
    state: Mutex<StubStoreState>,
}

impl StubStore {
    fn new(guard_home: PathBuf, pre_replay: bool) -> Arc<Self> {
        Arc::new(Self {
            guard_home,
            state: Mutex::new(StubStoreState {
                calls: Vec::new(),
                pre_replay,
            }),
        })
    }

    fn calls(&self) -> Vec<StoreCall> {
        self.state.lock().expect("state").calls.clone()
    }

    fn push(&self, call: StoreCall) {
        self.state.lock().expect("state").calls.push(call);
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
        Ok(true)
    }

    fn persist_deferred_post_hook_command_activity(
        &self,
        harness: &str,
        correlation: Option<&CorrelationHandle>,
        succeeded: bool,
        has_command: bool,
        invocation_preview: Option<&str>,
    ) -> Result<bool, io::Error> {
        self.push(StoreCall::DeferredPost {
            harness: harness.to_owned(),
            correlation_digest: correlation.map(|handle| handle.digest.clone()),
            succeeded,
            has_command,
            invocation_preview: invocation_preview.map(str::to_owned),
        });
        Ok(true)
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
        receipts: Box::new(StubReceipts),
        composio: Box::new(StubComposio),
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
        "none",
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
        "accepted",
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
        Some("d5b3406976b245e21cb4b99a6f44865fb54da626c9acfecf354bc3be3917a324"),
        "a prevented attempt cannot pair with a post event, so it gets its own key"
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
        "none",
    ));
    assert!(writer.stop(5.0), "writer drained");

    let calls = store.calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert!(matches!(calls[0], StoreCall::PreReplayProbe(_)));
}

#[test]
fn a_post_event_goes_through_the_deferred_pairing_helper() {
    let (store, writer) = fixture(false);
    assert!(writer.submit_command_activity(
        "claude-code",
        "PostToolUse",
        &command_payload(),
        true,
        None,
        None,
        false,
        "none",
    ));
    assert!(writer.stop(5.0), "writer drained");

    assert_eq!(
        store.calls(),
        vec![StoreCall::DeferredPost {
            harness: "claude-code".to_owned(),
            correlation_digest: Some(BASE_DIGEST.to_owned()),
            succeeded: true,
            has_command: true,
            invocation_preview: Some("rm -rf …".to_owned()),
        }]
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
        "none",
    ));
    assert!(writer.stop(5.0), "writer drained");

    assert!(store.calls().is_empty(), "{:?}", store.calls());
}
