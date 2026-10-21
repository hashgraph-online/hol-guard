//! What survives an append, a rewrite and a recovery of the evidence journal.

use super::*;

use std::sync::Arc;

use crate::hook_evidence_writer::{
    CommandActivityRecord, ComposioActionSchema, ComposioWorkflowProposal, ObservedCliIdentity,
    ObservedMcpServerIdentity, ObservedMcpTool,
};

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let elapsed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "hg-evidence-journal-{label}-{}-{elapsed}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn journal(&self) -> PathBuf {
        self.0.join("evidence.jsonl")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// No journal line in these tests is a receipt or an MCP discovery, so the
/// record validators behind them never have an answer to give.
struct NoReceipts;

impl ReceiptValidationApi for NoReceipts {
    fn validate_native_decision_receipt(
        &self,
        _value: &Map<String, Value>,
    ) -> Option<Map<String, Value>> {
        None
    }
}

struct NoComposio;

impl ComposioApi for NoComposio {
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

fn journal() -> NativeEvidenceJournal {
    NativeEvidenceJournal::new(Arc::new(NoReceipts), Arc::new(NoComposio))
}

fn activity(record_id: &str, preview: Option<&str>) -> EvidenceRecord {
    EvidenceRecord::CommandActivity(CommandActivityRecord {
        record_id: record_id.to_owned(),
        harness: "claude-code".to_owned(),
        event: "PreToolUse".to_owned(),
        correlation: None,
        has_command: true,
        succeeded: true,
        payload_bytes: 0,
        attempts: 0,
        policy_action: Some("allow".to_owned()),
        occurred_at: Some("2026-10-17T00:00:00+00:00".to_owned()),
        receipt_id: None,
        prompted: false,
        approval_reuse_status: "not-applicable".to_owned(),
        invocation_preview: preview.map(str::to_owned),
    })
}

const MAX_BYTES: usize = 1 << 20;

#[test]
fn a_recovered_record_carries_the_preview_its_sidecar_kept() {
    let home = TempDir::new("recover");
    let path = home.journal();
    let journal = journal();
    journal
        .append_journal(&path, &activity("first", Some("git status")))
        .unwrap();
    journal
        .append_journal(&path, &activity("second", None))
        .unwrap();

    let (records, invalid) = journal.recover_journal_records(&path, MAX_BYTES).unwrap();

    assert_eq!(invalid, 0);
    let previews: Vec<Option<&str>> = records
        .iter()
        .map(|record| record.get("invocation_preview").and_then(Value::as_str))
        .collect();
    assert_eq!(previews, vec![Some("git status"), None]);
    // The preview is never written into the journal line itself.
    let body = fs::read_to_string(&path).unwrap();
    assert!(!body.contains("git status"), "{body}");
}

#[test]
fn a_rewrite_drops_one_record_and_the_preview_behind_it() {
    let home = TempDir::new("rewrite");
    let path = home.journal();
    let journal = journal();
    journal
        .append_journal(&path, &activity("first", Some("git status")))
        .unwrap();
    journal
        .append_journal(&path, &activity("second", Some("ls -al")))
        .unwrap();

    assert_eq!(
        journal.rewrite_journal(&path, "first", MAX_BYTES).unwrap(),
        0
    );

    let (records, _) = journal.recover_journal_records(&path, MAX_BYTES).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].get("record_id").and_then(Value::as_str),
        Some("second")
    );
    assert_eq!(
        records[0].get("invocation_preview").and_then(Value::as_str),
        Some("ls -al")
    );
    let sidecar = fs::read_to_string(preview_sidecar_path(&path)).unwrap();
    assert!(!sidecar.contains("git status"), "{sidecar}");
}

#[test]
fn removing_the_last_record_removes_its_sidecar() {
    let home = TempDir::new("last");
    let path = home.journal();
    let journal = journal();
    journal
        .append_journal(&path, &activity("only", Some("git status")))
        .unwrap();

    journal.rewrite_journal(&path, "only", MAX_BYTES).unwrap();

    assert!(!preview_sidecar_path(&path).exists());
    let (records, _) = journal.recover_journal_records(&path, MAX_BYTES).unwrap();
    assert!(records.is_empty());
}

#[test]
fn a_line_that_is_not_an_object_is_counted_and_dropped() {
    let home = TempDir::new("invalid");
    let path = home.journal();
    let journal = journal();
    journal
        .append_journal(&path, &activity("kept", None))
        .unwrap();
    let mut file = OpenOptions::new().append(true).open(&path).unwrap();
    file.write_all(b"not json\n[]\n").unwrap();
    drop(file);

    let (records, invalid) = journal.recover_journal_records(&path, MAX_BYTES).unwrap();
    assert_eq!(invalid, 2);
    assert_eq!(records.len(), 1);

    // The rewrite reports the same two lines and writes neither back.
    assert_eq!(
        journal.rewrite_journal(&path, "absent", MAX_BYTES).unwrap(),
        2
    );
    let (records, invalid) = journal.recover_journal_records(&path, MAX_BYTES).unwrap();
    assert_eq!((records.len(), invalid), (1, 0));
}

#[test]
fn a_journal_bigger_than_its_bound_is_refused() {
    let home = TempDir::new("bounded");
    let path = home.journal();
    let journal = journal();
    journal
        .append_journal(&path, &activity("first", None))
        .unwrap();

    let error = journal.recover_journal_records(&path, 8).unwrap_err();

    assert!(error.to_string().contains("size limit"), "{error}");
}

#[test]
fn a_symlink_is_not_a_journal() {
    let home = TempDir::new("symlink");
    let path = home.journal();
    let target = home.0.join("elsewhere.jsonl");
    fs::write(&target, b"").unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();

    let error = journal()
        .append_journal(&path, &activity("first", None))
        .unwrap_err();

    assert_eq!(error.raw_os_error(), Some(libc::ELOOP), "{error}");
    assert_eq!(fs::read(&target).unwrap(), Vec::<u8>::new());
}

#[test]
fn a_preview_the_display_bound_rejects_is_never_written() {
    let home = TempDir::new("preview-bound");
    let path = home.journal();
    let journal = journal();
    let long = "x".repeat(INVOCATION_PREVIEW_MAX_CHARS + 1);
    journal
        .append_journal(&path, &activity("first", Some(&long)))
        .unwrap();
    journal
        .append_journal(&path, &activity("second", Some("   ")))
        .unwrap();

    assert!(!preview_sidecar_path(&path).exists());
    let (records, _) = journal.recover_journal_records(&path, MAX_BYTES).unwrap();
    assert!(records
        .iter()
        .all(|record| record.get("invocation_preview").is_none()));
}

#[test]
fn a_record_the_validators_reject_is_counted_before_the_rewrite_drops_it() {
    let home = TempDir::new("tampered");
    let path = home.journal();
    let journal = journal();
    journal
        .append_journal(&path, &activity("kept", None))
        .unwrap();
    // A well-formed object carrying the command-activity schema but none of
    // its fields: the kind of line an edit on disk leaves behind.
    let mut file = OpenOptions::new().append(true).open(&path).unwrap();
    file.write_all(
        b"{\"schema\":\"hol-guard-native-hook-evidence.v1\",\"record_id\":\"edited\"}\n",
    )
    .unwrap();
    drop(file);

    // The rewrite deletes it, so it has to report it: Python counts every line
    // the validators turn down, not only the ones that fail to decode.
    assert_eq!(
        journal.rewrite_journal(&path, "absent", MAX_BYTES).unwrap(),
        1
    );
    let (records, invalid) = journal.recover_journal_records(&path, MAX_BYTES).unwrap();
    assert_eq!((records.len(), invalid), (1, 0));
}

#[test]
fn a_sidecar_preview_never_lands_on_another_record_type() {
    let home = TempDir::new("sidecar-type");
    let path = home.journal();
    let journal = journal();
    journal
        .append_journal(&path, &activity("shared", Some("git status")))
        .unwrap();
    // A discovery record that happens to carry the same handle. Its parser
    // accepts a fixed set of keys, so an attached preview would delete it.
    let mut file = OpenOptions::new().append(true).open(&path).unwrap();
    file.write_all(
        b"{\"schema\":\"hol-guard-mcp-provider-evidence.v1\",\"record_id\":\"shared\"}\n",
    )
    .unwrap();
    drop(file);

    let (records, _) = journal.recover_journal_records(&path, MAX_BYTES).unwrap();
    let discovery = records
        .iter()
        .find(|value| {
            value.get("schema").and_then(Value::as_str)
                == Some("hol-guard-mcp-provider-evidence.v1")
        })
        .expect("the discovery line survives recovery");
    assert!(!discovery.contains_key("invocation_preview"));
    let activity = records
        .iter()
        .find(|value| {
            value.get("schema").and_then(Value::as_str) == Some("hol-guard-native-hook-evidence.v1")
        })
        .expect("the activity line survives recovery");
    assert_eq!(
        activity.get("invocation_preview").and_then(Value::as_str),
        Some("git status")
    );
}

/// A discovery seam that accepts one connector and reports a single action.
struct OneDiscovery;

impl ComposioApi for OneDiscovery {
    fn observed_mcp_tool(&self, harness: &str, tool_name: &str) -> Option<ObservedMcpTool> {
        (harness == "claude-code" && tool_name == "mcp__composio__composio_search_tools").then(
            || ObservedMcpTool {
                harness: harness.to_owned(),
                qualified_name: tool_name.to_owned(),
                identity: ObservedCliIdentity {
                    cli_id: "local-cli.mcp-test".to_owned(),
                    name: "composio".to_owned(),
                    kind: "executable".to_owned(),
                    identity_hash: "0".repeat(64),
                    example_label: "mcp__composio__".to_owned(),
                    interpreter_name: None,
                },
                server: ObservedMcpServerIdentity {
                    identity_hash: "0".repeat(64),
                    command: None,
                    args_hash: "0".repeat(64),
                },
            },
        )
    }

    fn composio_discovered_actions(
        &self,
        _tool_name: &str,
        _response: &Value,
    ) -> Option<Vec<ComposioActionSchema>> {
        Some(vec![ComposioActionSchema {
            toolkit: "github".to_owned(),
            tool_slug: "GITHUB_STAR".to_owned(),
            description: "star".to_owned(),
            input_schema: Map::new(),
            full_schema: true,
        }])
    }

    fn composio_workflow_proposals(
        &self,
        _tool_name: &str,
        _response: &Value,
    ) -> Option<Vec<ComposioWorkflowProposal>> {
        Some(Vec::new())
    }
}

#[test]
fn a_discovery_record_without_proposals_survives_a_rewrite() {
    let home = TempDir::new("six-key");
    let path = home.journal();
    let journal = NativeEvidenceJournal::new(Arc::new(NoReceipts), Arc::new(OneDiscovery));
    journal
        .append_journal(&path, &activity("kept", None))
        .unwrap();
    // The six-key form Python writes when a provider offered no guidance.
    // Reading it back has to accept the missing key, or the rewrite below
    // deletes evidence the Python journal would have kept.
    let mut file = OpenOptions::new().append(true).open(&path).unwrap();
    file.write_all(
        br#"{"harness":"claude-code","occurred_at":"2026-10-17T00:00:00+00:00","record_id":"discovery","schema":"hol-guard-mcp-provider-evidence.v1","tool_name":"mcp__composio__composio_search_tools","tool_schemas":{}}
"#,
    )
    .unwrap();
    drop(file);

    assert_eq!(
        journal.rewrite_journal(&path, "absent", MAX_BYTES).unwrap(),
        0
    );
    let (records, _) = journal.recover_journal_records(&path, MAX_BYTES).unwrap();
    assert_eq!(records.len(), 2);
}
