//! The receipts of plain relayed MCP tool calls, written by the resident.
//!
//! A forward or block the native relay decided leaves a record in the
//! direct-evidence queue, and the daemon's drain recorded each one as the
//! Python proxy does: one resident round trip to project the call, one for its
//! receipt evidence, and one more to write the inventory row, receipt and
//! runtime event. For a plain record every input of that receipt is already in
//! the record, so the resident writes it itself through the same
//! `record_tool_call_evidence` store operation, once the daemon acknowledges
//! the page that skipped it. A plain record is a forward, a policy block or a
//! refused inline prompt whose identity carries its firewall evidence.
//!
//! Everything else is still drained to the daemon: a remembered allow writes
//! the daemon's policy, a safe-alternative block adds an inbox row and an ask
//! block raises the desktop notice and the approval center.
//!
//! As in the Python drain, a record the resident cannot compose is dropped,
//! never guessed. One the store cannot take goes back to the queue as an
//! ordinary record, so the daemon records it, retrying as it always has.

use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use guard_command::mcp_runtime_evidence::ArgumentEntry;
use guard_contracts::{
    canonical_utc_timestamp, write_json_string, GuardStoreRequestV1, McpCallProjectionQueryV1,
    McpRuntimeEvidenceRequestV1, GUARD_STORE_REQUEST_SCHEMA,
    MCP_RUNTIME_EVIDENCE_COMMAND_ARGUMENT_KEYS, MCP_RUNTIME_EVIDENCE_PATH_ARGUMENT_KEYS,
    MCP_RUNTIME_EVIDENCE_REQUEST_SCHEMA,
};
use serde_json::{json, Map, Value};

use crate::guard_store_op::MAX_BUSY_TIMEOUT_MS;
use crate::hook_direct::saved_decision::consume::repair_store_permissions;
use crate::hook_evidence_store_gate::hold_storage_gate;
use crate::hook_evidence_store_timeout::sqlite_timeout_ms;
use crate::local_store_read::STORE_FILE_NAME;

#[path = "mcp_relay_receipt_record.rs"]
mod record;

use record::{block_taxonomy, plain, Plain};

const INLINE_SOURCES: [&str; 4] = [
    "inline-approved",
    "inline-denied",
    "native-approved",
    "claude-native-approved",
];
const POLICY_SOURCES: [&str; 15] = [
    "heuristic",
    "policy",
    "auto",
    "pre-tool-hook",
    "permission-request-hook",
    "policy-allow",
    "policy-block",
    "policy_allow",
    "policy_block",
    "heuristic-allow",
    "heuristic-block",
    "heuristic_allow",
    "heuristic_block",
    "auto-allow",
    "auto-block",
];
/// `GuardStore`'s default `guard_event_queue_limit`.
const EVENT_QUEUE_LIMIT: u64 = 1_000;

/// One writer at a time, so two drains never contend for the store.
static WRITER: Mutex<()> = Mutex::new(());

/// Whether the resident writes this queued record's receipt itself.
pub(crate) fn is_plain(record: &Value) -> bool {
    plain(record).is_some()
}

/// Write the receipts of acknowledged plain records off the drain's thread,
/// so the page the daemon waits for is not held behind the store. Records the
/// store cannot take go to `unwritten`.
pub(crate) fn write_detached(
    guard_home: &str,
    records: Vec<Value>,
    unwritten: crate::hook_direct_evidence::Unwritten,
) {
    if records.is_empty() {
        return;
    }
    let home = guard_home.to_owned();
    let slot = Arc::new(Mutex::new(Some(records)));
    let job = Arc::clone(&slot);
    let requeue = unwritten.clone();
    let spawned = std::thread::Builder::new()
        .name("guard-mcp-relay-receipts".to_owned())
        .spawn(move || {
            let records = take(&job);
            requeue.requeue(write(&home, records));
        });
    if spawned.is_err() {
        // No writer thread: the daemon records them.
        unwritten.requeue(take(&slot));
    }
}

fn take(slot: &Mutex<Option<Vec<Value>>>) -> Vec<Value> {
    slot.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
        .unwrap_or_default()
}

/// Write each record's receipt under one storage gate hold, and return the
/// plain records the store did not take: a home without a store, a gate that
/// stayed closed, or a write that failed. Records that are not plain are
/// dropped.
pub(crate) fn write(guard_home: &str, records: Vec<Value>) -> Vec<Value> {
    let composed: Vec<(Value, Map<String, Value>)> = records
        .into_iter()
        .filter_map(|record| {
            let args = compose(guard_home, &record, &Stamp::fresh()?)?;
            Some((record, args))
        })
        .collect();
    if composed.is_empty() {
        return Vec::new();
    }
    let home = Path::new(guard_home);
    if !home.join(STORE_FILE_NAME).is_file() {
        return records_of(composed);
    }
    let _writer = WRITER.lock().unwrap_or_else(PoisonError::into_inner);
    let timeout_ms = sqlite_timeout_ms();
    let unwritten = {
        let Ok(_gate) = hold_storage_gate(home, Duration::from_millis(timeout_ms.into())) else {
            return records_of(composed);
        };
        let busy_timeout_ms = u64::from(timeout_ms).clamp(1, MAX_BUSY_TIMEOUT_MS);
        composed
            .into_iter()
            .filter_map(|(record, args)| {
                (!store(guard_home, busy_timeout_ms, args)).then_some(record)
            })
            .collect()
    };
    repair_store_permissions(home);
    unwritten
}

fn records_of(composed: Vec<(Value, Map<String, Value>)>) -> Vec<Value> {
    composed.into_iter().map(|(record, _)| record).collect()
}

/// Whether the receipt is in the store: a failure after the commit (the
/// outbox generation read) leaves it written, so the daemon must not write it
/// again under a fresh receipt id.
fn store(guard_home: &str, busy_timeout_ms: u64, args: Map<String, Value>) -> bool {
    let (outcome, committed) = crate::guard_store_op::evaluate_committing(&GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: "mcp-relay-receipt".to_owned(),
        store_path: Path::new(guard_home)
            .join(STORE_FILE_NAME)
            .to_string_lossy()
            .into_owned(),
        guard_home: guard_home.to_owned(),
        method: "record_tool_call_evidence".to_owned(),
        source: "mcp-relay".to_owned(),
        busy_timeout_ms,
        args,
    });
    outcome.is_ok() || committed
}

/// The values `build_receipt` and the store call draw fresh for each write.
struct Stamp {
    receipt_id: String,
    device_id: String,
    /// `datetime.now(timezone.utc).isoformat()`.
    now: String,
    /// The same instant with its microseconds always written.
    store_now: String,
}

impl Stamp {
    fn fresh() -> Option<Self> {
        let micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_micros();
        let now = crate::policy_bundle_time::micros_to_utc_isoformat(
            i64::try_from(micros).ok()?,
            "+00:00",
        )?;
        let store_now = canonical_utc_timestamp(&now)?;
        let receipt = uuid4_hex()?;
        Some(Self {
            receipt_id: format!(
                "guard-receipt-{}-{}-{}-{}-{}",
                &receipt[..8],
                &receipt[8..12],
                &receipt[12..16],
                &receipt[16..20],
                &receipt[20..]
            ),
            device_id: uuid4_hex()?,
            now,
            store_now,
        })
    }
}

fn uuid4_hex() -> Option<String> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).ok()?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Some(hex::encode(bytes))
}

fn strings(value: &Value) -> Vec<&str> {
    value
        .as_array()
        .map(|items| items.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// `_map_approval_source`.
fn approval_source(source: &str) -> &'static str {
    if INLINE_SOURCES.contains(&source) {
        "inline"
    } else if POLICY_SOURCES.contains(&source) || source.starts_with("policy") {
        "policy"
    } else {
        "approval_center"
    }
}

/// `tool_decision_scanner_evidence`.
fn decision_evidence(decision: &Map<String, Value>) -> Vec<Value> {
    let field = |key: &str| decision.get(key).cloned().unwrap_or(Value::Null);
    let policy_action = field("policy_action");
    let mut evidence = Vec::new();
    if !field("normalization_reason_code").is_null() {
        evidence.push(json!({
            "source": "guard_action_normalizer",
            "input_source": "stored_tool_policy",
            "reason_code": field("normalization_reason_code"),
            "original_action": field("original_action"),
            "normalized_action": policy_action,
        }));
    }
    if !field("approval_reuse_reason_code").is_null() {
        evidence.push(json!({
            "source": "approval_reuse",
            "status": field("approval_reuse_status"),
            "reason_code": field("approval_reuse_reason_code"),
            "current_action": field("current_action"),
            "saved_action": field("saved_action"),
            "effective_action": policy_action,
        }));
    }
    evidence
}

/// `receipt_evidence_for_mcp_tool_call` for an artifact that carries its
/// firewall evidence: the displayed command and the firewall evidence entry.
fn receipt_evidence(
    guard_home: &str,
    plain: &Plain<'_>,
    stamp: &Stamp,
    risk_categories: &[String],
) -> Option<(Option<String>, Value)> {
    let projection = crate::mcp_proxy_projection::call_projection(&McpCallProjectionQueryV1 {
        tool_name: plain.tool_name.to_owned(),
        params: plain.params.clone(),
        risk: None,
    })
    .ok()?;
    // `argument_entries`: only the keys the command text reads are shipped.
    let arguments: Option<Vec<ArgumentEntry>> =
        projection["safe_arguments"].as_object().map(|safe| {
            safe.iter()
                .filter(|(key, _)| {
                    MCP_RUNTIME_EVIDENCE_COMMAND_ARGUMENT_KEYS.contains(&key.as_str())
                        || MCP_RUNTIME_EVIDENCE_PATH_ARGUMENT_KEYS.contains(&key.as_str())
                })
                .map(|(key, value)| (key.clone(), value.as_str().map(str::to_owned)))
                .collect()
        });
    let description = plain.artifact["metadata"]["tool_description"].as_str();
    let request = McpRuntimeEvidenceRequestV1 {
        schema: MCP_RUNTIME_EVIDENCE_REQUEST_SCHEMA.to_owned(),
        request_id: stamp.device_id.clone(),
        subop: "receipt_evidence".to_owned(),
        guard_home: guard_home.to_owned(),
        artifact_name: plain.artifact["name"].as_str()?.to_owned(),
        tool_description: description.map(str::to_owned),
        arguments,
        risk_categories: risk_categories.to_vec(),
        envelope: None,
    };
    let mut evidence = Map::new();
    evidence.insert("mcpSkillFirewall".to_owned(), plain.firewall.clone());
    let command_text = match crate::mcp_runtime_evidence_op::receipt_evidence(&request) {
        Ok((command_text, runtime_action)) => {
            if let Some(runtime_action) = runtime_action {
                evidence.insert("runtimeAction".to_owned(), runtime_action);
            }
            command_text
        }
        Err(_) => {
            evidence.insert("runtimeEvidence".to_owned(), json!("native_unavailable"));
            None
        }
    };
    Some((command_text, Value::Object(evidence)))
}

/// The `record_tool_call_evidence` arguments `allow_tool_call` or
/// `block_tool_call` writes for this record.
fn compose(guard_home: &str, record: &Value, stamp: &Stamp) -> Option<Map<String, Value>> {
    let plain = plain(record)?;
    let artifact = plain.artifact;
    let name = artifact["name"].as_str()?;
    let config_path = artifact["config_path"].as_str()?;
    let artifact_id = artifact["artifact_id"].as_str()?;
    let signals = strings(&plain.decision["signals"]);
    let risk_categories: Vec<String> = strings(&plain.decision["risk_categories"])
        .into_iter()
        .map(str::to_owned)
        .collect();
    let (raw_command_text, firewall_evidence) =
        receipt_evidence(guard_home, &plain, stamp, &risk_categories)?;
    let mut scanner_evidence = vec![firewall_evidence];
    scanner_evidence.extend(decision_evidence(plain.decision));
    scanner_evidence.extend(plain.append.iter().cloned());
    let (event_name, provenance_summary, user_override) = if plain.forward {
        (
            "runtime_tool_call_allowed",
            format!("runtime tool call allowed from {config_path}"),
            (plain.source == "inline-approved").then_some("inline-approve"),
        )
    } else {
        let (event_name, provenance) = block_taxonomy(plain.policy_action)?;
        (
            event_name,
            format!("{provenance} from {config_path}"),
            (plain.source == "inline-denied").then_some("inline-deny"),
        )
    };
    let mut changed = vec!["runtime_tool_call", plain.source];
    changed.extend(signals.iter().copied());
    let receipt = json!({
        "receipt_id": stamp.receipt_id,
        "timestamp": stamp.now,
        "harness": plain.harness,
        "artifact_id": artifact_id,
        "artifact_hash": plain.artifact_hash,
        "policy_decision": plain.policy_action,
        "capabilities_summary": format!("mcp tool call \u{2022} {name}"),
        "changed_capabilities": changed,
        "provenance_summary": provenance_summary,
        "user_override": user_override,
        "artifact_name": name,
        "source_scope": artifact["source_scope"],
        "diff_summary": diff_summary(&changed),
        "approval_source": approval_source(plain.source),
        "approval_request_id": null,
        "scanner_evidence": scanner_evidence,
        "raw_command_text": raw_command_text,
    });
    let launch_command = artifact["command"]
        .as_str()
        .filter(|command| !command.is_empty())
        .map(str::trim);
    let inventory = json!({
        "artifact_id": artifact_id,
        "harness": plain.harness,
        "artifact_name": name,
        "artifact_type": "tool_call",
        "source_scope": artifact["source_scope"],
        "config_path": config_path,
        "publisher": artifact["publisher"],
        "origin_url": null,
        "launch_command": launch_command,
        "transport": artifact["transport"],
        "artifact_hash": plain.artifact_hash,
        "policy_action": plain.policy_action,
        "changed": false,
        "approved": plain.forward,
        "now": stamp.now,
    });
    let risk_refs: Vec<&str> = risk_categories.iter().map(String::as_str).collect();
    let mut args = Map::new();
    args.insert("inventory".to_owned(), inventory);
    args.insert("receipt".to_owned(), receipt);
    args.insert("action_envelope".to_owned(), Value::Null);
    args.insert("now".to_owned(), json!(stamp.store_now));
    args.insert("new_device_id".to_owned(), json!(stamp.device_id));
    args.insert("event_queue_limit".to_owned(), json!(EVENT_QUEUE_LIMIT));
    args.insert("event_name".to_owned(), json!(event_name));
    args.insert(
        "event_payload_json".to_owned(),
        json!(event_payload_json(
            &plain,
            artifact_id,
            &risk_refs,
            &signals
        )?),
    );
    args.insert("event_occurred_at".to_owned(), json!(stamp.now));
    Some(args)
}

/// `_auto_diff_summary`.
fn diff_summary(changed: &[&str]) -> String {
    let sample = changed
        .iter()
        .take(3)
        .copied()
        .collect::<Vec<_>>()
        .join(", ");
    let suffix = if changed.len() > 3 { " ..." } else { "" };
    format!("{} change(s): {sample}{suffix}", changed.len())
}

/// The runtime event's payload as `json.dumps` writes it: insertion order,
/// `", "` and `": "` separators, ASCII only.
fn event_payload_json(
    plain: &Plain<'_>,
    artifact_id: &str,
    risk_categories: &[&str],
    signals: &[&str],
) -> Option<String> {
    let mut out = vec![b'{'];
    for (name, value) in [
        ("artifact_id", artifact_id),
        ("artifact_hash", plain.artifact_hash),
        ("decision_source", plain.source),
        ("policy_action", plain.policy_action),
    ] {
        key(&mut out, name);
        write_json_string(value, &mut out);
    }
    if !plain.forward {
        key(&mut out, "execution_outcome");
        write_json_string("not-executed", &mut out);
    }
    key(&mut out, "risk_categories");
    list(&mut out, risk_categories);
    key(&mut out, "signals");
    list(&mut out, signals);
    out.push(b'}');
    String::from_utf8(out).ok()
}

fn key(out: &mut Vec<u8>, name: &str) {
    if out.len() > 1 {
        out.extend_from_slice(b", ");
    }
    write_json_string(name, out);
    out.extend_from_slice(b": ");
}

fn list(out: &mut Vec<u8>, items: &[&str]) {
    out.push(b'[');
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.extend_from_slice(b", ");
        }
        write_json_string(item, out);
    }
    out.push(b']');
}

#[cfg(test)]
#[path = "mcp_relay_receipt_tests.rs"]
pub(crate) mod tests;
