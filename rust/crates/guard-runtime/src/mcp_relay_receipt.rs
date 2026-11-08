//! The receipts of plain relayed MCP tool calls, written by the resident.
//!
//! A forward or block the native relay decided leaves a record in the
//! direct-evidence queue, and the daemon's drain recorded each one as the
//! Python proxy does: one resident round trip to project the call, one for its
//! receipt evidence, and one more to write the inventory row, receipt and
//! runtime event. For a plain record every input of that receipt is already in
//! the record, so the resident writes it itself through the same
//! `record_tool_call_evidence` store operation, once the daemon acknowledges
//! the page that skipped it. A plain record is a forward, a policy block, a
//! refused inline prompt, a safe-alternative block or an ask block whose
//! identity carries its firewall evidence. The resident raises an ask block's
//! desktop notice itself as soon as it writes the request, so for a harness
//! whose approval flow never opens the browser its receipt is all that is left
//! to write. A safe-alternative block's silent inbox row follows its receipt
//! through the same `queue_blocked_approvals` store operation the daemon's
//! `record_unprompted_review` calls. A relayed package call's forward,
//! observed forward, policy block or ask block is plain too: its receipt is
//! written against the package request's artifact, which the resident
//! rebuilds from the record (`mcp_relay_receipt_package.rs`).
//!
//! Everything else is still drained to the daemon: a remembered allow writes
//! the daemon's policy, an ask block whose notice the resident could not read
//! still carries it, and an ask block from a harness whose approval flow opens
//! the approval center in the browser still needs the daemon to open it.
//!
//! As in the Python drain, a record the resident cannot compose is dropped,
//! never guessed. One the store cannot take goes back to the queue as an
//! ordinary record, so the daemon records it, retrying as it always has.

use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use guard_command::mcp_runtime_evidence::ArgumentEntry;
use guard_contracts::{
    canonical_utc_timestamp, GuardStoreRequestV1, McpCallProjectionQueryV1,
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

#[path = "mcp_relay_receipt_event.rs"]
mod event;
#[path = "mcp_relay_receipt_package.rs"]
mod package;
#[path = "mcp_relay_receipt_record.rs"]
mod record;
#[path = "mcp_relay_receipt_row.rs"]
mod row;

use event::{store_args, Receipt};
use record::plain;

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
const RECEIPT_METHOD: &str = "record_tool_call_evidence";
const QUEUE_METHOD: &str = "queue_blocked_approvals";
/// `GuardStore`'s default `guard_event_queue_limit`.
const EVENT_QUEUE_LIMIT: u64 = 1_000;

/// A receipt's store arguments and its silent inbox row's.
type Args = (Map<String, Value>, Option<Map<String, Value>>);
/// A record, its receipt's store arguments and its silent inbox row's.
type Composed = (Value, Map<String, Value>, Option<Map<String, Value>>);

/// One writer at a time, so two drains never contend for the store.
static WRITER: Mutex<()> = Mutex::new(());

/// Whether the resident writes this queued record's receipt itself.
pub(crate) fn is_plain(record: &Value) -> bool {
    plain(record).is_some() || package::plain(record).is_some()
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
    let composed: Vec<Composed> = records
        .into_iter()
        .filter_map(|record| {
            let (receipt, row) = compose(guard_home, &record, &Stamp::fresh()?)?;
            Some((record, receipt, row))
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
            .filter_map(|(record, receipt, row)| {
                if !store(guard_home, busy_timeout_ms, RECEIPT_METHOD, receipt) {
                    return Some(record);
                }
                // After the receipt, as the proxy writes them. A row the store
                // cannot take leaves the block without one, as
                // `record_unprompted_review` does.
                if let Some(row) = row {
                    store(guard_home, busy_timeout_ms, QUEUE_METHOD, row);
                }
                None
            })
            .collect()
    };
    repair_store_permissions(home);
    unwritten
}

fn records_of(composed: Vec<Composed>) -> Vec<Value> {
    composed.into_iter().map(|(record, ..)| record).collect()
}

/// Whether the write is in the store: a failure after the commit (the
/// outbox generation read) leaves it written, so the daemon must not write a
/// receipt again under a fresh receipt id.
fn store(guard_home: &str, busy_timeout_ms: u64, method: &str, args: Map<String, Value>) -> bool {
    let (outcome, committed) = crate::guard_store_op::evaluate_committing(&GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: "mcp-relay-receipt".to_owned(),
        store_path: Path::new(guard_home)
            .join(STORE_FILE_NAME)
            .to_string_lossy()
            .into_owned(),
        guard_home: guard_home.to_owned(),
        method: method.to_owned(),
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

/// The call a receipt's display evidence is derived from.
struct Call<'a> {
    tool_name: &'a str,
    params: &'a Value,
    artifact_name: &'a str,
    description: Option<&'a str>,
    /// The artifact's firewall evidence; the proxy enriches only a tool or
    /// server artifact, so a package request's receipt carries none.
    firewall: Option<&'a Value>,
}

/// `receipt_evidence_for_mcp_tool_call` for an artifact that needs no
/// enrichment: the displayed command and the firewall evidence entry.
fn receipt_evidence(
    guard_home: &str,
    call: &Call<'_>,
    stamp: &Stamp,
    risk_categories: &[String],
) -> Option<(Option<String>, Value)> {
    let projection = crate::mcp_proxy_projection::call_projection(&McpCallProjectionQueryV1 {
        tool_name: call.tool_name.to_owned(),
        params: call.params.clone(),
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
    let request = McpRuntimeEvidenceRequestV1 {
        schema: MCP_RUNTIME_EVIDENCE_REQUEST_SCHEMA.to_owned(),
        request_id: stamp.device_id.clone(),
        subop: "receipt_evidence".to_owned(),
        guard_home: guard_home.to_owned(),
        artifact_name: call.artifact_name.to_owned(),
        tool_description: call.description.map(str::to_owned),
        arguments,
        risk_categories: risk_categories.to_vec(),
        envelope: None,
    };
    let mut evidence = Map::new();
    if let Some(firewall) = call.firewall {
        evidence.insert("mcpSkillFirewall".to_owned(), firewall.clone());
    }
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
/// `block_tool_call` writes for this record, and the silent inbox row a
/// safe-alternative block adds after it.
fn compose(guard_home: &str, record: &Value, stamp: &Stamp) -> Option<Args> {
    if record.get("kind").and_then(Value::as_str) == Some(package::KIND) {
        return Some((package::compose(guard_home, record, stamp)?, None));
    }
    let plain = plain(record)?;
    let artifact = plain.artifact;
    let name = artifact["name"].as_str()?;
    let projected = plain.projected()?;
    let risk_categories = plain.risk_categories(projected.as_ref())?;
    let call = Call {
        tool_name: plain.tool_name,
        params: plain.params,
        artifact_name: name,
        description: artifact["metadata"]["tool_description"].as_str(),
        firewall: Some(plain.firewall),
    };
    let (raw_command_text, firewall_evidence) =
        receipt_evidence(guard_home, &call, stamp, &risk_categories)?;
    // `(*tool_decision_scanner_evidence(decision), *evidence_append)`, which
    // the inbox row records as well.
    let mut call_evidence = decision_evidence(plain.decision);
    call_evidence.extend(plain.append.iter().cloned());
    let row = projected
        .as_ref()
        .and_then(|projected| row::silent_review(&plain, projected, &call_evidence, stamp));
    let mut scanner_evidence = vec![firewall_evidence];
    scanner_evidence.extend(call_evidence);
    let launch_command = artifact["command"]
        .as_str()
        .filter(|command| !command.is_empty())
        .map(|command| command.trim().to_owned());
    let receipt = Receipt {
        harness: plain.harness,
        forward: plain.forward,
        source: plain.source,
        policy_action: plain.policy_action,
        artifact: event::Artifact {
            artifact_id: artifact["artifact_id"].as_str()?,
            name,
            artifact_type: "tool_call",
            source_scope: artifact["source_scope"].as_str()?,
            config_path: artifact["config_path"].as_str()?,
            publisher: artifact["publisher"].clone(),
            origin_url: Value::Null,
            launch_command,
            transport: artifact["transport"].clone(),
        },
        artifact_hash: plain.artifact_hash,
        signals: strings(&plain.decision["signals"]),
        risk_categories: &risk_categories,
        scanner_evidence,
        raw_command_text,
    };
    Some((store_args(&receipt, stamp)?, row))
}

#[cfg(test)]
#[path = "mcp_relay_receipt_tests.rs"]
pub(crate) mod tests;
