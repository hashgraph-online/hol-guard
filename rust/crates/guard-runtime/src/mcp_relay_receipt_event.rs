//! The `record_tool_call_evidence` arguments `allow_tool_call` and
//! `block_tool_call` write: the inventory row, the receipt with its diff
//! summary, and the runtime event payload, as the Python store writes them.

use guard_contracts::write_json_string;
use serde_json::{json, Map, Value};

use super::record::block_taxonomy;
use super::{approval_source, Stamp, EVENT_QUEUE_LIMIT};

/// The inventory fields of the artifact a receipt is written against,
/// `inventory_artifact_wire`.
pub(super) struct Artifact<'a> {
    pub(super) artifact_id: &'a str,
    pub(super) name: &'a str,
    pub(super) artifact_type: &'a str,
    pub(super) source_scope: &'a str,
    pub(super) config_path: &'a str,
    pub(super) publisher: Value,
    pub(super) origin_url: Value,
    pub(super) launch_command: Option<String>,
    pub(super) transport: Value,
}

/// Everything one receipt is written from.
pub(super) struct Receipt<'a> {
    pub(super) harness: &'a str,
    pub(super) forward: bool,
    pub(super) source: &'a str,
    pub(super) policy_action: &'a str,
    pub(super) artifact: Artifact<'a>,
    pub(super) artifact_hash: &'a str,
    pub(super) signals: Vec<&'a str>,
    pub(super) risk_categories: &'a [String],
    pub(super) scanner_evidence: Vec<Value>,
    pub(super) raw_command_text: Option<String>,
}

/// The `record_tool_call_evidence` arguments for `receipt`.
pub(super) fn store_args(receipt: &Receipt<'_>, stamp: &Stamp) -> Option<Map<String, Value>> {
    let artifact = &receipt.artifact;
    let config_path = artifact.config_path;
    let (event_name, provenance_summary, user_override) = if receipt.forward {
        (
            "runtime_tool_call_allowed",
            format!("runtime tool call allowed from {config_path}"),
            (receipt.source == "inline-approved").then_some("inline-approve"),
        )
    } else {
        let (event_name, provenance) = block_taxonomy(receipt.policy_action)?;
        (
            event_name,
            format!("{provenance} from {config_path}"),
            (receipt.source == "inline-denied").then_some("inline-deny"),
        )
    };
    let mut changed = vec!["runtime_tool_call", receipt.source];
    changed.extend(receipt.signals.iter().copied());
    let receipt_row = json!({
        "receipt_id": stamp.receipt_id,
        "timestamp": stamp.now,
        "harness": receipt.harness,
        "artifact_id": artifact.artifact_id,
        "artifact_hash": receipt.artifact_hash,
        "policy_decision": receipt.policy_action,
        "capabilities_summary": format!("mcp tool call \u{2022} {}", artifact.name),
        "changed_capabilities": changed,
        "provenance_summary": provenance_summary,
        "user_override": user_override,
        "artifact_name": artifact.name,
        "source_scope": artifact.source_scope,
        "diff_summary": diff_summary(&changed),
        "approval_source": approval_source(receipt.source),
        "approval_request_id": null,
        "scanner_evidence": receipt.scanner_evidence,
        "raw_command_text": receipt.raw_command_text,
    });
    let inventory = json!({
        "artifact_id": artifact.artifact_id,
        "harness": receipt.harness,
        "artifact_name": artifact.name,
        "artifact_type": artifact.artifact_type,
        "source_scope": artifact.source_scope,
        "config_path": config_path,
        "publisher": artifact.publisher,
        "origin_url": artifact.origin_url,
        "launch_command": artifact.launch_command,
        "transport": artifact.transport,
        "artifact_hash": receipt.artifact_hash,
        "policy_action": receipt.policy_action,
        "changed": false,
        "approved": receipt.forward,
        "now": stamp.now,
    });
    let mut args = Map::new();
    args.insert("inventory".to_owned(), inventory);
    args.insert("receipt".to_owned(), receipt_row);
    args.insert("action_envelope".to_owned(), Value::Null);
    args.insert("now".to_owned(), json!(stamp.store_now));
    args.insert("new_device_id".to_owned(), json!(stamp.device_id));
    args.insert("event_queue_limit".to_owned(), json!(EVENT_QUEUE_LIMIT));
    args.insert("event_name".to_owned(), json!(event_name));
    args.insert(
        "event_payload_json".to_owned(),
        json!(event_payload_json(receipt)?),
    );
    args.insert("event_occurred_at".to_owned(), json!(stamp.now));
    Some(args)
}

/// `_auto_diff_summary`.
pub(super) fn diff_summary(changed: &[&str]) -> String {
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
pub(super) fn event_payload_json(receipt: &Receipt<'_>) -> Option<String> {
    let mut out = vec![b'{'];
    for (name, value) in [
        ("artifact_id", receipt.artifact.artifact_id),
        ("artifact_hash", receipt.artifact_hash),
        ("decision_source", receipt.source),
        ("policy_action", receipt.policy_action),
    ] {
        key(&mut out, name);
        write_json_string(value, &mut out);
    }
    if !receipt.forward {
        key(&mut out, "execution_outcome");
        write_json_string("not-executed", &mut out);
    }
    key(&mut out, "risk_categories");
    let risk_categories: Vec<&str> = receipt.risk_categories.iter().map(String::as_str).collect();
    list(&mut out, &risk_categories);
    key(&mut out, "signals");
    list(&mut out, &receipt.signals);
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
