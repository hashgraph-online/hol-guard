use serde_json::{json, Map, Value};

use super::{compose, diff_summary, is_plain, write, Stamp};
use crate::guard_store_cmd_vectors_tests::temp_home;
use crate::guard_store_tool_call_evidence_tests::{build_database, count, vectors};

const HOME: &str = "/home/guard/.hol-guard";
const HASH: &str = "guard-approval-context:v1:0123456789abcdef";

/// A queued relay record as the native relay leaves it.
pub(crate) fn record(outcome: &str, source: &str, action: &str) -> Value {
    json!({
        "kind": "mcp_tool_call",
        "harness": "codex",
        "outcome": outcome,
        "decision_source": source,
        "policy_action": action,
        "tool_name": "run_command",
        "params": {"name": "run_command", "arguments": {"command": "ls -la"}},
        "arguments": {"format": "mapping", "entries": [["command", "ls -la"]]},
        "identity": {
            "artifact": {
                "artifact_id": "codex:project:shell:run_command",
                "name": "shell:run_command",
                "harness": "codex",
                "source_scope": "project",
                "config_path": "/work/.codex/config.toml",
                "command": "npx",
                "transport": "stdio",
                "publisher": null,
                "metadata": {
                    "mcpSkillFirewall": {"verdict": "clean", "findings": []},
                    "tool_description": "Run a shell command",
                },
            },
            "runtime_private_metadata": {},
            "artifact_hash": HASH,
            "risk_categories": [],
        },
        "decision": {
            "action": action,
            "policy_action": action,
            "source": source,
            "signals": ["shell"],
            "summary": "runs a shell command",
            "risk_categories": ["exec"],
            "normalization_reason_code": null,
            "original_action": null,
            "approval_reuse_status": null,
            "approval_reuse_reason_code": null,
            "current_action": null,
            "saved_action": null,
            "pending_approval_reuse_decision": null,
            "approval_reuse_claim_disposition": null,
            "post_claim_revalidated": false,
            "post_claim_authority": null,
        },
    })
}

fn stamp() -> Stamp {
    Stamp {
        receipt_id: "guard-receipt-00000000-0000-4000-8000-000000000000".to_owned(),
        device_id: "ffffffffffffffffffffffffffffffff".to_owned(),
        now: "2026-04-02T12:30:00+00:00".to_owned(),
        store_now: "2026-04-02T12:30:00.000000+00:00".to_owned(),
    }
}

fn composed(record: &Value) -> Map<String, Value> {
    compose(HOME, record, &stamp()).expect("a plain record composes")
}

fn edited(mut record: Value, edit: impl FnOnce(&mut Value)) -> Value {
    edit(&mut record);
    record
}

#[test]
fn a_forward_writes_the_allowed_receipt_inventory_and_event() {
    let args = composed(&record("forward", "policy", "allow"));
    let receipt = &args["receipt"];
    assert_eq!(receipt["receipt_id"], stamp().receipt_id);
    assert_eq!(receipt["timestamp"], "2026-04-02T12:30:00+00:00");
    assert_eq!(receipt["policy_decision"], "allow");
    assert_eq!(
        receipt["capabilities_summary"],
        "mcp tool call \u{2022} shell:run_command"
    );
    assert_eq!(
        receipt["changed_capabilities"],
        json!(["runtime_tool_call", "policy", "shell"])
    );
    assert_eq!(
        receipt["provenance_summary"],
        "runtime tool call allowed from /work/.codex/config.toml"
    );
    assert_eq!(receipt["user_override"], Value::Null);
    assert_eq!(receipt["approval_source"], "policy");
    assert_eq!(
        receipt["diff_summary"],
        "3 change(s): runtime_tool_call, policy, shell"
    );
    assert_eq!(receipt["raw_command_text"], "ls -la");
    assert_eq!(
        receipt["scanner_evidence"][0]["mcpSkillFirewall"],
        json!({"verdict": "clean", "findings": []})
    );
    let inventory = &args["inventory"];
    assert_eq!(inventory["artifact_type"], "tool_call");
    assert_eq!(inventory["launch_command"], "npx");
    assert_eq!(inventory["approved"], true);
    assert_eq!(inventory["now"], "2026-04-02T12:30:00+00:00");
    assert_eq!(args["now"], "2026-04-02T12:30:00.000000+00:00");
    assert_eq!(args["event_occurred_at"], "2026-04-02T12:30:00+00:00");
    assert_eq!(args["event_name"], "runtime_tool_call_allowed");
    assert_eq!(
        args["event_payload_json"],
        format!(
            "{{\"artifact_id\": \"codex:project:shell:run_command\", \"artifact_hash\": \"{HASH}\", \
             \"decision_source\": \"policy\", \"policy_action\": \"allow\", \
             \"risk_categories\": [\"exec\"], \"signals\": [\"shell\"]}}"
        )
    );
}

#[test]
fn an_inline_refusal_writes_a_not_executed_block() {
    let args = composed(&record("block", "inline-denied", "review"));
    let receipt = &args["receipt"];
    assert_eq!(receipt["user_override"], "inline-deny");
    assert_eq!(receipt["approval_source"], "inline");
    assert_eq!(
        receipt["provenance_summary"],
        "runtime tool call awaiting review from /work/.codex/config.toml"
    );
    assert_eq!(args["inventory"]["approved"], false);
    assert_eq!(args["event_name"], "runtime_tool_call_review_required");
    let payload: Value =
        serde_json::from_str(args["event_payload_json"].as_str().unwrap()).unwrap();
    assert_eq!(payload["execution_outcome"], "not-executed");
    assert!(args["event_payload_json"]
        .as_str()
        .unwrap()
        .contains("\"policy_action\": \"review\", \"execution_outcome\": \"not-executed\""));
}

#[test]
fn an_inline_approval_is_an_override() {
    let args = composed(&record("forward", "inline-approved", "allow"));
    assert_eq!(args["receipt"]["user_override"], "inline-approve");
    assert_eq!(args["receipt"]["approval_source"], "inline");
}

#[test]
fn decision_evidence_follows_the_firewall_and_precedes_the_appended_check() {
    let record = edited(record("forward", "policy", "warn"), |record| {
        let decision = &mut record["decision"];
        decision["normalization_reason_code"] = json!("legacy_action");
        decision["original_action"] = json!("allow");
        decision["approval_reuse_status"] = json!("accepted");
        decision["approval_reuse_reason_code"] = json!("same_hash");
        decision["saved_action"] = json!("warn");
        record["evidence_append"] = json!([{"source": "post_claim_check"}]);
    });
    let evidence = composed(&record)["receipt"]["scanner_evidence"].clone();
    let sources: Vec<&Value> = evidence
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| &entry["source"])
        .collect();
    assert_eq!(
        sources,
        [
            &Value::Null,
            &json!("guard_action_normalizer"),
            &json!("approval_reuse"),
            &json!("post_claim_check"),
        ]
    );
    assert_eq!(evidence[1]["normalized_action"], "warn");
    assert_eq!(evidence[2]["effective_action"], "warn");
}

#[test]
fn the_event_payload_escapes_like_json_dumps() {
    let record = edited(record("forward", "policy", "allow"), |record| {
        record["decision"]["signals"] = json!(["caf\u{e9}", "\u{1f600}"]);
    });
    let payload = composed(&record)["event_payload_json"].clone();
    assert!(payload
        .as_str()
        .unwrap()
        .ends_with("\"signals\": [\"caf\\u00e9\", \"\\ud83d\\ude00\"]}"));
}

#[test]
fn the_diff_summary_samples_three_changes() {
    assert_eq!(
        diff_summary(&["a", "b", "c", "d"]),
        "4 change(s): a, b, c ..."
    );
    assert_eq!(diff_summary(&["a"]), "1 change(s): a");
}

#[test]
fn records_the_daemon_owns_are_not_plain() {
    assert!(is_plain(&record("forward", "policy", "allow")));
    assert!(is_plain(&record("block", "policy-block", "block")));
    let not_plain = [
        record("remember", "policy", "allow"),
        record("forward", "policy", "review"),
        record("block", "approval-center-pending", "review"),
        record("block", "policy-block", "allow"),
        edited(record("forward", "policy", "allow"), |record| {
            record["harness"] = json!("claude-code");
            record["identity"]["artifact"]["harness"] = json!("claude-code");
        }),
        edited(record("forward", "policy", "allow"), |record| {
            record["identity"]["artifact"]["harness"] = json!("cursor");
        }),
        edited(record("forward", "policy", "allow"), |record| {
            record["decision"]["connector_setup"] = json!({});
        }),
        edited(record("forward", "policy", "allow"), |record| {
            record["decision"]["proxy"] = json!({});
        }),
        edited(record("forward", "policy", "allow"), |record| {
            record["decision"]["post_claim_revalidated"] = json!(true);
            record["decision"]["post_claim_authority"] = json!("fresh");
        }),
        edited(record("forward", "policy", "allow"), |record| {
            record["identity"]["artifact"]["metadata"]
                .as_object_mut()
                .unwrap()
                .remove("mcpSkillFirewall");
        }),
        edited(record("forward", "policy", "allow"), |record| {
            record["identity"]["artifact_hash"] = json!("0123456789abcdef");
        }),
        edited(record("forward", "policy", "allow"), |record| {
            record["arguments"]["entries"] = json!([["command", "rm -rf /"]]);
        }),
        edited(record("forward", "policy", "allow"), |record| {
            record["params"]["name"] = json!("other_tool");
        }),
        edited(record("forward", "policy", "allow"), |record| {
            record["evidence_append"] = json!(["not an object"]);
        }),
        edited(record("forward", "policy", "allow"), |record| {
            record["unexpected"] = json!(true);
        }),
    ];
    for record in &not_plain {
        assert!(!is_plain(record), "{record}");
    }
}

#[test]
fn a_home_without_a_store_hands_the_record_back() {
    let home = temp_home("relay-receipt-no-store");
    let unwritten = write(
        home.to_str().unwrap(),
        vec![record("forward", "policy", "allow")],
    );
    assert_eq!(unwritten, [record("forward", "policy", "allow")]);
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn plain_records_land_in_the_store() {
    let (receipts, inventory) = vectors();
    let home = temp_home("relay-receipt-store");
    build_database(&home.join("guard.db"), &receipts, &inventory);
    let before = count(&home, "runtime_receipts");
    let unwritten = write(
        home.to_str().unwrap(),
        vec![
            record("forward", "policy", "allow"),
            record("block", "inline-denied", "review"),
            record("remember", "policy", "allow"),
        ],
    );
    assert!(unwritten.is_empty(), "{unwritten:?}");
    assert_eq!(count(&home, "runtime_receipts"), before + 2);
    assert_eq!(count(&home, "guard_events"), 2);
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_receipt_committed_before_a_later_read_fails_is_not_handed_back() {
    let (receipts, inventory) = vectors();
    let home = temp_home("relay-receipt-post-commit");
    build_database(&home.join("guard.db"), &receipts, &inventory);
    // The outbox generation is read after the commit; a wake table without
    // its column fails that read with the receipt already written.
    rusqlite::Connection::open(home.join("guard.db"))
        .unwrap()
        .execute_batch(
            "create table guard_review_outbox_wake_state (singleton integer primary key)",
        )
        .unwrap();
    let before = count(&home, "runtime_receipts");
    let unwritten = write(
        home.to_str().unwrap(),
        vec![record("forward", "policy", "allow")],
    );
    assert!(unwritten.is_empty(), "{unwritten:?}");
    assert_eq!(count(&home, "runtime_receipts"), before + 1);
    let _ = std::fs::remove_dir_all(&home);
}
