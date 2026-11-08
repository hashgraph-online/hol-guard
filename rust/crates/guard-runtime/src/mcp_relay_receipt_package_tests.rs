use std::path::Path;

use guard_command::package_intent_common::{build_package_request_artifact, GuardArtifact};
use serde_json::{json, Map, Value};

use super::super::tests::record as tool_record;
use super::super::{compose, is_plain, write, Stamp};
use crate::guard_store_cmd_vectors_tests::temp_home;
use crate::guard_store_tool_call_evidence_tests::{build_database, count, vectors};

const HOME: &str = "/home/guard/.hol-guard";
const COMMAND: &str = "npm install left-pad";
const PATH: &str = "/usr/bin:/bin";
const PACKAGE_HASH: &str = "guard-approval-context:v1:fedcba9876543210";

/// The package request's artifact as the gate built it for `workspace`.
fn artifact(workspace: &Path) -> GuardArtifact {
    let intent = crate::mcp_relay_decide::parse_package_intent(
        "bash",
        &json!({"command": COMMAND}),
        Some(workspace),
        Some(PATH),
    )
    .expect("the command is a package request");
    build_package_request_artifact("codex", &intent, "/work/.codex/config.toml", "project")
}

/// A queued package record as `package_receipt::record` leaves it.
fn record(workspace: &Path, outcome: &str, source: &str, action: &str) -> Value {
    let mut record = tool_record(outcome, source, action);
    record["kind"] = json!("mcp_package_call");
    record["tool_name"] = json!("bash");
    record["params"] = json!({"name": "bash", "arguments": {"command": COMMAND}});
    record["arguments"] = json!({"format": "mapping", "entries": [["command", COMMAND]]});
    let mut package = json!({
        "artifact_id": artifact(workspace).artifact_id,
        "artifact_hash": PACKAGE_HASH,
        "workspace": workspace.to_str().unwrap(),
        "path": PATH,
        "evaluation": {"reasons": []},
        "evidence": [{"source": "execution_context", "cwd": "/work"}],
        "signals": ["package-install"],
    });
    if outcome == "forward" {
        package["policy_workspace"] = json!("/work");
    }
    record["package"] = package;
    record
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
    let (args, row) = compose(HOME, record, &stamp()).expect("a plain package record composes");
    assert!(row.is_none());
    args
}

const CENTER: &str = "http://127.0.0.1:4781";

/// A safe-alternative block whose record names the center its row links to.
fn reviewed(workspace: &Path) -> Value {
    edited(
        record(workspace, "block", "policy-safe-alternative", "review"),
        |record| {
            record["review"] = json!({"redaction_level": "full", "approval_center_url": CENTER})
        },
    )
}

fn edited(mut record: Value, edit: impl FnOnce(&mut Value)) -> Value {
    edit(&mut record);
    record
}

#[test]
fn a_forward_writes_the_allowed_receipt_against_the_package_artifact() {
    let workspace = temp_home("relay-package-forward");
    let expected = artifact(&workspace);
    let args = composed(&record(&workspace, "forward", "policy-allow", "allow"));
    let receipt = &args["receipt"];
    assert_eq!(receipt["artifact_id"], expected.artifact_id);
    assert_eq!(receipt["artifact_hash"], PACKAGE_HASH);
    assert_eq!(receipt["artifact_name"], expected.name);
    assert_eq!(
        receipt["changed_capabilities"],
        json!(["runtime_tool_call", "policy-allow", "package-install"])
    );
    assert_eq!(
        receipt["provenance_summary"],
        "runtime tool call allowed from /work/.codex/config.toml"
    );
    assert_eq!(receipt["approval_source"], "policy");
    assert_eq!(receipt["user_override"], Value::Null);
    // The proxy does not enrich a package request, so the firewall entry
    // carries no firewall evidence, and the package evidence follows it.
    let evidence = receipt["scanner_evidence"].as_array().unwrap();
    assert!(evidence[0].get("mcpSkillFirewall").is_none());
    assert_eq!(
        evidence[1..],
        [json!({"source": "execution_context", "cwd": "/work"})]
    );
    let inventory = &args["inventory"];
    assert_eq!(inventory["artifact_type"], "package_request");
    assert_eq!(inventory["artifact_type"], json!(expected.artifact_type));
    assert_eq!(inventory["origin_url"], json!(expected.url));
    assert_eq!(inventory["approved"], true);
    assert_eq!(inventory["artifact_hash"], PACKAGE_HASH);
    assert_eq!(args["event_name"], "runtime_tool_call_allowed");
    let payload: Value =
        serde_json::from_str(args["event_payload_json"].as_str().unwrap()).unwrap();
    assert_eq!(
        payload,
        json!({
            "artifact_id": expected.artifact_id,
            "artifact_hash": PACKAGE_HASH,
            "decision_source": "policy-allow",
            "policy_action": "allow",
            "risk_categories": [],
            "signals": ["package-install"],
        })
    );
    let _ = std::fs::remove_dir_all(&workspace);
}

#[test]
fn a_policy_block_writes_the_not_executed_receipt() {
    let workspace = temp_home("relay-package-block");
    let args = composed(&record(&workspace, "block", "policy-block", "block"));
    assert_eq!(args["event_name"], "runtime_tool_call_blocked");
    assert_eq!(args["inventory"]["approved"], false);
    assert_eq!(
        args["receipt"]["provenance_summary"],
        "runtime tool call blocked from /work/.codex/config.toml"
    );
    let payload: Value =
        serde_json::from_str(args["event_payload_json"].as_str().unwrap()).unwrap();
    assert_eq!(payload["execution_outcome"], "not-executed");
    let _ = std::fs::remove_dir_all(&workspace);
}

#[test]
fn a_rebuilt_artifact_that_differs_drops_the_record() {
    let workspace = temp_home("relay-package-mismatch");
    let record = edited(
        record(&workspace, "forward", "policy-allow", "allow"),
        |record| record["package"]["artifact_id"] = json!("codex:project:package:other"),
    );
    assert!(is_plain(&record));
    assert!(compose(HOME, &record, &stamp()).is_none());
    let _ = std::fs::remove_dir_all(&workspace);
}

/// An ask block whose desktop notice the resident raised.
fn asked(workspace: &Path) -> Value {
    edited(
        record(workspace, "block", "approval-center-pending", "review"),
        |record| {
            record["approval"] = json!({
                "approval_center_url": "http://127.0.0.1:4781/approvals",
                "review_url": "http://127.0.0.1:4781/approvals/req-1",
                "request_id": "req-1",
                "workspace": "/work",
                "notices": [],
            });
        },
    )
}

#[test]
fn an_ask_block_writes_the_pending_receipt_without_risk_categories() {
    let workspace = temp_home("relay-package-ask");
    let expected = artifact(&workspace);
    let args = composed(&asked(&workspace));
    assert_eq!(args["event_name"], "runtime_tool_call_review_required");
    assert_eq!(
        args["receipt"]["provenance_summary"],
        "runtime tool call awaiting review from /work/.codex/config.toml"
    );
    let receipt = &args["receipt"];
    assert_eq!(receipt["artifact_id"], expected.artifact_id);
    assert_eq!(receipt["artifact_hash"], PACKAGE_HASH);
    assert_eq!(receipt["approval_source"], "approval_center");
    assert_eq!(receipt["user_override"], Value::Null);
    assert_eq!(
        receipt["changed_capabilities"],
        json!([
            "runtime_tool_call",
            "approval-center-pending",
            "package-install"
        ])
    );
    assert_eq!(args["inventory"]["approved"], false);
    let payload: Value =
        serde_json::from_str(args["event_payload_json"].as_str().unwrap()).unwrap();
    assert_eq!(payload["execution_outcome"], "not-executed");
    assert_eq!(payload["risk_categories"], json!([]));
    let _ = std::fs::remove_dir_all(&workspace);
}

#[test]
fn ask_blocks_the_daemon_still_surfaces_are_not_plain() {
    let workspace = temp_home("relay-package-ask-owned");
    let ask = asked(&workspace);
    assert!(is_plain(&ask));
    let cases = [
        // The browser approval flow still opens the approval center.
        edited(ask.clone(), |r| {
            r["harness"] = json!("cline");
            r["identity"]["artifact"]["harness"] = json!("cline");
        }),
        // A notice the resident could not raise is the daemon's to raise.
        edited(ask.clone(), |r| {
            r["approval"]["notices"] = json!([{"request_id": "req-1"}])
        }),
        edited(ask.clone(), |r| r["approval"]["request_id"] = json!(" ")),
        edited(ask.clone(), |r| r["approval"]["extra"] = json!(true)),
        // An ask block is recorded as pending, and only a block is queued.
        edited(ask.clone(), |r| {
            r["decision_source"] = json!("policy-block")
        }),
        edited(ask.clone(), |r| {
            r["outcome"] = json!("forward");
            r["decision_source"] = json!("policy-allow");
            r["policy_action"] = json!("allow");
            r["package"]["policy_workspace"] = json!("/work");
        }),
        edited(ask, |r| r["review"] = json!({"redaction_level": "full"})),
    ];
    for case in cases {
        assert!(!is_plain(&case), "{case}");
    }
    let _ = std::fs::remove_dir_all(&workspace);
}

/// An observed forward whose notices the resident raised.
fn observed(workspace: &Path) -> Value {
    edited(
        record(workspace, "forward", "policy-observe", "allow"),
        |record| record["observed"] = json!({"notices": []}),
    )
}

#[test]
fn an_observed_forward_writes_the_allowed_receipt_under_the_mode() {
    let workspace = temp_home("relay-package-observed");
    let expected = artifact(&workspace);
    let args = composed(&observed(&workspace));
    assert_eq!(args["event_name"], "runtime_tool_call_allowed");
    let receipt = &args["receipt"];
    assert_eq!(receipt["artifact_id"], expected.artifact_id);
    assert_eq!(receipt["approval_source"], "policy");
    assert_eq!(
        receipt["changed_capabilities"],
        json!(["runtime_tool_call", "policy-observe", "package-install"])
    );
    assert_eq!(args["inventory"]["approved"], true);
    let payload: Value =
        serde_json::from_str(args["event_payload_json"].as_str().unwrap()).unwrap();
    assert_eq!(payload["decision_source"], "policy-observe");
    assert_eq!(payload["risk_categories"], json!([]));
    let _ = std::fs::remove_dir_all(&workspace);
}

#[test]
fn observed_forwards_the_daemon_still_surfaces_are_not_plain() {
    let workspace = temp_home("relay-package-observed-owned");
    let forward = observed(&workspace);
    assert!(is_plain(&forward));
    let cases = [
        edited(forward.clone(), |r| r["observed"] = json!({})),
        edited(forward.clone(), |r| {
            r["observed"] = json!({"notices": [], "extra": true})
        }),
        // An observed forward is recorded under the mode, and is a forward.
        edited(forward.clone(), |r| {
            r["decision_source"] = json!("policy-allow")
        }),
        edited(forward.clone(), |r| {
            r["outcome"] = json!("block");
            r["decision_source"] = json!("policy-block");
            r["policy_action"] = json!("block");
            r["package"]
                .as_object_mut()
                .unwrap()
                .remove("policy_workspace");
        }),
        edited(forward, |r| {
            r["approval"] = json!({
                "approval_center_url": "http://127.0.0.1:4781/approvals",
                "review_url": "http://127.0.0.1:4781/approvals/req-1",
                "request_id": "req-1",
                "workspace": "/work",
                "notices": [],
            })
        }),
    ];
    for case in cases {
        assert!(!is_plain(&case), "{case}");
    }
    let _ = std::fs::remove_dir_all(&workspace);
}

#[test]
fn package_records_the_daemon_owns_are_not_plain() {
    let workspace = temp_home("relay-package-owned");
    let forward = record(&workspace, "forward", "policy-allow", "allow");
    let block = record(&workspace, "block", "policy-block", "block");
    assert!(is_plain(&forward));
    assert!(is_plain(&block));
    let cases = [
        // An observed forward still carrying notices raises them.
        edited(forward.clone(), |r| {
            r["decision_source"] = json!("policy-observe");
            r["observed"] = json!({"notices": [{"request_id": "req-1"}]});
        }),
        edited(forward.clone(), |r| {
            r["decision_source"] = json!("policy-warn")
        }),
        // A queued request from a binding with no center still writes its
        // inbox row, and an ask block still raises its approval surface.
        edited(block.clone(), |r| {
            r["decision_source"] = json!("policy-safe-alternative");
            r["policy_action"] = json!("review");
            r["review"] = json!({"redaction_level": "full"});
        }),
        edited(block.clone(), |r| {
            r["decision_source"] = json!("approval-center-pending");
            r["policy_action"] = json!("review");
        }),
        edited(block.clone(), |r| {
            r["decision_source"] = json!("inline-denied")
        }),
        // Only a forward binds the policy workspace, and it must.
        edited(block.clone(), |r| {
            r["package"]["policy_workspace"] = json!("/work")
        }),
        edited(forward.clone(), |r| {
            r["package"]
                .as_object_mut()
                .unwrap()
                .remove("policy_workspace");
        }),
        edited(forward.clone(), |r| r["package"]["path"] = json!("  ")),
        edited(forward.clone(), |r| r["package"]["workspace"] = json!("")),
        edited(forward.clone(), |r| r["package"]["signals"] = json!([1])),
        edited(forward.clone(), |r| r["package"]["evidence"] = json!(["x"])),
        edited(forward.clone(), |r| r["package"]["extra"] = json!(true)),
        edited(forward.clone(), |r| {
            r.as_object_mut().unwrap().remove("package");
        }),
        edited(forward.clone(), |r| r["kind"] = json!("mcp_tool_call")),
        edited(forward, |r| r["harness"] = json!("claude-code")),
    ];
    for case in cases {
        assert!(!is_plain(&case), "{case}");
    }
    let _ = std::fs::remove_dir_all(&workspace);
}

#[test]
fn plain_package_records_land_in_the_store() {
    let (receipts, inventory) = vectors();
    let home = temp_home("relay-package-store");
    let workspace = temp_home("relay-package-store-ws");
    build_database(&home.join("guard.db"), &receipts, &inventory);
    let before = count(&home, "runtime_receipts");
    let unwritten = write(
        home.to_str().unwrap(),
        vec![
            record(&workspace, "forward", "policy-allow", "allow"),
            record(&workspace, "block", "policy-block", "block"),
        ],
    );
    assert!(unwritten.is_empty(), "{unwritten:?}");
    assert_eq!(count(&home, "runtime_receipts"), before + 2);
    assert_eq!(count(&home, "guard_events"), 2);
    let _ = std::fs::remove_dir_all(&home);
    let _ = std::fs::remove_dir_all(&workspace);
}

#[test]
fn a_safe_alternative_block_writes_its_receipt_then_a_silent_row() {
    let workspace = temp_home("relay-package-safe-alternative");
    let expected = artifact(&workspace);
    let (args, row) =
        compose(HOME, &reviewed(&workspace), &stamp()).expect("a plain package record composes");
    assert_eq!(args["event_name"], "runtime_tool_call_review_required");
    let receipt = &args["receipt"];
    assert_eq!(receipt["artifact_id"], expected.artifact_id);
    assert_eq!(receipt["artifact_hash"], PACKAGE_HASH);
    assert_eq!(
        receipt["changed_capabilities"],
        json!([
            "runtime_tool_call",
            "policy-safe-alternative",
            "package-install"
        ])
    );
    assert_eq!(args["inventory"]["approved"], false);
    // Projected with the artifact, so the receipt records its risk categories.
    let payload: Value =
        serde_json::from_str(args["event_payload_json"].as_str().unwrap()).unwrap();
    assert!(payload["risk_categories"].is_array());
    let row = row.expect("a safe-alternative block adds a row");
    assert_eq!(row["harness"], "codex");
    assert_eq!(row["prompt_shown"], false);
    assert_eq!(row["redaction_level"], "full");
    assert_eq!(row["now"], stamp().now);
    assert_eq!(row["approval_center_url"], CENTER);
    let item = &row["items"][0];
    assert_eq!(item["artifact_id"], expected.artifact_id);
    assert_eq!(item["artifact_type"], "package_request");
    assert_eq!(item["artifact_hash"], PACKAGE_HASH);
    assert_eq!(item["policy_action"], "review");
    assert_eq!(item["risk_signals"], json!(["package-install"]));
    // The decision's evidence and the package's, without the firewall entry.
    let evidence = item["scanner_evidence"].as_array().unwrap();
    assert_eq!(
        evidence.last(),
        Some(&json!({"source": "execution_context", "cwd": "/work"}))
    );
    assert!(evidence
        .iter()
        .all(|entry| entry.get("mcpSkillFirewall").is_none()));
    let artifacts = row["artifacts"].as_object().unwrap();
    assert!(artifacts.contains_key(&expected.artifact_id));
    let _ = std::fs::remove_dir_all(&workspace);
}

#[test]
fn safe_alternative_blocks_the_daemon_still_writes_are_not_plain() {
    let workspace = temp_home("relay-package-safe-alternative-owned");
    let block = reviewed(&workspace);
    assert!(is_plain(&block));
    let cases = [
        // A binding with no center leaves the row to the daemon's origin.
        edited(block.clone(), |r| {
            r["review"] = json!({"redaction_level": "full"})
        }),
        edited(block.clone(), |r| {
            r["review"]["redaction_level"] = json!("secret")
        }),
        edited(block.clone(), |r| r["review"]["extra"] = json!(true)),
        // A safe-alternative block is recorded under its own source.
        edited(block.clone(), |r| {
            r["decision_source"] = json!("policy-block")
        }),
        edited(block.clone(), |r| r["observed"] = json!({"notices": []})),
        edited(block, |r| {
            r["outcome"] = json!("forward");
            r["decision_source"] = json!("policy-allow");
            r["policy_action"] = json!("allow");
            r["package"]["policy_workspace"] = json!("/work");
        }),
    ];
    for case in cases {
        assert!(!is_plain(&case), "{case}");
    }
    let _ = std::fs::remove_dir_all(&workspace);
}

#[test]
fn a_safe_alternative_block_that_is_not_reviewable_adds_no_row() {
    let workspace = temp_home("relay-package-safe-alternative-block");
    let block = edited(reviewed(&workspace), |r| {
        r["policy_action"] = json!("block")
    });
    let (_, row) = compose(HOME, &block, &stamp()).expect("a plain package record composes");
    assert!(row.is_none());
    let _ = std::fs::remove_dir_all(&workspace);
}
