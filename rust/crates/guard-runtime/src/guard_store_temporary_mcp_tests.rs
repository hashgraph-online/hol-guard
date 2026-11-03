//! The native temporary MCP grant over the recorded approval schema: which
//! pending requests a grant answers, which it has to leave alone, and what it
//! refuses to write at all. Rows come from the recorded queue-result vectors;
//! only the fields the sweep reads are replaced.

use std::collections::BTreeMap;
use std::path::Path;

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_approval_reads::tests::{seed, store_call};
use crate::guard_store_cmd_vectors_tests::temp_home;

const VECTORS: &str = include_str!("../testdata/guard_store/approval_queue_result_vectors.json");
const RESOLVED_AT: &str = "2026-03-02T10:00:00+00:00";
const EXPIRES_AT: &str = "2026-03-02T11:00:00+00:00";
const SERVER: &str = "srv-1";
const CATEGORY: &str = "browser_navigation";
const REASON: &str = "routine browser capability";

/// A stored decision that agrees with a terminal policy action.
const BLOCK_DECISION: &str = r#"{"action": "block", "approval_scopes": [], "confidence": "likely", "guard_action": "block", "reason": "block", "signals": [], "user_title": "Blocked"}"#;

/// A stored browser intent for one server and one routine category.
fn browser_intent(server: &str, intent: &str, category: &str) -> String {
    json!({
        "mcp_server_identity_hash": server,
        "mcp_server_name": "browser",
        "intent": intent,
        "risk_categories": [category],
    })
    .to_string()
}

/// The pending requests one grant has to tell apart: the request that asked
/// for it, the same capability again, another category, another server,
/// another harness, and one whose policy action no approval can lift.
fn requests() -> [(&'static str, &'static str, &'static str, String); 6] {
    let navigation = || browser_intent(SERVER, "browser.navigation", CATEGORY);
    [
        ("g-source", "codex", "require-reapproval", navigation()),
        ("g-same", "codex", "require-reapproval", navigation()),
        (
            "g-other-category",
            "codex",
            "require-reapproval",
            browser_intent(SERVER, "browser.inspect", "browser_inspection"),
        ),
        (
            "g-other-server",
            "codex",
            "require-reapproval",
            browser_intent("srv-2", "browser.navigation", CATEGORY),
        ),
        ("g-claude", "claude", "require-reapproval", navigation()),
        ("g-block", "codex", "block", navigation()),
    ]
}

/// The recorded `single` scenario with this module's rows in place of its own.
/// Each request keeps its own queue group, so nothing is resolved as a
/// duplicate of the request the grant settles.
fn scenario(vectors: &Value) -> Value {
    let recorded = vectors["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|scenario| scenario["name"] == "single")
        .unwrap();
    let template = recorded["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["request_id"] == "r-ok")
        .unwrap()
        .as_object()
        .unwrap();
    let rows: Vec<Value> = requests()
        .into_iter()
        .map(|(request_id, harness, policy_action, intent)| {
            let mut row = template.clone();
            row.insert("request_id".to_owned(), json!(request_id));
            row.insert("harness".to_owned(), json!(harness));
            row.insert("policy_action".to_owned(), json!(policy_action));
            row.insert(
                "queue_group_id".to_owned(),
                json!(format!("qg-{request_id}")),
            );
            row.insert("browser_intent_json".to_owned(), json!(intent));
            // The recorded decision states `require-reapproval`. A row whose
            // policy action is terminal needs a decision that says so too, or
            // the projection reports a contract inconsistency instead of the
            // terminal action the sweep is being asked about.
            if policy_action == "block" {
                row.insert("decision_v2_json".to_owned(), json!(BLOCK_DECISION));
            }
            Value::Object(row)
        })
        .collect();
    json!({"name": "temporary-mcp", "rows": rows})
}

/// A seeded store with those requests pending.
fn store(label: &str) -> std::path::PathBuf {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let home = temp_home(&format!("temporary-mcp-{label}"));
    seed(&home.join("guard.db"), &vectors, &scenario(&vectors));
    home
}

/// One grant call, as `apply_temporary_mcp_grant_resolution` receives it.
fn grant(home: &Path, request_id: &str, target: &str) -> Result<Value, (String, String)> {
    store_call(
        home,
        "guard",
        "apply_temporary_mcp_grant_resolution",
        json!({
            "request_id": request_id,
            "resolved_at": RESOLVED_AT,
            "reason": REASON,
            "grant_target": target,
            "grant_server_identity_hash": SERVER,
            "grant_category": CATEGORY,
            "decision": {
                "harness": "codex",
                "scope": "artifact",
                "action": "allow",
                "source": "approval-gate",
                "artifact_id": format!("mcp-temporary-grant:v1:{SERVER}:{target}"),
                "reason": REASON,
                "expires_at": EXPIRES_AT,
            },
        }),
    )
}

fn covered(reply: &Value) -> Vec<String> {
    let mut ids: Vec<String> = reply["covered_request_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| id.as_str().unwrap().to_owned())
        .collect();
    ids.sort();
    ids
}

fn statuses(home: &Path) -> BTreeMap<String, String> {
    let connection = Connection::open(home.join("guard.db")).unwrap();
    let mut statement = connection
        .prepare("select request_id, status from approval_requests")
        .unwrap();
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .unwrap();
    rows.collect::<Result<_, _>>().unwrap()
}

fn pending(home: &Path) -> Vec<String> {
    let mut ids: Vec<String> = statuses(home)
        .into_iter()
        .filter(|(_, status)| status == "pending")
        .map(|(request_id, _)| request_id)
        .collect();
    ids.sort();
    ids
}

fn granted_selectors(home: &Path) -> Vec<String> {
    let connection = Connection::open(home.join("guard.db")).unwrap();
    let mut statement = connection
        .prepare("select artifact_id from policy_decisions order by artifact_id")
        .unwrap();
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap();
    rows.collect::<Result<_, _>>().unwrap()
}

#[test]
fn an_exact_grant_settles_only_the_request_that_asked_for_it() {
    let home = store("exact");
    let reply = grant(&home, "g-source", "exact").unwrap();
    assert_eq!(reply["result"]["resolved"], json!(true));
    assert_eq!(covered(&reply), Vec::<String>::new());
    assert_eq!(
        pending(&home),
        [
            "g-block",
            "g-claude",
            "g-other-category",
            "g-other-server",
            "g-same"
        ]
    );
    assert_eq!(
        granted_selectors(&home),
        [format!("mcp-temporary-grant:v1:{SERVER}:exact")]
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_server_grant_settles_every_routine_request_for_that_server() {
    let home = store("server");
    let reply = grant(&home, "g-source", "server").unwrap();
    assert_eq!(reply["result"]["resolved"], json!(true));
    assert_eq!(covered(&reply), ["g-other-category", "g-same"]);
    // Another server, another harness and a terminal policy action are not
    // this grant's to answer.
    assert_eq!(pending(&home), ["g-block", "g-claude", "g-other-server"]);
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_category_grant_leaves_the_server_s_other_categories_pending() {
    let home = store("category");
    let reply = grant(&home, "g-source", "category").unwrap();
    assert_eq!(covered(&reply), ["g-same"]);
    assert_eq!(
        pending(&home),
        ["g-block", "g-claude", "g-other-category", "g-other-server"]
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_terminal_request_is_refused_before_anything_is_written() {
    let home = store("blocked");
    let reply = grant(&home, "g-block", "server").unwrap();
    assert_eq!(
        reply,
        json!({"blocked": "terminal_policy_action_not_resolvable"})
    );
    assert_eq!(granted_selectors(&home), Vec::<String>::new());
    assert_eq!(
        pending(&home),
        [
            "g-block",
            "g-claude",
            "g-other-category",
            "g-other-server",
            "g-same",
            "g-source"
        ]
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_caller_cannot_choose_the_time_the_grant_is_written_at() {
    let home = store("reserved");
    let reply = store_call(
        &home,
        "guard",
        "apply_temporary_mcp_grant_resolution",
        json!({
            "request_id": "g-source",
            "resolved_at": RESOLVED_AT,
            "grant_target": "exact",
            "grant_server_identity_hash": SERVER,
            "grant_category": CATEGORY,
            "decision": {
                "harness": "codex",
                "scope": "artifact",
                "action": "allow",
                "source": "approval-gate",
                "artifact_id": "mcp-temporary-grant:v1:exact",
                "now": "1999-01-01T00:00:00+00:00",
            },
        }),
    );
    assert!(reply.is_err(), "{reply:?}");
    assert_eq!(granted_selectors(&home), Vec::<String>::new());
    let _ = std::fs::remove_dir_all(&home);
}
