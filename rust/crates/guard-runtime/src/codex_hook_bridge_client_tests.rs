//! The client modes the native Codex bridge serves itself: binding capture
//! in process and an unsendable query.

use super::*;
use crate::binding_capture_fs::initialize_marker;
use crate::binding_capture_json::{parse_object, Json};
use crate::binding_capture_op::now_seconds;

/// The fields daemon admission strips before the forwarded fingerprint.
const TRANSPORT_FIELDS: [&str; 3] = ["guard_remaining_seconds", "guard_remaining_ms", "hook_env"];
const PRE_TOOL: &str = r#"{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"Bash","tool_input":{"command":"ls"},"tool_use_id":"c1"}"#;

fn capture_rows(home: &GuardHome, run_id: &str) -> Vec<Value> {
    let path = home
        .home
        .join("diagnostics")
        .join(format!("codex-binding-capture.{run_id}.jsonl"));
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn a_binding_capture_records_the_forwarded_hook_once() {
    let answer = r#"{"hookSpecificOutput":{"permissionDecision":"allow"},"policy_action":"allow","receipt":"r"}"#;
    let (home, daemon) = codex_home(
        "codex-capture",
        vec![Exchange::Hook(200, answer.to_owned())],
    );
    let now = now_seconds();
    let session = initialize_marker(&home.home, "run-bridge", now as i64 + 300, None, None, now)
        .expect("capture marker");
    let (route, prepared) = route_hook(&config(&home), PRE_TOOL, Instant::now());
    assert_eq!(
        route,
        Route::Respond(r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse"}}"#.to_owned())
    );
    assert_eq!(prepared.unwrap().event_name, PRE_TOOL_USE);
    let hooks = daemon.join().unwrap();
    assert_eq!(hooks.len(), 1);
    let Some(Json::Obj(sent)) = parse_object(&hooks[0].body) else {
        panic!("the daemon body is an object");
    };
    let forwarded = Json::Obj(
        sent.into_iter()
            .filter(|(key, _)| !TRANSPORT_FIELDS.contains(&key.as_str()))
            .collect(),
    );
    let raw = parse_object(PRE_TOOL.as_bytes()).unwrap();
    let rows = capture_rows(&home, "run-bridge");
    let ingress: Vec<&Value> = rows
        .iter()
        .filter(|row| row["route"] == json!("bridge_ingress"))
        .collect();
    assert_eq!(ingress.len(), 1, "{rows:?}");
    assert_eq!(
        ingress[0]["forwarded_payload_hmac_sha256"].as_str(),
        session
            .payload_hmac("forwarded", &forwarded, now)
            .as_deref()
    );
    assert_eq!(
        ingress[0]["raw_payload_hmac_sha256"].as_str(),
        session.payload_hmac("raw", &raw, now).as_deref()
    );
}

#[test]
fn an_unusable_capture_marker_leaves_the_hook_native() {
    let home = GuardHome::new("codex-capture-broken");
    let diagnostics = home.home.join("diagnostics");
    std::fs::create_dir_all(&diagnostics).unwrap();
    std::os::unix::fs::symlink(
        "/nonexistent",
        diagnostics.join("codex-binding-capture.v2.json"),
    )
    .unwrap();
    // No daemon and no start command: the native path fails closed.
    let (route, prepared) = route_hook(&config(&home), STOP, Instant::now());
    assert_eq!(route, Route::Respond(fail_closed("Stop")));
    assert_eq!(prepared.unwrap().event_name, "Stop");
}

#[test]
fn an_unsendable_query_fails_closed_without_a_start() {
    let home = GuardHome::new("codex-unsendable");
    let marker = home.scratch("started");
    let mut bridge = config(&home);
    bridge.query = "a b".to_owned();
    bridge.start_command = shell(&format!(": > '{}'", marker.display()));
    let (route, prepared) = route_hook(&bridge, STOP, Instant::now());
    assert_eq!(route, Route::Respond(fail_closed("Stop")));
    assert_eq!(prepared.unwrap().event_name, "Stop");
    assert!(!marker.exists());
}
