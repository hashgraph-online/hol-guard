use std::collections::HashMap;

use serde_json::{json, Value};

use super::*;

struct Run {
    reply: Option<Option<Reply>>,
    seen: Vec<(String, Value)>,
}

fn drive(path: &str, steps: &[(&str, Value)]) -> Run {
    let by_name: HashMap<String, Value> = steps
        .iter()
        .map(|(name, answer)| ((*name).to_owned(), answer.clone()))
        .collect();
    let mut seen = Vec::new();
    let mut call = |name: &str, args: Value| {
        seen.push((name.to_owned(), args));
        by_name.get(name).cloned().ok_or(CallError::Unavailable)
    };
    let mut host = Host {
        call: &mut call,
        args: Map::new(),
    };
    let reply = route_post(path, &mut host);
    Run { reply, seen }
}

fn answered(run: Run) -> (u16, Value) {
    run.reply.flatten().unwrap_or_else(|| unreachable!())
}

fn facts(required: bool, repair: bool) -> Value {
    json!({
        "required": required,
        "repair": repair,
        "connect_url": "https://hol.example/guard/connect",
        "cloud_state": null,
        "package_state": null,
    })
}

fn opened() -> Value {
    json!({"session_id": "s1", "authorize_url": "https://hol.example/a", "browser_opened": true})
}

#[test]
fn cloud_connect_runs_the_flow_and_reports_it_running() {
    let run = drive(
        CLOUD_PATH,
        &[
            ("connect.facts", facts(true, false)),
            ("connect.begin", json!({"started": true})),
            ("connect.open", opened()),
            ("connect.run", json!({"running": true})),
        ],
    );
    let names: Vec<&str> = run.seen.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(
        names,
        [
            "connect.facts",
            "connect.begin",
            "connect.open",
            "connect.run"
        ]
    );
    let starting = &run.seen[1].1["state"];
    assert_eq!(starting["state"], "starting");
    assert_eq!(starting["purpose"], "insights_share");
    let request_id = starting["request_id"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(request_id.starts_with("guard-connect-") && request_id.len() == 46);
    assert_eq!(run.seen[3].1["session_id"], "s1");
    let (status, body) = answered(run);
    assert_eq!(status, 202);
    assert_eq!(body["connect_required"], true);
    let flow = &body["connect_flow"];
    assert_eq!(flow["state"], "running");
    assert_eq!(flow["action_label"], "Connect Guard Cloud");
    assert_eq!(flow["authorize_url"], "https://hol.example/a");
    assert_eq!(flow["request_id"], request_id.as_str());
    assert_eq!(flow["poll_after_ms"], 1500);
    assert!(flow["detail"]
        .as_str()
        .unwrap_or_default()
        .ends_with("unlock public sharing automatically."));
}

#[test]
fn cloud_connect_not_required_is_a_conflict() {
    let run = drive(CLOUD_PATH, &[("connect.facts", facts(false, false))]);
    let (status, body) = answered(run);
    assert_eq!(status, 409);
    assert_eq!(body["error"], "guard_cloud_connect_not_required");
    assert_eq!(body["dashboard_url"], "https://hol.example/guard");
    assert_eq!(body["connect_flow"], Value::Null);
}

#[test]
fn a_flow_in_flight_is_returned_unchanged() {
    let current = json!({"state": "running", "request_id": "guard-connect-x"});
    let run = drive(
        CLOUD_PATH,
        &[
            ("connect.facts", facts(true, true)),
            (
                "connect.begin",
                json!({"started": false, "current": current}),
            ),
        ],
    );
    assert_eq!(
        answered(run),
        (
            202,
            json!({"connect_required": true, "connect_flow": current})
        )
    );
}

#[test]
fn a_session_that_cannot_open_records_the_failure() {
    let run = drive(
        PACKAGE_FIREWALL_PATH,
        &[
            (
                "supply_chain.entitlement",
                json!({"reason": " Guard_Cloud_Reconnect_Required "}),
            ),
            ("connect.facts", facts(true, true)),
            ("connect.begin", json!({"started": true})),
            ("connect.open", json!({"error": "no browser"})),
            ("connect.set_state", json!({})),
        ],
    );
    assert_eq!(run.seen[1].1["reason"], "guard_cloud_reconnect_required");
    assert_eq!(run.seen[4].1["state"]["state"], "failed");
    let (status, body) = answered(run);
    assert_eq!(status, 500);
    assert_eq!(body["state"], "failed");
    assert_eq!(body["detail"], "no browser");
    assert_eq!(body["action_label"], "Repair Guard Cloud access");
    assert_eq!(body["browser_opened"], false);
    assert!(body.get("purpose").is_none());
}

#[test]
fn package_firewall_connect_needs_a_connect_reason() {
    let run = drive(
        PACKAGE_FIREWALL_PATH,
        &[("supply_chain.entitlement", json!({"reason": "allowed"}))],
    );
    let (status, body) = answered(run);
    assert_eq!(status, 409);
    assert_eq!(body["entitlement"]["reason"], "allowed");
}

#[test]
fn package_firewall_connect_runs_unwrapped() {
    let run = drive(
        PACKAGE_FIREWALL_PATH,
        &[
            (
                "supply_chain.entitlement",
                json!({"reason": "guard_cloud_connect_required"}),
            ),
            ("connect.facts", facts(true, false)),
            ("connect.begin", json!({"started": true})),
            (
                "connect.open",
                json!({"session_id": "s", "authorize_url": "u", "browser_opened": false}),
            ),
            ("connect.run", json!({"running": true})),
        ],
    );
    let (status, body) = answered(run);
    assert_eq!(status, 202);
    assert_eq!(body["state"], "running");
    assert_eq!(body["action_label"], "Connect HOL Guard Cloud");
    assert!(body["detail"]
        .as_str()
        .unwrap_or_default()
        .starts_with("HOL Guard is waiting"));
}

#[test]
fn an_unreachable_open_clears_the_flow_and_relays() {
    let run = drive(
        CLOUD_PATH,
        &[
            ("connect.facts", facts(true, false)),
            ("connect.begin", json!({"started": true})),
            ("connect.set_state", json!({})),
        ],
    );
    assert_eq!(
        run.seen.last().map(|(name, _)| name.as_str()),
        Some("connect.set_state")
    );
    assert_eq!(run.reply, Some(None));
    assert!(drive("/v1/cloud/other", &[]).reply.is_none());
}

#[test]
fn status_resolves_the_flow_in_flight() {
    let mut facts = facts(true, false);
    facts["package_state"] = json!({"state": "starting", "browser_opened": null});
    facts["cloud_state"] = json!({"state": "failed"});
    let flow = resolve_flow(facts.as_object().unwrap_or(&Map::new()));
    assert_eq!(flow["title"], "Finish Guard Cloud sign-in in your browser");
    assert_eq!(
        flow["detail"],
        "HOL Guard is opening the secure sign-in flow in your browser."
    );
    assert_eq!(flow["poll_after_ms"], 1500);
    facts["package_state"] = Value::Null;
    let flow = resolve_flow(facts.as_object().unwrap_or(&Map::new()));
    assert_eq!(flow["title"], "Guard Cloud sign-in needs attention");
    assert_eq!(flow["poll_after_ms"], Value::Null);
    facts["required"] = json!(false);
    assert!(resolve_flow(facts.as_object().unwrap_or(&Map::new())).is_null());
    let mut steps = HashMap::new();
    steps.insert("connect.facts".to_owned(), self::facts(true, true));
    let mut call = |name: &str, _: Value| steps.get(name).cloned().ok_or(CallError::Unavailable);
    let mut host = Host {
        call: &mut call,
        args: Map::new(),
    };
    let (status, body) = finish(status(&mut host)).unwrap_or_else(|| unreachable!());
    assert_eq!(status, 200);
    assert_eq!(body["connect_required"], true);
    assert_eq!(body["connect_flow"]["state"], "idle");
    assert_eq!(
        body["connect_flow"]["action_label"],
        "Repair Guard Cloud access"
    );
}
