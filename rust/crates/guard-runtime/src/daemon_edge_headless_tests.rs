use std::collections::HashMap;

use serde_json::{json, Value};

use super::*;

type Read = (u16, Value, bool);

struct Run {
    reply: Option<Reply>,
    seen: Vec<(String, Value)>,
}

fn host_run(
    steps: &[(&str, Value)],
    drive: impl FnOnce(&mut Host<'_, '_>) -> Option<Reply>,
) -> Run {
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
    let reply = drive(&mut host);
    Run { reply, seen }
}

fn app(action: &str, payload: Value, steps: &[(&str, Value)]) -> Run {
    let payload = payload.as_object().cloned().unwrap_or_default();
    host_run(steps, |host| finish(app_action(host, action, &payload)))
}

fn read(path: &str, query: &str, steps: &[(&str, Value)]) -> (Option<Read>, Vec<(String, Value)>) {
    let mut out = None;
    let run = host_run(steps, |host| {
        out = route_get(path, query, host).flatten();
        None
    });
    (out, run.seen)
}

fn completed() -> Value {
    json!({
        "harness": "codex",
        "result": {"managed_install": {"active": true}},
        "receipt": {"id": "r1", "operation": "install", "status": "ok", "timestamp": "t", "extra": 1},
        "cloud_sync": {"status": "queued"},
        "location_id": " loc ",
        "reconnect": {
            "latest_cloud_sync": {"synced_at": "s"},
            "last_runtime_sync_at": "rt",
            "local_guard_online_at": null,
            "daemon_id": "d",
            "daemon_version": "9.9",
            "hostname": "h",
        },
    })
}

#[test]
fn a_connect_reports_the_protected_state_and_reconnect() {
    let run = app(
        "connect",
        json!({"harness": " codex "}),
        &[("headless.app_action", completed())],
    );
    assert_eq!(run.seen[0].1["operation"], "install");
    assert_eq!(run.seen[0].1["harness_action"], "install");
    assert_eq!(run.seen[0].1["harness"], "codex");
    let (status, body) = run.reply.unwrap_or_else(|| unreachable!());
    assert_eq!(status, 200);
    assert_eq!(body["status"], "completed");
    assert_eq!(body["state"]["app_status"], "protected");
    assert_eq!(body["state"]["outcome"], "app_connected");
    assert_eq!(
        body["state"]["receipt_summary"],
        json!({"id": "r1", "operation": "install", "status": "ok", "timestamp": "t"})
    );
    let reconnect = &body["reconnect"];
    assert_eq!(reconnect["reconciliation_status"], "queued");
    assert_eq!(reconnect["location_id"], "loc");
    assert_eq!(reconnect["freshness"]["last_receipt_sync_at"], "s");
    assert_eq!(reconnect["freshness"]["local_guard_online_at"], Value::Null);
    assert_eq!(reconnect["local_identity"]["daemon_version"], "9.9");
    let id = reconnect["correlation_id"].as_str().unwrap_or_default();
    assert_eq!(id.len(), 36);
    assert_eq!(&id[14..15], "4");
}

#[test]
fn app_refusals_name_their_codes() {
    let run = app("explode", json!({}), &[]);
    let (status, body) = run.reply.unwrap_or_else(|| unreachable!());
    assert_eq!(status, 400);
    assert_eq!(body["error"]["code"], "unsupported_operation");
    let run = app("connect", json!({"harness": " "}), &[]);
    assert_eq!(
        run.reply.unwrap_or_else(|| unreachable!()).1["error"]["code"],
        "missing_harness"
    );
    let run = app(
        "disconnect",
        json!({"harness": "x"}),
        &[("headless.app_action", json!({"error": "unknown_harness"}))],
    );
    assert_eq!(run.reply.unwrap_or_else(|| unreachable!()).0, 404);
    let run = app(
        "disconnect",
        json!({"harness": "x"}),
        &[("headless.app_action", json!({"error": "boom"}))],
    );
    assert_eq!(
        run.reply.unwrap_or_else(|| unreachable!()).1["error"]["code"],
        "remove_failed"
    );
    let run = app(
        "status",
        json!({"harness": "cursor", "surface": " web "}),
        &[(
            "headless.app_action",
            json!({"error": "invalid_cursor_surface"}),
        )],
    );
    let (status, body) = run.reply.unwrap_or_else(|| unreachable!());
    assert_eq!(status, 400);
    assert_eq!(body["error"]["surface"], "web");
    let run = app(
        "disconnect",
        json!({"harness": "x"}),
        &[(
            "headless.app_action",
            json!({"reply": [428, {"error": "approval_gate_required"}]}),
        )],
    );
    assert_eq!(
        run.reply,
        Some((428, json!({"error": "approval_gate_required"})))
    );
    assert!(app("connect", json!({"harness": "x"}), &[]).reply.is_none());
}

#[test]
fn runtime_merges_the_snapshot_and_operator_health() {
    let snapshot = json!({
        "snapshot": {"items": []},
        "security_level": "balanced",
        "scheduler": {"queued": 2, "queued_limit": 8, "active": 1, "active_limit": 4, "oldest_queued_ms": 7},
        "evidence_writer": {"started": true, "running": true},
        "activity": {"persistence_error_count": 0, "last_error_code": null},
    });
    let (reply, seen) = read(
        RUNTIME_PATH,
        "include_receipts=false&active_request_id=+r+",
        &[("runtime.snapshot", snapshot.clone())],
    );
    assert_eq!(seen[0].1["include_receipts"], false);
    assert_eq!(seen[0].1["include_items"], true);
    assert_eq!(seen[0].1["active_request_id"], "r");
    let (status, body, no_store) = reply.unwrap_or_else(|| unreachable!());
    assert_eq!((status, no_store), (200, false));
    assert_eq!(body["security_level"], "balanced");
    // The edge's own scheduler replaces the snapshot's, so the load figures
    // are checked on the health verdict directly.
    assert!(body["operator_health"]["workers_configured"].is_number());
    let health = operator_health(snapshot.as_object().unwrap_or_else(|| unreachable!()));
    assert_eq!(health["state"], "backlogged");
    assert_eq!(health["workers_ready"], 3);
    assert_eq!(health["oldest_wait_ms"], 7);
    let mut stopped = snapshot.clone();
    stopped["evidence_writer"]["running"] = json!(false);
    let (reply, _) = read(RUNTIME_PATH, "", &[("runtime.snapshot", stopped)]);
    let body = reply.unwrap_or_else(|| unreachable!()).1;
    assert_eq!(body["operator_health"]["state"], "saturated");
    assert_eq!(body["operator_health"]["repairable"], true);
    let mut busy = snapshot;
    busy["activity"] = json!({"persistence_error_count": 1, "last_error_code": "sqlite.busy"});
    busy["evidence_writer"] = json!({"started": false, "running": false});
    let (reply, _) = read(RUNTIME_PATH, "", &[("runtime.snapshot", busy)]);
    assert_eq!(
        reply.unwrap_or_else(|| unreachable!()).1["operator_health"]["state"],
        "store-contended"
    );
}

#[test]
fn local_clis_validate_the_identity_filter() {
    let identity = "a".repeat(64);
    let (reply, seen) = read(
        LOCAL_CLIS_PATH,
        &format!("identity={identity}"),
        &[("local_clis.list", json!({"payload": {"items": []}}))],
    );
    assert_eq!(seen[0].1["identity"], identity.as_str());
    assert_eq!(reply, Some((200, json!({"items": []}), true)));
    for bad in [
        "identity=",
        "identity=ABC",
        &format!("identity={identity}&identity={identity}"),
    ] {
        let (reply, seen) = read(LOCAL_CLIS_PATH, bad, &[]);
        assert!(seen.is_empty());
        assert_eq!(
            reply.unwrap_or_else(|| unreachable!()).1["error"],
            "invalid_identity"
        );
    }
    let (reply, _) = read(
        LOCAL_CLIS_PATH,
        "",
        &[("local_clis.list", json!({"payload": null}))],
    );
    assert_eq!(reply.unwrap_or_else(|| unreachable!()).0, 500);
    let (reply, _) = read("/v1/other", "", &[]);
    assert!(reply.is_none());
}
