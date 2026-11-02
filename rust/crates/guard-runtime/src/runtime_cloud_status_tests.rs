use serde_json::{json, Value};

use super::*;

// 2026-01-02T00:00:00Z
const NOW: i64 = 1_767_312_000_000_000;

fn args() -> Value {
    json!({
        "connect_state": null,
        "cloud_state": "paired_active",
        "sync_configured": true,
        "oauth_repair_required": false,
        "connect_retry_required": false,
        "connect_retry_refresh_race": false,
        "shared_proof_recorded": true,
        "pending_events": 0,
        "event_summary": {},
        "synced_at": [],
        "policy_ack": {
            "acknowledgement": {},
            "bundle_hash": null,
            "bundle_version": null,
            "device_id": null,
        },
        "sync_url": null,
    })
}

fn status(args: &Value) -> Value {
    dispatch_at(args, NOW).unwrap()
}

fn proof_state(connect_state: Value) -> Value {
    let mut args = args();
    args["connect_state"] = connect_state;
    status(&args)["proof_status"].clone()
}

#[test]
fn proof_status_follows_the_connect_state() {
    let cases = [
        (json!({"status": "retry_required"}), "stalled"),
        (json!({"milestone": "first_sync_failed"}), "failed"),
        (
            json!({"milestone": "first_sync_pending", "status": "expired"}),
            "pending",
        ),
        (json!({"status": "expired"}), "expired"),
        (json!({"milestone": "waiting_for_browser"}), "waiting"),
        (json!({"status": "waiting"}), "waiting"),
        (json!({"milestone": "first_sync_succeeded"}), "synced"),
        (
            json!({"proof": {"first_synced_at": "2026-01-01"}}),
            "synced",
        ),
        (json!({"proof": {"first_synced_at": ""}}), "not_connected"),
        (
            json!({"milestone": "sync_not_available"}),
            "sync_unavailable",
        ),
        (json!({"status": "", "milestone": 1}), "not_connected"),
    ];
    for (mut state, expected) in cases {
        if expected == "stalled" {
            state["reason"] = json!("Refresh token ALREADY CONSUMED by another device");
        }
        assert_eq!(proof_state(state.clone())["state"], expected, "{state}");
    }
    let pending = proof_state(json!({"milestone": "first_sync_pending", "request_id": "r1"}));
    assert_eq!(
        pending,
        json!({
            "state": "pending",
            "label": "First proof pending",
            "detail": "Browser sign-in finished. Local Guard will retry the first proof sync \
                       automatically while the daemon is running, or you can run hol-guard sync now.",
            "request_id": "r1",
        })
    );
    assert_eq!(
        proof_state(Value::Null),
        json!({
            "state": "not_connected",
            "label": "Cloud proof not started",
            "detail": "Connect Guard Cloud to sync this device proof.",
            "request_id": null,
        })
    );
    assert_eq!(
        proof_state(json!({"status": "retry_required", "reason": "already consumed"}))["detail"],
        REFRESH_RACE_PROOF_DETAIL
    );
}

#[test]
fn cloud_state_copy_puts_repair_first() {
    let mut args = args();
    let result = status(&args);
    assert_eq!(result["cloud_state_label"], "Connected");
    assert!(result["cloud_state_detail"]
        .as_str()
        .unwrap()
        .starts_with("This machine is connected to Guard Cloud. Open Home"));
    args["connect_retry_required"] = json!(true);
    assert!(status(&args)["cloud_state_detail"]
        .as_str()
        .unwrap()
        .contains("before shared proof can resume"));
    args["shared_proof_recorded"] = json!(false);
    assert!(status(&args)["cloud_state_detail"]
        .as_str()
        .unwrap()
        .contains("before the first shared proof can land"));
    args["connect_retry_refresh_race"] = json!(true);
    assert!(status(&args)["cloud_state_detail"]
        .as_str()
        .unwrap()
        .ends_with("Run hol-guard connect once when you want shared proof restored."));
    args["oauth_repair_required"] = json!(true);
    args["cloud_state"] = json!("local_only");
    let result = status(&args);
    assert_eq!(result["cloud_state_label"], "Local only");
    assert!(result["cloud_state_detail"]
        .as_str()
        .unwrap()
        .starts_with("Guard Cloud sign-in on this machine is incomplete."));
}

fn health(update: impl FnOnce(&mut Value)) -> Value {
    let mut args = args();
    update(&mut args);
    status(&args)["cloud_sync_health"].clone()
}

#[test]
fn sync_health_states_follow_python_precedence() {
    assert_eq!(health(|_| {})["state"], "healthy");
    assert_eq!(
        health(|a| {
            a["connect_retry_required"] = json!(true);
            a["sync_configured"] = json!(false);
        })["state"],
        "failed"
    );
    assert_eq!(
        health(|a| a["sync_configured"] = json!(false))["state"],
        "disabled"
    );
    assert_eq!(
        health(|a| a["event_summary"] = json!({"status": "failed", "sync_skipped": true}))["state"],
        "failed"
    );
    let skipped = json!({"sync_skipped": true, "sync_reason": "guard_events_endpoint_unavailable"});
    assert_eq!(
        health(|a| a["event_summary"] = skipped)["state"],
        "degraded"
    );
    let truthy = json!({"sync_skipped": 1, "sync_reason": "guard_events_endpoint_unavailable"});
    assert_eq!(health(|a| a["event_summary"] = truthy)["state"], "healthy");
    let stale = health(|a| {
        a["synced_at"] = json!(["2025-12-30T00:00:00Z"]);
        a["pending_events"] = json!(3);
    });
    assert_eq!(stale["state"], "stale");
    assert_eq!(stale["last_synced_at"], "2025-12-30T00:00:00Z");
    let pending = health(|a| {
        a["synced_at"] = json!(["2026-01-01T12:00:00Z"]);
        a["pending_events"] = json!(3);
        a["event_summary"] = json!({"next_retry_after": "later"});
    });
    assert_eq!(
        pending,
        json!({
            "state": "pending",
            "label": "Cloud sync pending",
            "detail": "3 local proof events are queued for the next Cloud sync.",
            "pending_events": 3,
            "last_synced_at": "2026-01-01T12:00:00Z",
            "next_retry_after": "later",
        })
    );
    let waiting = health(|a| a["cloud_state"] = json!("paired_waiting"));
    assert_eq!(
        waiting["detail"],
        "Waiting for the first shared Cloud proof from this machine."
    );
    let one = health(|a| a["pending_events"] = json!(1));
    assert_eq!(
        one["detail"],
        "One local proof event is queued for the next Cloud sync."
    );
}

#[test]
fn failed_sync_detail_names_the_repair() {
    let race = health(|a| {
        a["connect_retry_required"] = json!(true);
        a["connect_retry_refresh_race"] = json!(true);
    });
    assert!(race["detail"]
        .as_str()
        .unwrap()
        .ends_with("to mint a fresh Cloud refresh token."));
    let oauth = health(|a| a["oauth_repair_required"] = json!(true));
    assert!(oauth["detail"]
        .as_str()
        .unwrap()
        .starts_with("Guard Cloud authorization on this machine needs repair."));
    let upload = health(|a| a["event_summary"] = json!({"status": "failed"}));
    assert!(upload["detail"]
        .as_str()
        .unwrap()
        .starts_with("Guard Cloud did not accept the last upload."));
}

#[test]
fn latest_timestamp_compares_instants_and_keeps_the_first_tie() {
    let values = json!([
        "2026-01-01T10:00:00+02:00",
        "  ",
        "not a time",
        5,
        "2026-01-01T08:00:00Z",
        "2026-01-01T08:00:00",
        "2026-01-01T07:30:00Z",
    ]);
    let latest = latest_sync_timestamp(values.as_array().unwrap());
    assert_eq!(
        latest.map(|(_, value)| value),
        Some("2026-01-01T10:00:00+02:00")
    );
    assert_eq!(latest_sync_timestamp(&[json!("x"), Value::Null]), None);
}

fn acknowledged() -> Value {
    let mut args = args();
    args["policy_ack"] = json!({
        "acknowledgement": {
            "bundleHash": "hash-1",
            "bundleVersion": "7",
            "deviceId": "device-1",
            "status": "synced",
            "appliedAt": "2026-01-01T12:00:00Z",
        },
        "bundle_hash": "hash-1",
        "bundle_version": "7",
        "device_id": "device-1",
    });
    args
}

fn last_ack_at(args: &Value) -> Value {
    status(args)["cloud_policy_last_ack_at"].clone()
}

#[test]
fn policy_ack_time_needs_this_device_and_the_current_bundle() {
    assert_eq!(last_ack_at(&args()), Value::Null);
    assert_eq!(last_ack_at(&acknowledged()), "2026-01-01T12:00:00Z");
    for (key, value) in [
        ("bundleHash", json!("hash-2")),
        ("bundleVersion", json!(7)),
        ("deviceId", json!("device-2")),
        ("status", json!("pending")),
        ("appliedAt", json!("")),
        ("appliedAt", json!("not a time")),
    ] {
        let mut args = acknowledged();
        args["policy_ack"]["acknowledgement"][key] = value;
        assert_eq!(last_ack_at(&args), Value::Null, "{key}");
    }
    for key in ["bundle_hash", "bundle_version", "device_id"] {
        let mut args = acknowledged();
        args["policy_ack"][key] = Value::Null;
        assert_eq!(last_ack_at(&args), Value::Null, "{key}");
    }
    let mut empty_hash = acknowledged();
    empty_hash["policy_ack"]["bundle_hash"] = json!("");
    empty_hash["policy_ack"]["acknowledgement"]["bundleHash"] = json!("");
    assert_eq!(last_ack_at(&empty_hash), Value::Null);
    // A naive time is read as UTC, as Python's `fromisoformat` accepts it.
    let mut naive = acknowledged();
    naive["policy_ack"]["acknowledgement"]["appliedAt"] = json!("2026-01-01T12:00:00");
    assert_eq!(last_ack_at(&naive), "2026-01-01T12:00:00");
}

#[test]
fn guard_pages_follow_the_sync_origin() {
    let defaults = status(&args());
    assert_eq!(defaults["dashboard_url"], "https://hol.org/guard");
    assert_eq!(defaults["inbox_url"], "https://hol.org/guard/inbox");
    assert_eq!(defaults["fleet_url"], "https://hol.org/guard/protect");
    assert_eq!(defaults["connect_url"], "https://hol.org/guard/connect");
    let mut staging = args();
    staging["sync_url"] = json!("https://staging.example.test:8443/api/guard/receipts/sync");
    let staging = status(&staging);
    assert_eq!(
        staging["dashboard_url"],
        "https://staging.example.test:8443/guard"
    );
    assert_eq!(
        staging["connect_url"],
        "https://staging.example.test:8443/guard/connect"
    );
    for relative in ["", "/api/guard/receipts/sync"] {
        let mut args = args();
        args["sync_url"] = json!(relative);
        assert_eq!(status(&args)["dashboard_url"], "https://hol.org/guard");
    }
}

#[test]
fn malformed_arguments_are_refused() {
    let mut cases = Vec::new();
    for key in [
        "cloud_state",
        "sync_configured",
        "pending_events",
        "event_summary",
        "synced_at",
        "connect_state",
        "policy_ack",
        "sync_url",
    ] {
        let mut missing = args();
        missing.as_object_mut().unwrap().remove(key);
        cases.push(missing);
    }
    let mut negative = args();
    negative["pending_events"] = json!(-1);
    cases.push(negative);
    let mut truthy = args();
    truthy["oauth_repair_required"] = json!(1);
    cases.push(truthy);
    let mut listed = args();
    listed["connect_state"] = json!([]);
    cases.push(listed);
    let mut sync_url = args();
    sync_url["sync_url"] = json!(1);
    cases.push(sync_url);
    let mut ack_list = args();
    ack_list["policy_ack"]["acknowledgement"] = json!([]);
    cases.push(ack_list);
    for key in [
        "acknowledgement",
        "bundle_hash",
        "bundle_version",
        "device_id",
    ] {
        let mut missing = args();
        missing["policy_ack"].as_object_mut().unwrap().remove(key);
        cases.push(missing);
    }
    let mut numeric_hash = args();
    numeric_hash["policy_ack"]["bundle_hash"] = json!(1);
    cases.push(numeric_hash);
    for case in cases {
        assert_eq!(dispatch_at(&case, NOW), Err(ERR_INVALID), "{case}");
    }
}
