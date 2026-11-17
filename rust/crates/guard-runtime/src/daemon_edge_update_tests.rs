use std::collections::HashMap;

use serde_json::{json, Value};

use super::*;

fn drive(payload: Value, status: Value, extra: &[(&str, Value)]) -> (Option<Reply>, Vec<String>) {
    let mut by_name: HashMap<String, Value> = extra
        .iter()
        .map(|(name, answer)| ((*name).to_owned(), answer.clone()))
        .collect();
    by_name.insert("update.status".to_owned(), status);
    let mut seen = Vec::new();
    let mut call = |name: &str, _args: Value| {
        seen.push(name.to_owned());
        by_name.get(name).cloned().ok_or(CallError::Unavailable)
    };
    let mut host = Host {
        call: &mut call,
        args: Map::new(),
    };
    let Value::Object(payload) = payload else {
        unreachable!()
    };
    let reply = finish(update(&mut host, &payload));
    (reply, seen)
}

fn reply(run: (Option<Reply>, Vec<String>)) -> Reply {
    run.0.unwrap_or_else(|| unreachable!())
}

#[test]
fn an_available_update_is_scheduled() {
    let status =
        json!({"auto_updatable": true, "update_available": true, "release_channel": "alpha"});
    let run = drive(
        json!({}),
        status,
        &[("update.schedule", json!({"scheduled": true}))],
    );
    assert_eq!(run.1, ["update.status", "update.schedule"]);
    assert_eq!(reply(run), (200, json!({"scheduled": true})));
}

#[test]
fn refusals_name_the_reason() {
    for (payload, status, error, message) in [
        (
            json!({}),
            json!({"python_update_required": true, "blocked_reason": ""}),
            "update_not_supported",
            "Update requires a different Python runtime.",
        ),
        (
            json!({"force_pypi_reinstall": 1}),
            json!({"blocked_reason": "Pinned."}),
            "update_not_supported",
            "Pinned.",
        ),
        (
            json!({}),
            json!({"update_available": true}),
            "update_not_supported",
            "Automatic update is not available.",
        ),
        (
            json!({}),
            json!({"auto_updatable": true}),
            "update_not_available",
            LATEST,
        ),
    ] {
        assert_eq!(
            reply(drive(payload, status, &[])),
            (400, json!({"error": error, "message": message}))
        );
    }
}

#[test]
fn a_forced_reinstall_skips_the_availability_checks() {
    let run = drive(
        json!({"force_pypi_reinstall": true}),
        json!({"recovery_reinstall_available": true}),
        &[("update.schedule", json!({"scheduled": true}))],
    );
    assert_eq!(reply(run).0, 200);
}

#[test]
fn desktop_handoff() {
    let desktop = json!({"installer": "desktop", "update_available": true, "latest_version": "9", "current_version": "8"});
    let run = drive(
        json!({"handoff_to_desktop": true}),
        desktop.clone(),
        &[("update.handoff", json!({"recorded": true}))],
    );
    assert_eq!(
        reply(run),
        (
            200,
            json!({"handoff_requested": true, "current_version": "8", "latest_version": "9"})
        )
    );
    let run = drive(
        json!({"handoff_to_desktop": true}),
        desktop,
        &[("update.handoff", json!({"recorded": false}))],
    );
    assert_eq!(reply(run).0, 500);
    let run = drive(
        json!({"handoff_to_desktop": true}),
        json!({"installer": "pipx"}),
        &[],
    );
    assert_eq!(reply(run).1["error"], "desktop_handoff_unavailable");
    let run = drive(
        json!({"handoff_to_desktop": true}),
        json!({"installer": "desktop", "update_available": true}),
        &[],
    );
    assert_eq!(reply(run).1["error"], "update_not_available");
}

#[test]
fn an_unreachable_library_relays() {
    let mut call = |_: &str, _: Value| Err(CallError::Unavailable);
    let mut host = Host {
        call: &mut call,
        args: Map::new(),
    };
    assert!(finish(status(&mut host)).is_none());
}
