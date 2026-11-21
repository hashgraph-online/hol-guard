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
fn desktop_handoff_keeps_the_offered_release_when_the_recheck_loses_it() {
    // The dashboard offered 3.61.0a5; the fresh status check could not
    // confirm the alpha (rate limited) and fell back to the running Core.
    let rechecked = json!({
        "installer": "desktop",
        "update_available": false,
        "latest_version": "3.61.0a1",
        "current_version": "3.61.0a1",
    });
    let mut recorded_args = Vec::new();
    let mut call = |name: &str, args: Value| match name {
        "update.status" => Ok(rechecked.clone()),
        "update.handoff" => {
            recorded_args.push(args);
            Ok(json!({"recorded": true}))
        }
        _ => Err(CallError::Unavailable),
    };
    let mut host = Host {
        call: &mut call,
        args: Map::new(),
    };
    let Value::Object(payload) = json!({"handoff_to_desktop": true, "latest_version": "3.61.0a5"})
    else {
        unreachable!()
    };
    let answer = finish(update(&mut host, &payload)).unwrap_or_else(|| unreachable!());
    assert_eq!(
        answer,
        (
            200,
            json!({"handoff_requested": true, "current_version": "3.61.0a1", "latest_version": "3.61.0a5"})
        )
    );
    assert_eq!(recorded_args.len(), 1);
    assert_eq!(recorded_args[0]["latest_version"], "3.61.0a5");
}

#[test]
fn desktop_handoff_refuses_an_offered_version_that_is_not_newer() {
    let rechecked = json!({
        "installer": "desktop",
        "update_available": false,
        "latest_version": "3.61.0a1",
        "current_version": "3.61.0a1",
    });
    for offered in [
        json!("3.61.0a1"),
        json!("3.60.0"),
        json!("not a version"),
        json!(""),
        json!(7),
        json!("9".repeat(80)),
    ] {
        let run = drive(
            json!({"handoff_to_desktop": true, "latest_version": offered}),
            rechecked.clone(),
            &[("update.handoff", json!({"recorded": true}))],
        );
        assert_eq!(run.1, ["update.status"], "{offered}");
        assert_eq!(reply(run).1["error"], "update_not_available", "{offered}");
    }
}

#[test]
fn desktop_handoff_prefers_the_checked_release_over_the_offered_one() {
    let status = json!({
        "installer": "desktop",
        "update_available": true,
        "latest_version": "3.61.0a6",
        "current_version": "3.61.0a1",
    });
    let run = drive(
        json!({"handoff_to_desktop": true, "latest_version": "3.61.0a5"}),
        status,
        &[("update.handoff", json!({"recorded": true}))],
    );
    assert_eq!(reply(run).1["latest_version"], "3.61.0a6");
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
