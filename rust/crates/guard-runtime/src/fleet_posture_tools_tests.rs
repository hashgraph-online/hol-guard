use serde_json::{json, Map, Value};

use super::{client_section, reported_tools};
use crate::guard_store_local_cli::parse_utc;

const NOW: &str = "2026-10-23T12:00:00+00:00";

fn now() -> i64 {
    parse_utc(&Value::from(NOW)).unwrap()
}

fn tool(harness: &str, setup_status: &str) -> Value {
    json!({
        "harness": harness,
        "setupStatus": setup_status,
        "hasConfigPaths": true,
        "toolVersion": "1.2.3",
        "coverage": {
            "nativeHooks": true,
            "browserFallback": false,
            "mcpProxy": true,
            "promptHooks": false,
            "blindSpots": ["web search"],
        },
        "lastActivityAt": null,
        "paused": false,
        "configured": true,
        "override": null,
    })
}

fn rows(tools: &[Value], last: Option<&Value>, detail: bool) -> Vec<Map<String, Value>> {
    reported_tools(tools, last.and_then(Value::as_object), now(), detail)
        .unwrap()
        .into_iter()
        .map(|(_, row)| row)
        .collect()
}

fn state(tool: Value) -> String {
    rows(
        &[tool],
        Some(&json!({"tools": {"codex": "protected"}})),
        true,
    )[0]["protectionState"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn with(mut tool: Value, key: &str, value: Value) -> Value {
    tool[key] = value;
    tool
}

#[test]
fn setup_status_and_pause_decide_the_protection_state() {
    let codex = || tool("codex", "active");
    assert_eq!(state(codex()), "protected");
    assert_eq!(state(with(codex(), "paused", json!(true))), "paused");
    assert_eq!(state(tool("codex", "partial")), "needs_setup");
    assert_eq!(state(tool("codex", "broken")), "broken");
    // A broken setup outranks a pause.
    assert_eq!(
        state(with(tool("codex", "broken"), "paused", json!(true))),
        "broken"
    );
    // Configuration left behind by an uninstalled tool still needs setup.
    assert_eq!(state(tool("codex", "not_found")), "needs_setup");
    assert_eq!(
        state(with(
            tool("codex", "not_found"),
            "hasConfigPaths",
            json!(false)
        )),
        "not_detected"
    );
}

#[test]
fn activity_staleness_keeps_the_exact_seven_day_boundary() {
    for (last_activity, expected) in [
        ("2026-10-16T12:00:00.000001+00:00", "protected"),
        ("2026-10-16T12:00:00Z", "protected"),
        ("2026-10-16T11:59:59.999999+00:00", "stale"),
    ] {
        let active = with(
            tool("codex", "active"),
            "lastActivityAt",
            json!(last_activity),
        );
        assert_eq!(state(active), expected, "{last_activity}");
    }
    let unparseable = with(
        tool("codex", "active"),
        "lastActivityAt",
        json!("yesterday"),
    );
    assert_eq!(state(unparseable), "protected");
}

#[test]
fn a_row_reports_hooks_blind_spots_override_and_activity() {
    let mut spotted = tool("cursor", "active");
    spotted["coverage"]["blindSpots"] = json!((0..10)
        .map(|index| format!("{index}{}", "é".repeat(100)))
        .collect::<Vec<_>>());
    spotted["override"] = json!("watch");
    spotted["lastActivityAt"] = json!("2026-10-23T11:00:00.500000Z");
    let row = &rows(&[spotted.clone()], None, true)[0];
    assert_eq!(
        row["hooks"],
        json!({"nativeHooks": true, "browserFallback": false, "mcpProxy": true, "promptHooks": false})
    );
    let spots = row["blindSpots"].as_array().unwrap();
    assert_eq!(spots.len(), 8);
    assert_eq!(spots[0].as_str().unwrap().chars().count(), 80);
    assert_eq!(row["postureOverride"], "off");
    assert_eq!(row["lastActivityAt"], "2026-10-23T11:00:00Z");
    assert_eq!(row["toolVersion"], "1.2.3");
    // A minimal report leaves the blind spots out.
    assert_eq!(rows(&[spotted], None, false)[0]["blindSpots"], json!([]));

    let overrides = [
        (json!(true), json!(null), json!("default")),
        (json!(true), json!("enforce"), json!("enforce")),
        (json!(false), json!("watch"), Value::Null),
    ];
    for (configured, posture, expected) in overrides {
        let mut row = tool("codex", "active");
        row["configured"] = configured;
        row["override"] = posture;
        row["toolVersion"] = json!(7);
        row["coverage"] = json!({});
        let reported = &rows(&[row], None, true)[0];
        assert_eq!(reported["postureOverride"], expected);
        assert_eq!(reported["toolVersion"], Value::Null);
        assert_eq!(reported["blindSpots"], json!([]));
    }
}

#[test]
fn an_undetected_tool_is_reported_only_once_it_disappears() {
    let absent = with(tool("codex", "not_found"), "hasConfigPaths", json!(false));
    for last in [
        None,
        Some(json!({"tools": {}})),
        Some(json!({"tools": {"codex": null}})),
        Some(json!({"tools": {"codex": "not_detected"}})),
        Some(json!({"tools": ["codex"]})),
    ] {
        assert!(
            rows(&[absent.clone()], last.as_ref(), true).is_empty(),
            "{last:?}"
        );
    }
    let last = json!({"tools": {"codex": "protected"}});
    assert_eq!(rows(&[absent], Some(&last), true).len(), 1);
}

#[test]
fn malformed_tools_are_refused() {
    for tool in [
        json!("codex"),
        json!({"setupStatus": "active"}),
        json!({"harness": "codex", "setupStatus": 1}),
    ] {
        assert!(reported_tools(&[tool], None, now(), true).is_err());
    }
}

fn client(version: &str, runtime: Value, state: Value) -> Value {
    client_section(&json!({"version": version, "runtime": runtime, "autoUpdateState": state}))
        .unwrap()
}

#[test]
fn the_client_section_reports_version_channel_and_runtime() {
    let stable = client("3.58.0", json!("native"), Value::Null);
    assert_eq!(
        stable,
        json!({
            "version": "3.58.0",
            "channel": "stable",
            "runtime": "native",
            "autoUpdate": {"enabled": false, "lastCheckedAt": null, "lastResult": null},
        })
    );
    let alpha = client("3.59.0a12", json!("rust"), json!("not an object"));
    assert_eq!(
        (&alpha["version"], &alpha["channel"], &alpha["runtime"]),
        (&json!("3.59.0a12"), &json!("alpha"), &json!("python"))
    );
    assert_eq!(
        client("3.59.0DEV1", Value::Null, Value::Null)["channel"],
        "alpha"
    );
    assert_eq!(
        client("not-a-version", Value::Null, Value::Null)["version"],
        "0.0.0"
    );
    let long = format!("1.2.3+{}", "x".repeat(40));
    assert_eq!(
        client(&long, Value::Null, Value::Null)["version"]
            .as_str()
            .unwrap()
            .len(),
        32
    );
    // The channel the last check stored wins over the version's own.
    let stored = json!({"last_status": {"release_channel": "alpha"}});
    assert_eq!(client("3.58.0", Value::Null, stored)["channel"], "alpha");
    let unknown = json!({"last_status": {"release_channel": "beta"}});
    assert_eq!(client("3.58.0", Value::Null, unknown)["channel"], "stable");
    assert!(client_section(&json!({"version": 3})).is_err());
}

fn last_result(extra: Value) -> Value {
    let mut state = json!({
        "last_check_at": "2026-10-16T06:00:00+00:00",
        "last_status": {"auto_updatable": true, "update_available": true, "release_channel": "stable"},
    });
    for (key, value) in extra.as_object().unwrap() {
        state[key] = value.clone();
    }
    client("3.58.0", Value::Null, state)["autoUpdate"]["lastResult"].clone()
}

#[test]
fn auto_update_reports_what_the_last_cycle_did() {
    let ran = "2026-10-16T06:00:00+00:00";
    let earlier = "2026-10-16T05:00:00+00:00";
    let cases = [
        (json!({}), "update_available"),
        (
            json!({"last_update_exit_code": 1, "last_update_at": ran}),
            "failed",
        ),
        (
            json!({"last_update_exit_code": 0, "last_update_at": ran}),
            "updated",
        ),
        (
            json!({"last_update_exit_code": false, "last_update_at": ran}),
            "updated",
        ),
        (
            json!({"last_update_exit_code": 0.0, "last_update_at": ran}),
            "updated",
        ),
        (
            json!({"last_update_exit_code": "0", "last_update_at": ran}),
            "failed",
        ),
        (json!({"last_update_error": true}), "failed"),
        (json!({"last_update_error": 1}), "update_available"),
        // An update from an earlier cycle says nothing about this one.
        (
            json!({"last_update_exit_code": 1, "last_update_at": earlier}),
            "update_available",
        ),
        (
            json!({"last_status": {"auto_updatable": true, "update_available": true, "blocked_reason": "managed"}, "last_update_exit_code": 1, "last_update_at": ran}),
            "update_available",
        ),
        (
            json!({"last_status": {"auto_updatable": 0, "update_available": true}, "last_update_error": true}),
            "update_available",
        ),
        (
            json!({"last_status": {"auto_updatable": true, "update_available": "yes"}}),
            "up_to_date",
        ),
    ];
    for (extra, expected) in cases {
        assert_eq!(last_result(extra.clone()), expected, "{extra}");
    }
    let checked = client(
        "3.58.0",
        Value::Null,
        json!({"last_check_at": "2026-10-16T06:00:00+00:00", "last_status": {"auto_updatable": true, "update_available": true, "release_channel": "alpha"}}),
    );
    assert_eq!(
        checked["autoUpdate"],
        json!({"enabled": true, "lastCheckedAt": "2026-10-16T06:00:00Z", "lastResult": "update_available"})
    );
    for state in [
        json!({"last_check_error": true}),
        json!({"last_update_error": true}),
    ] {
        let failed = client("3.58.0", Value::Null, state);
        assert_eq!(
            failed["autoUpdate"],
            json!({"enabled": false, "lastCheckedAt": null, "lastResult": "failed"})
        );
    }
}
