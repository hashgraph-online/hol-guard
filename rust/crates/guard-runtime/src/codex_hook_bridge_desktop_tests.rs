//! The Desktop lane: lane flags, the probe handoff and a registration that
//! failed before the runtime started.

use std::time::{Duration, Instant};

use super::*;

const OPERATION: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";
const REQUEST: &str = "transition-hook-0123456789abcdef0123456789abcdef";

fn args(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

fn config(query: &str, timeouts: &[(&str, i64)]) -> BridgeConfig {
    BridgeConfig {
        state_path: "/g/daemon-state.json".to_owned(),
        query: query.to_owned(),
        hook_timeouts: timeouts
            .iter()
            .map(|(event, seconds)| ((*event).to_owned(), *seconds))
            .collect(),
        start_command: vec!["start".to_owned()],
        fallback_command: vec!["fallback".to_owned()],
    }
}

fn probe_body(cwd: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "cwd": cwd,
        "guard_transition_probe": {
            "schema": "hol-guard.transition-hook-probe.v1",
            "operation_id": OPERATION,
            "request_id": REQUEST,
        },
    })
    .to_string()
}

fn handoff(config: &BridgeConfig, body: &str) -> Option<serde_json::Value> {
    let payload = pyjson::parse_mapping_lone_surrogates(body).unwrap().value;
    handoff_document(
        config,
        &payload,
        body,
        Duration::from_secs(8),
        Instant::now(),
    )
}

#[test]
fn lane_flags_lead_the_argv_and_installed_argv_has_none() {
    let installed = args(&["/usr/bin/python3", "-I", "/b.py", "{}"]);
    assert_eq!(
        split_lane(&installed),
        (Lane::default(), installed.as_slice())
    );

    let flagged = args(&[
        "--guard-desktop-lane",
        "--guard-registration-failure=codex_hook_manifest_mac_invalid",
        "{}",
    ]);
    let (lane, rest) = split_lane(&flagged);
    assert!(lane.desktop);
    assert_eq!(
        lane.registration_failure.as_deref(),
        Some("codex_hook_manifest_mac_invalid")
    );
    assert_eq!(rest, &flagged[2..]);
}

#[test]
fn a_cause_that_is_not_a_reason_code_still_fails_closed() {
    let flagged = args(&["--guard-registration-failure=Not A Code", "{}"]);
    let (lane, rest) = split_lane(&flagged);
    assert_eq!(
        lane.registration_failure.as_deref(),
        Some("codex_hook_launch_unauthenticated")
    );
    assert_eq!(rest, &flagged[1..]);
    // A repeated flag is not consumed, so it is read as the config.
    let repeated = args(&[
        "--guard-registration-failure=a",
        "--guard-registration-failure=b",
    ]);
    assert_eq!(split_lane(&repeated).1, &repeated[1..]);
}

#[test]
fn a_probe_hands_back_the_paths_the_signed_command_needs() {
    let body = probe_body("/work");
    let config = config("home=%2Fhome%2Fu&guard-home=%2Fg", &[("PreToolUse", 25)]);
    let document = handoff(&config, &body).unwrap();
    assert_eq!(document["schema"], "hol-guard.codex-desktop-probe.v1");
    assert_eq!(document["data"], body.as_str());
    assert_eq!(document["guard_home"], "/g");
    assert_eq!(document["home"], "/home/u");
    assert_eq!(document["workspace"], "/work");
    assert_eq!(document["timeout_seconds"], 25);
    let remaining = document["remaining_seconds"].as_f64().unwrap();
    assert!(remaining > 7.0 && remaining <= 8.0, "{remaining}");
}

#[test]
fn a_probe_without_one_absolute_home_workspace_or_deadline_is_refused() {
    let timeouts = [("PreToolUse", 25)];
    for query in ["", "home=relative", "home=%2Fa&home=%2Fb", "home=%2Fa%00b"] {
        assert!(
            handoff(&config(query, &timeouts), &probe_body("/w")).is_none(),
            "{query}"
        );
    }
    let valid = config("home=%2Fh", &timeouts);
    assert!(handoff(&valid, &probe_body("relative")).is_none());
    assert!(handoff(
        &config("home=%2Fh", &[("PostToolUse", 25)]),
        &probe_body("/w")
    )
    .is_none());
    let mut relative_state = valid;
    relative_state.state_path = "daemon-state.json".to_owned();
    assert!(handoff(&relative_state, &probe_body("/w")).is_none());
}

#[test]
fn a_guard_home_named_directly_is_used_as_it_is() {
    let mut config = config("home=%2Fh", &[("PreToolUse", 25)]);
    config.state_path = "/guard".to_owned();
    assert_eq!(
        handoff(&config, &probe_body("/w")).unwrap()["guard_home"],
        "/guard"
    );
}

#[test]
fn only_the_desktop_lane_hands_a_probe_back() {
    let config = config("home=%2Fh", &[("PreToolUse", 25)]);
    let body = probe_body("/w");
    let other_lane = Lane::default();
    assert_eq!(settle(&other_lane, &config, &body, Instant::now()), None);
    let desktop = Lane {
        desktop: true,
        registration_failure: Some("codex_hook_launch_unauthenticated".to_owned()),
    };
    // The probe is the signed bundle's to answer even when the runtime's own
    // registration did not authenticate.
    assert_eq!(
        settle(&desktop, &config, &body, Instant::now()),
        Some(PROBE_HANDOFF_EXIT)
    );
}

#[test]
fn a_failed_registration_denies_every_other_hook() {
    let config = config("home=%2Fh", &[("PreToolUse", 25), ("PostToolUse", 25)]);
    let lane = Lane {
        desktop: true,
        registration_failure: Some("codex_hook_launch_unauthenticated".to_owned()),
    };
    let body = r#"{"hook_event_name":"PostToolUse","tool_name":"Bash"}"#;
    assert_eq!(settle(&lane, &config, body, Instant::now()), Some(0));
    assert_eq!(settle(&lane, &config, "[1]", Instant::now()), Some(0));
    let authenticated = Lane {
        desktop: true,
        registration_failure: None,
    };
    assert_eq!(settle(&authenticated, &config, body, Instant::now()), None);
}
