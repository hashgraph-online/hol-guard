use super::*;

const FIXTURE: &str = include_str!("../../../../tests/fixtures/harness-protection-states.v1.json");

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("protection state fixture")
}

fn rows(fixture: &Value, case: &Value) -> Vec<CapabilityRow> {
    let all: Vec<CapabilityRow> =
        serde_json::from_value(fixture["rows"].clone()).expect("fixture rows");
    match case["rows"].as_array() {
        Some(indexes) => indexes
            .iter()
            .map(|index| {
                let row = &fixture["rows"][index.as_u64().expect("row index") as usize];
                serde_json::from_value(row.clone()).expect("fixture row")
            })
            .collect(),
        None => all,
    }
}

#[test]
fn vocabulary_matches_the_shared_fixture() {
    let fixture = fixture();
    let states: Vec<&str> = fixture["states"]
        .as_array()
        .expect("states")
        .iter()
        .map(|entry| entry["state"].as_str().expect("state"))
        .collect();
    assert_eq!(states, PROTECTION_STATES);
}

#[test]
fn every_fixture_case_derives_its_states() {
    let fixture = fixture();
    for case in fixture["cases"].as_array().expect("cases") {
        let rows = rows(&fixture, case);
        let payload = with_event_states(case["coverage"].clone(), Some(&rows));
        let derived: Vec<&str> = payload["event_states"]
            .as_array()
            .expect("event states")
            .iter()
            .map(|entry| entry["state"].as_str().expect("state"))
            .collect();
        let expected: Vec<&str> = case["event_states"]
            .as_array()
            .expect("expected")
            .iter()
            .map(|state| state.as_str().expect("state"))
            .collect();
        assert_eq!(derived, expected, "{}", case["id"]);
        assert_eq!(
            payload["protection_state"], case["protection_state"],
            "{}",
            case["id"]
        );
        for state in &derived {
            assert!(PROTECTION_STATES.contains(state), "{state}");
        }
    }
}

#[test]
fn no_derivation_claims_an_unmodelled_live_state() {
    let fixture = fixture();
    for case in fixture["cases"].as_array().expect("cases") {
        let rows = rows(&fixture, case);
        let payload = with_event_states(case["coverage"].clone(), Some(&rows));
        let text = payload.to_string();
        assert!(!text.contains("transport_ready"), "{}", case["id"]);
        assert!(!text.contains("live_allow_proven"), "{}", case["id"]);
    }
}

#[test]
fn live_evidence_for_another_event_proves_nothing_here() {
    let row: CapabilityRow = serde_json::from_value(json!({
        "event": "PreToolUse",
        "transport": "native_hook",
        "mode": "blocking",
        "declared_actions": ["block"],
    }))
    .expect("row");
    let payload = json!({
        "state": "tested",
        "reason": null,
        "evidence": [{
            "evidence_level": "live_block",
            "transport": "native_hook",
            "events": ["UserPromptSubmit"],
        }],
    });
    let answered = with_event_states(payload, Some(&vec![row]));
    assert_eq!(answered["event_states"][0]["state"], "configured");
    assert_eq!(answered["protection_state"], "configured");
}

#[test]
fn a_harness_without_rows_is_unsupported() {
    let answered = with_event_states(json!({ "state": "version_unknown", "reason": null }), None);
    assert_eq!(answered["event_states"], json!([]));
    assert_eq!(answered["protection_state"], "unsupported");
}

#[test]
fn live_evidence_on_another_transport_proves_nothing_here() {
    let rows: Vec<CapabilityRow> = serde_json::from_value(json!([
        { "event": "PreToolUse", "transport": "native_hook", "mode": "blocking", "declared_actions": ["block"] },
        { "event": "PreToolUse", "transport": "agent_plugin", "mode": "blocking", "declared_actions": ["block"] },
    ]))
    .expect("rows");
    let payload = json!({
        "state": "tested",
        "reason": null,
        "evidence": [{
            "evidence_level": "live_block",
            "transport": "native_hook",
            "events": ["PreToolUse"],
        }],
    });
    let answered = with_event_states(payload, Some(&rows));
    assert_eq!(answered["event_states"][0]["state"], "live_block_proven");
    assert_eq!(answered["event_states"][1]["state"], "configured");
    assert_eq!(answered["protection_state"], "partial");
}

#[test]
fn live_evidence_without_a_transport_proves_nothing() {
    let row: CapabilityRow = serde_json::from_value(json!({
        "event": "PreToolUse",
        "transport": "native_hook",
        "mode": "blocking",
        "declared_actions": ["block"],
    }))
    .expect("row");
    let payload = json!({
        "state": "tested",
        "reason": null,
        "evidence": [{ "evidence_level": "live_block", "events": ["PreToolUse"] }],
    });
    let answered = with_event_states(payload, Some(&vec![row]));
    assert_eq!(answered["event_states"][0]["state"], "configured");
}

#[test]
fn an_event_split_by_tool_reports_each_row_with_its_tools() {
    let rows: Vec<CapabilityRow> = serde_json::from_value(json!([
        { "event": "PreToolUse", "tools": ["Bash"], "transport": "native_hook", "mode": "blocking", "declared_actions": ["block"] },
        { "event": "PreToolUse", "tools": ["apply_patch"], "transport": "native_hook", "mode": "blocking", "declared_actions": ["block"] },
        { "event": "Stop", "transport": "native_hook", "mode": "observe", "declared_actions": ["observe"] },
    ]))
    .expect("rows");
    let answered = with_event_states(json!({ "state": "tested", "reason": null }), Some(&rows));
    assert_eq!(answered["event_states"][0]["tools"], json!(["Bash"]));
    assert_eq!(answered["event_states"][1]["tools"], json!(["apply_patch"]));
    assert_eq!(answered["event_states"][2]["tools"], json!([]));
}

#[test]
fn an_event_split_by_surface_keeps_each_surface() {
    let rows: Vec<CapabilityRow> = serde_json::from_value(json!([
        { "event": "*", "surface": "cli", "transport": "none", "mode": "unsupported", "declared_actions": [] },
        { "event": "*", "surface": "cloud_agent", "transport": "none", "mode": "unsupported", "declared_actions": [] },
        { "event": "Stop", "transport": "native_hook", "mode": "observe", "declared_actions": ["observe"] },
    ]))
    .expect("rows");
    let answered = with_event_states(json!({ "state": "tested", "reason": null }), Some(&rows));
    assert_eq!(answered["event_states"][0]["surface"], "cli");
    assert_eq!(answered["event_states"][1]["surface"], "cloud_agent");
    assert_eq!(answered["event_states"][2]["surface"], Value::Null);
}
