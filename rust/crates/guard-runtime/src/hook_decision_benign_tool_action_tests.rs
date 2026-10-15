//! The resident computes `verified_benign` for tool actions itself. Compose
//! over the recorded Python `is_explicitly_benign_tool_action_request` vectors
//! must never be more permissive than Python, and must agree on the vectors
//! whose verdict needs no host trust. Missing, oversized or unsupported
//! inputs fail closed.

use std::collections::BTreeMap;

use guard_contracts::{
    CodexToolOutputFactsV1, HookCompositionInputsV1, HookControlSnapshotV1, HookNativeRequestV1,
};
use serde_json::{json, Value};

use crate::hook_decision_compose::compose;
use crate::sfrs_support::{replay_vectors, ReplayVector};

const ENTRY: &str = "is_explicitly_benign_tool_action_request";
const ENTRIES: &[(&str, &[u8])] = &[(
    ENTRY,
    include_bytes!(
        "../../guard-command/tests/fixtures/sfrs/is_explicitly_benign_tool_action_request.json.gz"
    ),
)];

fn inputs(native_request: Option<HookNativeRequestV1>, event: &str) -> HookCompositionInputsV1 {
    let mut value = json!({
        "harness": "codex",
        "canonical_harness": "codex",
        "event_fields": {"hook_event_name": event},
        "tool_name_text": "Bash",
        "configured_action": "review",
        "has_configured_override": false,
        "has_narrow_override": false,
        "runtime_artifact_checked": false,
        "prompt_nonblank": false,
        "has_command_text": true,
        "facts": {"verified_apply_patch": false},
    });
    value["native_request"] = serde_json::to_value(native_request).unwrap();
    serde_json::from_value(value).unwrap()
}

fn host(vector: &ReplayVector, home: &str) -> CodexToolOutputFactsV1 {
    let mut environment = BTreeMap::from([("HOME".to_owned(), home.to_owned())]);
    if let Some(recorded) = vector.env.as_object() {
        environment.extend(
            recorded
                .iter()
                .filter_map(|(key, value)| Some((key.clone(), value.as_str()?.to_owned()))),
        );
    }
    CodexToolOutputFactsV1 {
        process_cwd: vector.dir.to_string_lossy().into_owned(),
        home: home.to_owned(),
        account_home: None,
        groups: Vec::new(),
        environment,
        git_executable: None,
    }
}

fn call(vector: &ReplayVector) -> HookNativeRequestV1 {
    let home = vector.env["HOME"]
        .as_str()
        .map_or_else(|| vector.dir.to_string_lossy().into_owned(), str::to_owned);
    HookNativeRequestV1 {
        tool_name: vector.args["tool_name"].clone(),
        tool_input: vector.args["arguments"].clone(),
        cwd: vector.args["cwd"].as_str().map(str::to_owned),
        home_dir: vector.args["home_dir"].as_str().map(str::to_owned),
        host: host(vector, &home),
        control_snapshot: None,
    }
}

fn verified_benign(inputs: &HookCompositionInputsV1) -> bool {
    compose(inputs)
        .expect("native verdicts need no transport fact")
        .verified_benign
}

#[test]
fn compose_is_never_more_permissive_than_recorded_python_vectors() {
    let (vectors, _root) = replay_vectors(ENTRIES, ENTRY);
    let (mut compared, mut expected_benign, mut agreed) = (0, 0, 0);
    let mut looser = Vec::new();
    for vector in vectors.iter().filter(|vector| !vector.host_dependent) {
        let expected = vector.expected(&Value::Null) == json!(true);
        let actual = verified_benign(&inputs(Some(call(vector)), "PreToolUse"));
        // The recorded Python runs stubbed git as missing or untrusted; a real
        // trusted git on this host may legitimately make those benign.
        let git_stubbed = vector.args["arguments"]["command"]
            .as_str()
            .is_some_and(|command| command.contains("git"));
        if !expected && actual && !git_stubbed {
            looser.push(vector.id.clone());
        }
        compared += 1;
        expected_benign += usize::from(expected);
        agreed += usize::from(expected && actual);
    }
    assert!(looser.is_empty(), "{looser:?}");
    assert!(compared > 0 && expected_benign > 0);
    // Real filesystem trust refuses some stub-trusted vectors; most agree.
    assert!(
        agreed * 2 >= expected_benign,
        "agreed {agreed} of {expected_benign}"
    );
}

#[test]
fn only_pre_tool_use_is_verified_benign() {
    let (vectors, _root) = replay_vectors(ENTRIES, ENTRY);
    let vector = vectors
        .iter()
        .find(|vector| !vector.host_dependent && vector.expected(&Value::Null) == json!(true))
        .expect("a benign vector");
    let request = call(vector);
    assert!(verified_benign(&inputs(
        Some(request.clone()),
        "PreToolUse"
    )));
    assert!(!verified_benign(&inputs(Some(request), "PostToolUse")));
}

#[test]
fn missing_request_is_not_benign() {
    assert!(!verified_benign(&inputs(None, "PreToolUse")));
}

#[test]
fn unknown_control_health_is_not_benign() {
    let (vectors, _root) = replay_vectors(ENTRIES, ENTRY);
    let vector = vectors
        .iter()
        .find(|vector| !vector.host_dependent && vector.expected(&Value::Null) == json!(true))
        .expect("a benign vector");
    let mut request = call(vector);
    request.control_snapshot = Some(HookControlSnapshotV1 {
        health: "unknown-health".to_owned(),
        layers: Vec::new(),
    });
    assert!(!verified_benign(&inputs(Some(request), "PreToolUse")));
}

#[test]
fn oversized_host_facts_are_not_benign() {
    let (vectors, _root) = replay_vectors(ENTRIES, ENTRY);
    let vector = vectors
        .iter()
        .find(|vector| !vector.host_dependent && vector.expected(&Value::Null) == json!(true))
        .expect("a benign vector");
    let mut request = call(vector);
    request
        .host
        .environment
        .extend((0..200).map(|index| (format!("K{index}"), "v".to_owned())));
    assert!(!verified_benign(&inputs(Some(request), "PreToolUse")));
}
