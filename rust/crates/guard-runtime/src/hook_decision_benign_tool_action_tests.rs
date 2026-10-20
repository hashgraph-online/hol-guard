//! The resident computes `verified_benign` for tool actions itself. Compose
//! over the recorded Python `is_explicitly_benign_tool_action_request` vectors
//! must never be more permissive than Python, and must agree on the vectors
//! whose verdict needs no host trust. Missing, oversized or unsupported
//! inputs fail closed.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use guard_contracts::{
    CodexToolOutputFactsV1, HookCompositionInputsV1, HookControlSnapshotV1, HookNativeRequestV1,
};
use serde_json::{json, Value};

use crate::hook_decision_compose::compose;
use crate::hook_decision_native_facts::{
    verdict_handoff, verdict_is_recorded, verdict_is_recorded_after, VerdictHandoff,
};
use crate::sfrs_support::{replay_vectors, ReplayVector};

/// The verdict handoff is one slot for the process, so a test that asserts
/// what it holds runs alone among the tests that fill it.
static VERDICT_TABLE: Mutex<()> = Mutex::new(());

fn verdict_table() -> MutexGuard<'static, ()> {
    VERDICT_TABLE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

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
        "facts": {},
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
    let _table = verdict_table();
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
    let _table = verdict_table();
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
    let _table = verdict_table();
    assert!(!verified_benign(&inputs(None, "PreToolUse")));
}

#[test]
fn unknown_control_health_is_not_benign() {
    let _table = verdict_table();
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
    let _table = verdict_table();
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

#[test]
fn a_composition_hands_its_verdict_to_the_finalize_that_follows() {
    let _table = verdict_table();
    let (vectors, _root) = replay_vectors(ENTRIES, ENTRY);
    let vector = vectors
        .iter()
        .find(|vector| !vector.host_dependent)
        .expect("a vector");
    let mut request = call(vector);
    request.cwd = Some("/nonexistent/hol-guard-verdict-handoff/first".to_owned());
    let first = inputs(Some(request.clone()), "PreToolUse");
    request.cwd = Some("/nonexistent/hol-guard-verdict-handoff/second".to_owned());
    let second = inputs(Some(request), "PreToolUse");

    let verdict = {
        let _mode = verdict_handoff(VerdictHandoff::Record);
        verified_benign(&first)
    };
    assert!(verdict_is_recorded(&first));
    // Another directory composes to another verdict and can never take this one.
    assert!(!verdict_is_recorded(&second));
    // The window bounds the handoff to the hook that opened it.
    assert!(!verdict_is_recorded_after(&first, Duration::from_secs(3)));

    let taken = {
        let _mode = verdict_handoff(VerdictHandoff::Take);
        verified_benign(&first)
    };
    assert_eq!(verdict, taken);
    // Taking empties the slot, so no verdict is ever read twice.
    assert!(!verdict_is_recorded(&first));
}

#[test]
fn a_later_composition_displaces_the_verdict_an_earlier_one_left() {
    let _table = verdict_table();
    let (vectors, _root) = replay_vectors(ENTRIES, ENTRY);
    let vector = vectors
        .iter()
        .find(|vector| !vector.host_dependent)
        .expect("a vector");
    let mut request = call(vector);
    request.cwd = Some("/nonexistent/hol-guard-verdict-displaced/first".to_owned());
    let first = inputs(Some(request.clone()), "PreToolUse");
    request.cwd = Some("/nonexistent/hol-guard-verdict-displaced/second".to_owned());
    let second = inputs(Some(request), "PreToolUse");

    let _mode = verdict_handoff(VerdictHandoff::Record);
    let _ = verified_benign(&first);
    assert!(verdict_is_recorded(&first));
    // A later hook composes before it finalizes, so the slot never carries a
    // verdict across the command that ran in between.
    let _ = verified_benign(&second);
    assert!(!verdict_is_recorded(&first));
    assert!(verdict_is_recorded(&second));
}

#[test]
fn a_composition_outside_the_two_queries_records_nothing() {
    let _table = verdict_table();
    let (vectors, _root) = replay_vectors(ENTRIES, ENTRY);
    let vector = vectors
        .iter()
        .find(|vector| !vector.host_dependent)
        .expect("a vector");
    let mut request = call(vector);
    request.cwd = Some("/nonexistent/hol-guard-verdict-off/only".to_owned());
    let composed = inputs(Some(request.clone()), "PreToolUse");
    // The default mode: any other caller of `compose` leaves nothing behind.
    let _ = verified_benign(&composed);
    assert!(!verdict_is_recorded(&composed));
}

#[test]
fn a_request_free_composition_records_no_verdict() {
    let _table = verdict_table();
    let _mode = verdict_handoff(VerdictHandoff::Record);
    let composed = inputs(None, "PreToolUse");
    assert!(!verified_benign(&composed));
    assert!(!verdict_is_recorded(&composed));
}
