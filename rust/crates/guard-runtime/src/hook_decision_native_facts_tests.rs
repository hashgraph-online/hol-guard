//! The resident computes `benign_native_file_read` itself: compose answers
//! match the recorded Python `is_explicitly_benign_native_file_read_request`
//! vectors, and a missing or malformed request fails closed.

use std::collections::BTreeMap;

use guard_contracts::{CodexToolOutputFactsV1, HookCompositionInputsV1, HookNativeRequestV1};
use serde_json::{json, Value};

use crate::hook_decision_compose::compose;
use crate::sfrs_support::replay_vectors;

const ENTRY: &str = "is_explicitly_benign_native_file_read_request";
const ENTRIES: &[(&str, &[u8])] = &[(
    ENTRY,
    include_bytes!(
        "../../guard-command/tests/fixtures/sfrs/is_explicitly_benign_native_file_read_request.json.gz"
    ),
)];

fn inputs(native_request: Option<HookNativeRequestV1>) -> HookCompositionInputsV1 {
    let mut value = json!({
        "harness": "codex",
        "canonical_harness": "codex",
        "event_fields": {"hook_event_name": "PreToolUse"},
        "tool_name_text": "Read",
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

fn request(tool_name: Value, tool_input: Value, root: &str, home: &str) -> HookNativeRequestV1 {
    HookNativeRequestV1 {
        tool_name,
        tool_input,
        cwd: Some(root.to_owned()),
        home_dir: Some(home.to_owned()),
        host: CodexToolOutputFactsV1 {
            process_cwd: root.to_owned(),
            home: home.to_owned(),
            account_home: None,
            groups: Vec::new(),
            environment: BTreeMap::from([("HOME".to_owned(), home.to_owned())]),
            git_executable: None,
        },
        control_snapshot: None,
    }
}

/// `true` when compose relaxed the default on the native verdicts.
fn native_read_verdict(inputs: &HookCompositionInputsV1) -> bool {
    compose(inputs)
        .expect("native verdicts need no transport fact")
        .relaxed
}

#[test]
fn compose_matches_recorded_python_native_file_read_vectors() {
    let (vectors, _root) = replay_vectors(ENTRIES, ENTRY);
    let mut compared = 0;
    let mut benign = 0;
    for vector in vectors.iter().filter(|vector| !vector.host_dependent) {
        let home = vector.env["HOME"]
            .as_str()
            .map_or_else(|| vector.dir.to_string_lossy().into_owned(), str::to_owned);
        let args = &vector.args;
        let call = HookNativeRequestV1 {
            cwd: args["cwd"].as_str().map(str::to_owned),
            home_dir: args["home_dir"].as_str().map(str::to_owned),
            ..request(
                args["tool_name"].clone(),
                args["arguments"].clone(),
                &vector.dir.to_string_lossy(),
                &home,
            )
        };
        let expected = vector.expected(&Value::Null) == json!(true);
        assert_eq!(
            native_read_verdict(&inputs(Some(call))),
            expected,
            "{}: {}",
            vector.id,
            vector.args
        );
        compared += 1;
        benign += usize::from(expected);
    }
    assert!(compared > 0 && benign > 0 && benign < compared);
}

#[test]
fn missing_request_is_not_benign() {
    assert!(!native_read_verdict(&inputs(None)));
}

#[test]
fn oversized_host_facts_are_not_benign() {
    let dir = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("hook-native-facts-{}", std::process::id()));
    let (work, home) = (dir.join("work"), dir.join("home"));
    std::fs::create_dir_all(&work).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    let file = work.join("README.md");
    std::fs::write(&file, "hello").unwrap();
    let input = json!({"path": file.to_string_lossy()});
    let call = request(
        json!("Read"),
        input,
        &work.to_string_lossy(),
        &home.to_string_lossy(),
    );
    let benign = native_read_verdict(&inputs(Some(call.clone())));
    let mut oversized = call;
    oversized
        .host
        .environment
        .extend((0..200).map(|index| (format!("K{index}"), "v".to_owned())));
    let oversized_verdict = native_read_verdict(&inputs(Some(oversized)));
    let _ = std::fs::remove_dir_all(&dir);
    assert!(benign, "plain file read should be benign");
    assert!(!oversized_verdict);
}

#[test]
fn non_read_tool_is_not_benign() {
    let root = std::env::temp_dir().canonicalize().unwrap();
    let root = root.to_string_lossy().into_owned();
    let call = request(
        json!("Bash"),
        json!({"command": "touch marker"}),
        &root,
        &root,
    );
    assert!(!native_read_verdict(&inputs(Some(call))));
}
