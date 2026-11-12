//! A harness that names the file it is about to touch under its own spelling
//! still reaches the envelope's target paths.

use std::path::Path;

use crate::hook_adapter_envelope::{normalize_harness_envelope, EnvelopeRequest, IntentSummary};
use crate::hook_adapter_paths::PathEnv;
use crate::hook_adapter_value::{parse_python_json, OMap, OValue};

fn target_paths(harness: &str, tool_name: &str, tool_input: &str) -> Vec<String> {
    let text = format!(
        r#"{{"hook_event_name":"PreToolUse","tool_name":"{tool_name}","tool_input":{tool_input}}}"#
    );
    let payload: OMap = parse_python_json(&text)
        .expect("payload json")
        .as_map()
        .expect("payload map")
        .clone();
    let request = EnvelopeRequest {
        harness,
        event_name: "PreToolUse",
        payload: &payload,
        workspace: Some("/srv/project"),
        home_dir: Some("/home/user"),
        devin_project_dir: None,
        env: PathEnv::default(),
    };
    let mut provider =
        |_: &str, _: Option<&Path>, _: Option<&Path>| -> Option<IntentSummary> { None };
    let envelope = normalize_harness_envelope(&request, &mut provider).expect("envelope");
    envelope
        .get("target_paths")
        .and_then(OValue::as_list)
        .expect("target_paths")
        .iter()
        .filter_map(OValue::non_blank_str)
        .map(str::to_owned)
        .collect()
}

#[test]
fn a_read_that_names_its_file_as_target_file_reaches_the_target_paths() {
    for (harness, tool, key) in [
        ("grok", "Read", "target_file"),
        ("grok", "Read", "targetFile"),
    ] {
        let paths = target_paths(
            harness,
            tool,
            &format!(r#"{{"{key}":"/srv/project/src/app.ts"}}"#),
        );
        assert!(
            paths.iter().any(|path| path.ends_with("app.ts")),
            "{harness} {tool} {key}: {paths:?}"
        );
    }
}

#[test]
fn two_reads_of_different_files_do_not_share_one_empty_target_list() {
    let first = target_paths("grok", "Read", r#"{"target_file":"/srv/project/a.ts"}"#);
    let second = target_paths("grok", "Read", r#"{"target_file":"/srv/project/b.ts"}"#);
    assert_ne!(
        first, second,
        "a path-free envelope would make every read look like the same action"
    );
}
