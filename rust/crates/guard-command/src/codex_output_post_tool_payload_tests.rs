//! The post-tool reviews read their command texts from the payload; older
//! clients still send the list they derived.

use std::fs;
use std::path::PathBuf;

use serde_json::{json, Value};

use super::{review_post_tool_read_only_payload, Input};
use crate::codex_output_env::{Ctx, GitCheck, GitRun, InspectionHost};

struct Host;

impl InspectionHost for Host {
    fn env(&self, _: &str) -> Option<String> {
        None
    }
    fn git_executable(&self) -> Option<String> {
        None
    }
    fn git_safety(&self, _: GitCheck, _: Option<&str>, _: &[String]) -> bool {
        false
    }
    fn git_binary_trusted(&self, _: &str, _: &str) -> bool {
        false
    }
    fn run_git(&self, _: &str, _: &[String], _: &str) -> GitRun {
        GitRun::Failed("payload tests do not run git")
    }
    fn path_exists(&self, path: &str) -> bool {
        fs::symlink_metadata(path).is_ok()
    }
    fn real_path(&self, path: &str) -> Option<String> {
        fs::canonicalize(path)
            .ok()
            .map(|path| path.to_string_lossy().into_owned())
    }
}

fn scratch(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "guard-post-tool-payload-{}-{name}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("home")).unwrap();
    fs::create_dir_all(root.join("src")).unwrap();
    fs::canonicalize(root).unwrap()
}

fn output_body(tool_input: Value) -> Value {
    json!({
        "harness_label": "Codex",
        "tool_label": "Bash",
        "tool_name": "Bash",
        "tool_input": tool_input,
        "arguments": null,
        "tool_input_present": true,
        "response_text": "",
        "cwd": null,
        "home_dir": null,
        "deadline_ms": 5_000,
    })
}

#[test]
fn an_output_review_reads_the_commands_from_the_payload() {
    let body = output_body(json!({"command": " ls -l ", "commands": ["pwd"]}));
    let input = Input::parse(&body).unwrap();
    assert_eq!(input.command_texts, ["ls -l", "pwd"]);
}

#[test]
fn an_older_client_list_is_still_the_one_reviewed() {
    let mut body = output_body(json!({"command": "ls -l"}));
    body["command_texts"] = json!(["cat README.md"]);
    let input = Input::parse(&body).unwrap();
    assert_eq!(input.command_texts, ["cat README.md"]);

    body["command_texts"] = json!([7]);
    assert!(Input::parse(&body).is_err());
    body["command_texts"] = json!([]);
    body["extra"] = json!(true);
    assert!(Input::parse(&body).is_err());
}

/// The verdict for one payload, run against a fresh tree named for the test.
fn verdict(name: &str, tool_name: &str, tool_input: Value) -> Result<bool, &'static str> {
    verdict_with(name, tool_name, tool_input, |_| {})
}

fn verdict_with(
    name: &str,
    tool_name: &str,
    tool_input: Value,
    edit: impl FnOnce(&mut Value),
) -> Result<bool, &'static str> {
    let root = scratch(name);
    let home = root.join("home");
    let mut body = json!({
        "tool_name": tool_name,
        "tool_input": tool_input,
        "cwd": root.to_string_lossy(),
        "home_dir": home.to_string_lossy(),
    });
    edit(&mut body);
    let ctx = Ctx::new(&Host, &root.to_string_lossy(), &home.to_string_lossy());
    review_post_tool_read_only_payload(&ctx, &body)
}

#[test]
fn a_batch_of_source_searches_is_read_only() {
    let input = json!({"commands": ["rg foo src", "grep bar src/app.py"]});
    assert_eq!(verdict("batch", "Bash", input), Ok(true));
}

#[test]
fn a_payload_naming_no_command_or_a_mutating_one_is_not_read_only() {
    assert_eq!(verdict("none", "Bash", json!({})), Ok(false));
    assert_eq!(
        verdict("mutating", "Bash", json!({"command": "rm -rf src"})),
        Ok(false)
    );
    let mixed = json!({"commands": ["rg foo src", "rm -rf src"]});
    assert_eq!(verdict("mixed", "Bash", mixed), Ok(false));
}

#[test]
fn a_payload_past_the_per_command_bounds_is_not_read_only() {
    let searches = |count: usize| -> Vec<String> {
        (0..count)
            .map(|index| format!("rg foo src/a{index}"))
            .collect()
    };
    assert_eq!(
        verdict("at-bound", "Bash", json!({ "commands": searches(256) })),
        Ok(true)
    );
    assert_eq!(
        verdict("past-bound", "Bash", json!({ "commands": searches(257) })),
        Ok(false)
    );
    let long = format!("rg {} src", "a".repeat(64 * 1024));
    assert_eq!(
        verdict("long", "Bash", json!({ "command": long })),
        Ok(false)
    );
}

#[test]
fn a_malformed_payload_is_refused() {
    let input = json!({"command": "ls"});
    let extra = verdict_with("extra", "Bash", input.clone(), |body| {
        body["session_id"] = json!("s");
    });
    assert!(extra.is_err());
    let missing = verdict_with("missing", "Bash", input.clone(), |body| {
        body.as_object_mut().unwrap().remove("home_dir");
    });
    assert!(missing.is_err());
    let relative = verdict_with("relative", "Bash", input, |body| {
        body["cwd"] = json!("src");
    });
    assert!(relative.is_err());
}

/// The caller flattened the tool response before sending it, so whatever it
/// missed never reached the scan. The response now travels whole and the text
/// is read here, so a caller that flattened nothing still has its output
/// scanned.
#[test]
fn a_whole_tool_response_is_read_here() {
    let mut body = output_body(json!({"command": "ls"}));
    body["tool_response"] = json!({"stdout": "AWS_SECRET_ACCESS_KEY=abc"});
    let input = Input::parse(&body).unwrap();
    assert_eq!(input.response_text, "AWS_SECRET_ACCESS_KEY=abc");
}

/// A caller that flattened the response the same way must not have its text
/// counted twice, and one that appended its own captured output keeps that
/// text beside what the response says.
#[test]
fn a_flattened_response_is_not_repeated() {
    let mut body = output_body(json!({"command": "ls"}));
    body["tool_response"] = json!({"stdout": "token=abc"});
    body["response_text"] = json!("token=abc\ntrailing stdout");
    let input = Input::parse(&body).unwrap();
    assert_eq!(input.response_text, "token=abc\ntrailing stdout");

    body["response_text"] = json!("only what the caller captured");
    let input = Input::parse(&body).unwrap();
    assert_eq!(
        input.response_text,
        "token=abc\nonly what the caller captured"
    );
}

/// A line of the response that merely occurs inside a longer line the caller
/// sent has not been read: `token=abc` is its own secret even when the caller
/// happened to send `xtoken=abcdef`.
#[test]
fn a_line_inside_a_longer_one_is_not_read_yet() {
    let mut body = output_body(json!({"command": "ls"}));
    body["tool_response"] = json!({"stdout": "token=abc"});
    body["response_text"] = json!("xtoken=abcdef");
    let input = Input::parse(&body).unwrap();
    assert_eq!(input.response_text, "token=abc\nxtoken=abcdef");
}

/// The comparison hashes the caller's lines once rather than searching its
/// whole text per response line, so a large response that the caller already
/// flattened is read well inside the hook deadline.
#[test]
fn a_large_flattened_response_is_compared_once() {
    let text: String = (0..50_000)
        .map(|line| format!("line {line} of the tool response\n"))
        .collect();
    let mut body = output_body(json!({"command": "ls"}));
    body["tool_response"] = json!({"stdout": text});
    body["response_text"] = json!(text);
    let started = std::time::Instant::now();
    let input = Input::parse(&body).unwrap();
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "comparing a flattened response took {:?}",
        started.elapsed()
    );
    assert_eq!(input.response_text, text);
}

/// The walk reads the named output keys at the top level and everything below
/// them, so a secret nested under a key this scan does not name is still read
/// once something it does name carries it.
#[test]
fn the_walk_reads_below_a_named_key_but_not_beside_one() {
    let mut body = output_body(json!({"command": "ls"}));
    body["tool_response"] = json!({
        "metadata": {"ignored": "beside a named key"},
        "result": {"nested": {"deeper": "token=abc"}},
    });
    let input = Input::parse(&body).unwrap();
    assert_eq!(input.response_text, "token=abc");
}

/// The walk stops rather than following a response that nests without end.
#[test]
fn the_walk_stops_at_its_depth() {
    let mut nested = json!("token=abc");
    for _ in 0..8 {
        nested = json!({"inner": nested});
    }
    let mut body = output_body(json!({"command": "ls"}));
    body["tool_response"] = json!({"result": nested});
    let input = Input::parse(&body).unwrap();
    assert_eq!(input.response_text, "");
}

/// An older caller sends no response at all, so the text it flattened stays
/// the text the scan reads.
#[test]
fn an_older_caller_keeps_the_text_it_sent() {
    let mut body = output_body(json!({"command": "ls"}));
    body["response_text"] = json!("token=abc");
    let input = Input::parse(&body).unwrap();
    assert_eq!(input.response_text, "token=abc");

    body["tool_response"] = Value::Null;
    let input = Input::parse(&body).unwrap();
    assert_eq!(input.response_text, "token=abc");
}

/// A response map is a `BTreeMap` here but the caller flattens it in the order
/// the response was built, so the two agree on what they read and not on the
/// order. A two-key response the caller already flattened must not be read
/// twice, whichever order it sent, and trimming what it sent changes nothing.
#[test]
fn a_flattened_response_is_not_repeated_whatever_its_key_order() {
    let mut body = output_body(json!({"command": "ls"}));
    body["tool_response"] = json!({"stdout": "A", "stderr": "B"});

    for supplied in ["A\nB", "B\nA", "\nA\nB\n"] {
        body["response_text"] = json!(supplied);
        let input = Input::parse(&body).unwrap();
        assert_eq!(input.response_text, supplied);
    }

    body["response_text"] = json!("A");
    let input = Input::parse(&body).unwrap();
    assert_eq!(input.response_text, "B\nA\nA");
}
