use std::fs;

use serde_json::{json, Value};

use super::dispatch;
use crate::runner_authority_op::ERR_INVALID;

const HOME: &str = "/nonexistent-guard-home";

fn launch(args: &[&str], workspace: Option<&str>) -> Vec<String> {
    let request = json!({
        "op": "argv",
        "args": args.join("\0"),
        "count": args.len(),
        "workspace": workspace,
    });
    let answer = dispatch(&request, HOME).unwrap();
    let joined = answer["argv"].as_str().unwrap();
    let argv: Vec<String> = joined.split('\0').map(str::to_owned).collect();
    assert_eq!(answer["count"], json!(argv.len()));
    argv
}

#[test]
fn no_arguments_open_the_workspace() {
    assert_eq!(launch(&[], Some("/work")), ["opencode", "/work"]);
    assert_eq!(launch(&[], None), ["opencode"]);
}

#[test]
fn subcommands_pass_through_untouched() {
    assert_eq!(
        launch(&["mcp", "list", "fix", "it"], Some("/work")),
        ["opencode", "mcp", "list", "fix", "it"]
    );
    assert_eq!(
        launch(&["run", "--", "x"], None),
        ["opencode", "run", "--", "x"]
    );
}

#[test]
fn trailing_words_become_one_prompt() {
    assert_eq!(
        launch(&["--model", "gpt-4", "fix", "the", "bug"], Some("/work")),
        [
            "opencode",
            "/work",
            "--model",
            "gpt-4",
            "--prompt",
            "fix the bug"
        ]
    );
    assert_eq!(
        launch(&["debug", "--verbose"], None),
        ["opencode", "--prompt", "debug --verbose"]
    );
    assert_eq!(launch(&[""], None), ["opencode", "--prompt", ""]);
}

#[test]
fn an_explicit_prompt_keeps_every_argument() {
    assert_eq!(
        launch(&["-m", "x", "--prompt=hi", "more"], None),
        ["opencode", "-m", "x", "--prompt=hi", "more"]
    );
    assert_eq!(
        launch(&["fix", "--prompt", "hi"], None),
        ["opencode", "fix", "--prompt", "hi"]
    );
}

#[test]
fn double_dash_ends_the_options() {
    assert_eq!(
        launch(&["-s", "abc", "--", "-v", "now"], None),
        ["opencode", "-s", "abc", "--prompt", "-v now"]
    );
    assert_eq!(
        launch(&["--continue", "--"], None),
        ["opencode", "--continue"]
    );
}

#[test]
fn optional_values_follow_python_rules() {
    assert_eq!(
        launch(&["--port", "4096", "go"], None),
        ["opencode", "--port", "4096", "--prompt", "go"]
    );
    // `str.isdigit` accepts any Unicode digit, and nothing else.
    assert_eq!(
        launch(&["--port", "\u{0663}\u{00b2}", "go"], None),
        ["opencode", "--port", "\u{0663}\u{00b2}", "--prompt", "go"]
    );
    assert_eq!(
        launch(&["--port", "x1", "go"], None),
        ["opencode", "--port", "--prompt", "x1 go"]
    );
    assert_eq!(
        launch(&["--title", "My run", "go"], None),
        ["opencode", "--title", "My run", "--prompt", "go"]
    );
    assert_eq!(
        launch(&["--title", "-c", "go"], None),
        ["opencode", "--title", "-c", "--prompt", "go"]
    );
    assert_eq!(
        launch(&["--model=gpt", "go"], None),
        ["opencode", "--model=gpt", "--prompt", "go"]
    );
    assert_eq!(launch(&["--model"], None), ["opencode", "--model"]);
}

#[test]
fn refuses_malformed_argv_requests() {
    for request in [
        json!({ "op": "argv", "args": "a\0b", "count": 3, "workspace": null }),
        json!({ "op": "argv", "args": "a", "count": 0, "workspace": null }),
        json!({ "op": "argv", "args": [], "count": 0, "workspace": null }),
        json!({ "op": "argv", "args": "", "count": 0, "workspace": 1 }),
        json!({ "op": "argv", "args": "", "count": 0 }),
        json!({ "op": "launch", "args": "", "count": 0, "workspace": null }),
    ] {
        assert_eq!(dispatch(&request, HOME), Err(ERR_INVALID), "{request}");
    }
}

fn environment(overlay: Option<&str>, inline: Option<&str>) -> Value {
    let home = tempfile::tempdir().unwrap();
    if let Some(overlay) = overlay {
        fs::create_dir(home.path().join("opencode")).unwrap();
        fs::write(home.path().join("opencode/runtime-config.json"), overlay).unwrap();
    }
    let request = json!({ "op": "environment", "inline": inline });
    dispatch(&request, home.path().to_str().unwrap()).unwrap()["content"].clone()
}

#[test]
fn no_overlay_sets_nothing() {
    assert_eq!(environment(None, Some("{\"a\": 1}")), Value::Null);
    assert_eq!(environment(Some("not-json!"), None), Value::Null);
    assert_eq!(environment(Some("[1]"), None), Value::Null);
}

#[test]
fn overlay_merges_over_the_inline_config_in_order() {
    let content = environment(
        Some(r#"{"mcp": {"b": {"enabled": false}, "c": 1}, "permission": "ask"}"#),
        Some(
            r#"{"z": 1.0, "mcp": {"b": {"command": ["x"]}, "a": 2}, "permission": {"bash": "allow"}}"#,
        ),
    );
    assert_eq!(
        content,
        json!(
            r#"{"z": 1.0, "mcp": {"b": {"command": ["x"], "enabled": false}, "a": 2, "c": 1}, "permission": "ask"}"#
        )
    );
}

#[test]
fn unusable_inline_config_is_ignored() {
    let overlay = Some(r#"{"é": NaN}"#);
    let expected = json!(r#"{"\u00e9": NaN}"#);
    for inline in [None, Some(""), Some("{"), Some("[1, 2]"), Some("\"text\"")] {
        assert_eq!(environment(overlay, inline), expected, "{inline:?}");
    }
}

#[test]
fn refuses_malformed_environment_requests() {
    for request in [
        json!({ "op": "environment", "inline": 1 }),
        json!({ "op": "environment" }),
        json!({ "op": "environment", "inline": null, "overlay_path": "/x" }),
    ] {
        assert_eq!(dispatch(&request, HOME), Err(ERR_INVALID), "{request}");
    }
    let request = json!({ "op": "environment", "inline": null });
    assert_eq!(dispatch(&request, ""), Err(ERR_INVALID));
}
