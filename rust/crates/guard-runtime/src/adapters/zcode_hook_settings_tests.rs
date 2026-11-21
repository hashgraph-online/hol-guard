//! Replays `zcode/hook_settings_vectors.json`, recorded from the original
//! Python ZCode adapter's `hooks` mapping handling, through the native plan
//! and build: the mapping Guard leaves behind must equal what the Python left
//! behind, key order included, with the same `enabled` record.

use guard_runtime_pyjson::{parse, PyVal};
use serde_json::{json, Value};

use crate::zcode_hook_settings::{has_handlers, install_hooks, recorded_enabled, uninstall_hooks};
use crate::zcode_hook_surface::enabled_text;

const VECTORS: &str = include_str!("../../testdata/zcode/hook_settings_vectors.json");

fn handlers(vectors: &Value) -> Vec<(String, PyVal)> {
    ["PreToolUse", "UserPromptSubmit"]
        .into_iter()
        .map(|name| {
            let text = vectors["handlers"][name].as_str().expect("handler text");
            (name.to_owned(), parse(text).expect("handler"))
        })
        .collect()
}

#[test]
fn replays_vectors_recorded_from_the_python_adapter() {
    let vectors: Value = serde_json::from_str(VECTORS).expect("vectors");
    let handlers = handlers(&vectors);
    let cases = vectors["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 118);
    for case in cases {
        let name = case["name"].as_str().expect("case name");
        let request = &case["request"];
        let expected = &case["expected"];
        let hooks = parse(request["hooks"].as_str().expect("hooks text")).expect("hooks");
        let after = if request["op"] == "install" {
            assert_eq!(
                json!(has_handlers(&hooks)),
                expected["has_handlers"],
                "{name}"
            );
            let matchers: Vec<&str> = request["matchers"]
                .as_array()
                .expect("matchers")
                .iter()
                .map(|matcher| matcher.as_str().expect("matcher"))
                .collect();
            install_hooks(&hooks, &matchers, &handlers)
        } else {
            uninstall_hooks(&hooks)
        };
        let want = parse(expected["after"].as_str().expect("after text")).expect("after");
        assert_eq!(PyVal::Dict(after), want, "{name}");
        let saved = recorded_enabled(
            &hooks,
            request["path"].as_str().expect("path"),
            &request["history"],
            &request["managed_config_path"],
        );
        let enabled = enabled_text(&hooks, saved, false).expect("enabled record");
        let enabled: Value = serde_json::from_str(&enabled).expect("enabled json");
        assert_eq!(enabled, expected["enabled"], "{name}");
    }
}

#[test]
fn keeps_user_entries_and_refreshes_guard_groups() {
    let guard = "old --harness zcode # HOL_GUARD_MANAGED_ZCODE";
    let text = format!(
        r#"{{"Stop": [{{"hooks": [{{"command": "echo stop"}}]}}],
            "events": {{"PreToolUse": [{{"matcher": "Bash", "x": 1,
                "hooks": [{{"command": "mine"}}, {{"command": "{guard}"}}]}}]}}}}"#
    );
    let hooks = parse(&text).expect("hooks");
    let handlers = vec![
        ("PreToolUse".to_owned(), PyVal::Str("pre".to_owned())),
        (
            "UserPromptSubmit".to_owned(),
            PyVal::Str("prompt".to_owned()),
        ),
    ];
    let after = PyVal::Dict(install_hooks(&hooks, &["Bash", "Read"], &handlers));
    let want = parse(
        r#"{"events": {
            "PreToolUse": [
                {"matcher": "Bash", "x": 1, "hooks": [{"command": "mine"}, "pre"]},
                {"hooks": ["pre"], "matcher": "Read"}],
            "Stop": [{"hooks": [{"command": "echo stop"}]}],
            "UserPromptSubmit": [{"hooks": ["prompt"]}]}}"#,
    )
    .expect("want");
    assert_eq!(after, want);
    let pruned = PyVal::Dict(uninstall_hooks(&after));
    assert_eq!(pruned, after, "plain handlers are never Guard's");
}
