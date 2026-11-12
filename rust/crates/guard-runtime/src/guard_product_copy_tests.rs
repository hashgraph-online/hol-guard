use serde_json::{json, Value};

use super::*;

fn harness_facts(name: &str) -> Value {
    json!({
        "harness": name,
        "installed": true,
        "command_available": true,
        "managed": false,
        "scanned": true,
        "artifact_count": 1,
        "review_count": 0,
        "warning_count": 0,
        "approval_flow": null,
    })
}

fn args(harnesses: Vec<Value>) -> Value {
    json!({
        "harnesses": harnesses,
        "cloud_state": "local_only",
        "sync_url": null,
        "oauth_repair_required": false,
        "connect_retry_required": false,
        "connect_retry_refresh_race": false,
        "shared_proof_recorded": false,
        "approval_center_url": null,
        "runtime_state_present": false,
        "include_steps": true,
    })
}

fn copy(args: &Value) -> Value {
    dispatch(args).unwrap()
}

fn with(name: &str, update: impl FnOnce(&mut Value)) -> Value {
    let mut item = harness_facts(name);
    update(&mut item);
    item
}

#[test]
fn next_action_follows_scan_and_managed_state() {
    let cases = [
        (with("codex", |_| {}), "install"),
        (
            with("codex", |h| {
                h["installed"] = json!(false);
                h["command_available"] = json!(false);
            }),
            "install-harness",
        ),
        (with("codex", |h| h["managed"] = json!(true)), "run"),
        (
            with("codex", |h| {
                h["managed"] = json!(true);
                h["review_count"] = json!(2);
            }),
            "review",
        ),
        (
            with("codex", |h| {
                h["scanned"] = json!(false);
                h["installed"] = json!(false);
                h["command_available"] = json!(false);
            }),
            "install",
        ),
        (
            with("codex", |h| {
                h["scanned"] = json!(false);
                h["managed"] = json!(true);
            }),
            "run",
        ),
        (
            with("codex", |h| {
                h["scanned"] = json!(false);
                h["managed"] = json!(true);
                h["warning_count"] = json!(1);
            }),
            "review",
        ),
    ];
    for (item, expected) in cases {
        let result = copy(&args(vec![item.clone()]));
        assert_eq!(result["harnesses"][0]["next_action"], expected, "{item}");
    }
    let fields = &copy(&args(vec![harness_facts("cursor")]))["harnesses"][0];
    assert_eq!(fields["install_command"], "hol-guard install cursor");
    assert_eq!(fields["run_command"], "hol-guard run cursor --dry-run");
    assert_eq!(fields["review_command"], "hol-guard diff cursor");
    assert_eq!(fields["receipts_command"], "hol-guard receipts");
}

#[test]
fn approval_experience_rank_prefers_native_prompts() {
    let cases = [
        (json!(null), 4),
        (json!({}), 3),
        (json!({"prompt_channel": "hook", "tier": "mixed"}), 0),
        (
            json!({"prompt_channel": "native", "tier": "native-harness"}),
            0,
        ),
        (
            json!({"prompt_channel": "hook", "auto_open_browser": false}),
            1,
        ),
        (
            json!({"prompt_channel": "hook", "auto_open_browser": null}),
            1,
        ),
        (json!({"auto_open_browser": 0}), 2),
        (json!({"tier": ""}), 3),
        (json!({"tier": "native-harness"}), 4),
        (json!({"prompt_channel": true, "tier": "mixed"}), 4),
        (json!({"prompt_channel": "hook", "tier": 1}), 4),
    ];
    for (flow, expected) in cases {
        assert_eq!(approval_experience_rank(Some(&flow)), expected, "{flow}");
    }
    assert_eq!(approval_experience_rank(None), 4);
}

#[test]
fn recommended_harness_follows_python_sort_key() {
    assert_eq!(copy(&args(vec![]))["recommended"], Value::Null);
    let missing = with("codex", |h| h["installed"] = json!(false));
    let empty = with("claude-code", |h| h["artifact_count"] = json!(0));
    let browser = with("hermes", |h| h["approval_flow"] = json!({}));
    let unknown = with("zed", |h| h["approval_flow"] = json!({}));
    let native = with("opencode", |h| {
        h["approval_flow"] = json!({"prompt_channel": "hook", "tier": "mixed"});
    });
    let result = copy(&args(vec![
        missing.clone(),
        empty.clone(),
        unknown.clone(),
        browser.clone(),
    ]));
    assert_eq!(result["recommended"], 3);
    let result = copy(&args(vec![browser.clone(), native.clone()]));
    assert_eq!(result["recommended"], 1);
    // Equal keys keep the first harness.
    let result = copy(&args(vec![unknown.clone(), unknown]));
    assert_eq!(result["recommended"], 0);
    let no_command = with("codex", |h| h["command_available"] = json!(false));
    let result = copy(&args(vec![no_command, harness_facts("codex")]));
    assert_eq!(result["recommended"], 1);
}

#[test]
fn runtime_status_reads_center_then_state() {
    let mut value = args(vec![]);
    assert_eq!(copy(&value)["runtime_status"], "offline");
    value["runtime_state_present"] = json!(true);
    assert_eq!(copy(&value)["runtime_status"], "stale");
    value["approval_center_url"] = json!("");
    assert_eq!(copy(&value)["runtime_status"], "stale");
    value["approval_center_url"] = json!("http://127.0.0.1:5474");
    assert_eq!(copy(&value)["runtime_status"], "active");
}

#[test]
fn guard_urls_use_the_sync_origin() {
    let urls = |sync_url: Value| {
        let mut value = args(vec![]);
        value["sync_url"] = sync_url;
        let result = copy(&value);
        [
            result["dashboard_url"].clone(),
            result["connect_url"].clone(),
            result["inbox_url"].clone(),
            result["fleet_url"].clone(),
        ]
    };
    let default = [
        json!("https://hol.org/guard"),
        json!("https://hol.org/guard/connect"),
        json!("https://hol.org/guard/inbox"),
        json!("https://hol.org/guard/protect"),
    ];
    for sync_url in [
        json!(null),
        json!(""),
        json!("/api/guard/sync"),
        json!("https:///x"),
    ] {
        assert_eq!(urls(sync_url.clone()), default, "{sync_url}");
    }
    assert_eq!(
        urls(json!(
            " HTTPS://staging.example:8443/points/api/guard/receipts/sync?x=1"
        )),
        [
            json!("https://staging.example:8443/guard"),
            json!("https://staging.example:8443/guard/connect"),
            json!("https://staging.example:8443/guard/inbox"),
            json!("https://staging.example:8443/guard/protect"),
        ]
    );
}

#[test]
fn cloud_copy_puts_repair_first_and_names_the_connect_url() {
    let mut value = args(vec![]);
    value["sync_url"] = json!("https://example.test/api/guard/receipts/sync");
    let detail = |value: &Value| {
        copy(value)["cloud_state_detail"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    assert!(detail(&value).starts_with("Local Guard is active and keeps receipts"));
    assert_eq!(copy(&value)["cloud_state_label"], "Local only");
    value["cloud_state"] = json!("paired_active");
    assert_eq!(copy(&value)["cloud_state_label"], "Connected and active");
    assert!(detail(&value).contains("command center at https://example.test/guard for Home"));
    value["cloud_state"] = json!("paired_waiting");
    assert_eq!(
        copy(&value)["cloud_state_label"],
        "Connected, waiting for first sync"
    );
    assert!(detail(&value).ends_with("`hol-guard sync` to force a retry now."));
    value["connect_retry_required"] = json!(true);
    assert!(detail(&value).ends_with(
        "Run `hol-guard connect` or reopen https://example.test/guard/connect to repair the \
         first sync."
    ));
    value["shared_proof_recorded"] = json!(true);
    assert!(detail(&value).ends_with("to restore sync."));
    value["connect_retry_refresh_race"] = json!(true);
    assert!(detail(&value).ends_with("when you want shared proof restored."));
    value["oauth_repair_required"] = json!(true);
    assert_eq!(
        detail(&value),
        "Guard Cloud sign-in on this machine is incomplete. Run `hol-guard connect` or reopen \
         https://example.test/guard/connect to repair local authorization and resume sync."
    );
    value["cloud_state"] = json!("unknown");
    assert_eq!(copy(&value)["cloud_state_label"], "Local only");
}

#[test]
fn next_steps_follow_the_recommended_harness() {
    let titles = |value: &Value| {
        copy(value)["next_steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|step| step["title"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    };
    let none = copy(&args(vec![]));
    assert_eq!(none["next_steps"][0]["command"], "hol-guard detect");
    assert_eq!(none["next_steps"].as_array().unwrap().len(), 1);
    let mut value = args(vec![harness_facts("codex")]);
    assert_eq!(
        titles(&value),
        [
            "Install Guard for codex",
            "Run Guard before launch",
            "Inspect receipts",
            "Resolve queued approvals",
            "Optional cloud connect",
        ]
    );
    let steps = copy(&value)["next_steps"].clone();
    assert_eq!(steps[0]["command"], "hol-guard install codex");
    assert_eq!(steps[1]["command"], "hol-guard run codex --dry-run");
    assert_eq!(
        steps[1]["detail"],
        "Dry-run codex once so Guard records the current tool state before you rely on it."
    );
    value["harnesses"][0]["managed"] = json!(true);
    value["harnesses"][0]["review_count"] = json!(1);
    value["cloud_state"] = json!("paired_waiting");
    let steps = copy(&value)["next_steps"].clone();
    assert_eq!(steps[0]["title"], "Review changed codex tools");
    assert_eq!(steps[0]["command"], "hol-guard diff codex");
    assert_eq!(steps[4]["title"], "Open Guard Home");
    assert_eq!(steps[4]["command"], "https://hol.org/guard");
    value["harnesses"][0]["managed"] = json!(false);
    value["harnesses"][0]["installed"] = json!(false);
    value["harnesses"][0]["command_available"] = json!(false);
    let steps = copy(&value)["next_steps"].clone();
    assert_eq!(steps[0]["title"], "Install codex");
    assert_eq!(steps[0]["command"], "hol-guard detect");
    value["include_steps"] = json!(false);
    assert_eq!(copy(&value)["next_steps"], Value::Null);
}

#[test]
fn malformed_arguments_are_refused() {
    let mut cases = vec![json!([]), json!({})];
    for key in [
        "harnesses",
        "cloud_state",
        "sync_url",
        "oauth_repair_required",
        "approval_center_url",
        "runtime_state_present",
        "include_steps",
    ] {
        let mut missing = args(vec![]);
        missing.as_object_mut().unwrap().remove(key);
        cases.push(missing);
    }
    for (key, bad) in [
        ("installed", json!(1)),
        ("artifact_count", json!(-1)),
        ("review_count", json!("1")),
        ("harness", json!(null)),
        ("scanned", json!(null)),
    ] {
        cases.push(args(vec![with("codex", |h| h[key] = bad)]));
    }
    cases.push(args(vec![json!("codex")]));
    for case in cases {
        assert_eq!(dispatch(&case), Err(ERR_INVALID), "{case}");
    }
}
