use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::{bridge_config, installed, Object, TOOL_MATCHER};
use crate::cursor_hook_command::Syntax;
use crate::transition_files::Fault;

fn object(value: Value) -> Object {
    value.as_object().cloned().unwrap()
}

const CONFIG: &str = r#"{"state_path":"/s","manifest_path":"/m","query":"q","fallback_command":["a"],"start_command":["b"],"hook_timeouts":{"PreToolUse":5}}"#;

fn handler() -> Value {
    json!({"type": "command", "command": format!("/rt codex-hook-bridge '{CONFIG}'")})
}

fn manifest(roles: &[&str]) -> Object {
    let group = json!({"matcher": TOOL_MATCHER, "hooks": [handler()]});
    let packaged: Vec<Value> = roles.iter().map(|role| json!({"role": role})).collect();
    object(json!({
        "events": [{
            "event": "PreToolUse",
            "group": group,
            "handler": handler(),
            "handler_index": 0,
            "argv": ["/rt", "codex-hook-bridge", CONFIG],
        }],
        "packaged_files": packaged,
    }))
}

fn config(groups: usize) -> Object {
    let group = json!({"matcher": TOOL_MATCHER, "hooks": [handler()]});
    object(json!({
        "features": {"hooks": true},
        "hooks": {"PreToolUse": vec![group; groups]},
    }))
}

fn reason(fault: Fault) -> String {
    match fault {
        Fault::Transition(reason) => reason.to_owned(),
        _ => String::new(),
    }
}

fn syntax() -> Syntax {
    Syntax::new(false, BTreeMap::new())
}

#[test]
fn the_configured_binding_yields_its_exact_argv_and_channel() {
    let modern = manifest(&["hook_probe", "native_receipt"]);
    let (argv, environment, channel) = installed(&modern, &config(1), &mut syntax()).unwrap();
    assert_eq!(argv, vec!["/rt", "codex-hook-bridge", CONFIG]);
    assert!(environment.is_empty());
    assert!(channel);
    let legacy = manifest(&[]);
    assert!(!installed(&legacy, &config(1), &mut syntax()).unwrap().2);
}

#[test]
fn a_disabled_duplicated_or_half_channel_binding_is_invalid() {
    let modern = manifest(&["hook_probe", "native_receipt"]);
    let mut disabled = config(1);
    disabled["features"]["hooks"] = json!(false);
    for (manifest, config) in [
        (modern.clone(), disabled),
        (modern.clone(), config(2)),
        (modern, config(0)),
        (manifest(&["hook_probe"]), config(1)),
    ] {
        let error = installed(&manifest, &config, &mut syntax()).unwrap_err();
        assert_eq!(reason(error), "admission_hook_binding_invalid");
    }
    let mut foreign = manifest(&[]);
    foreign["events"][0]["argv"] = json!(["/rt", "foreign", CONFIG]);
    assert!(installed(&foreign, &config(1), &mut syntax()).is_err());
    let mut env = manifest(&[]);
    env["events"][0]["handler"]["env"] = json!({"A": 1});
    assert!(installed(&env, &config(1), &mut syntax()).is_err());
}

#[test]
fn the_bridge_config_needs_every_field_and_one_positive_timeout() {
    let bridge = bridge_config(CONFIG).unwrap();
    assert_eq!(bridge.manifest_path, "/m");
    assert_eq!(bridge.fallback_command, vec!["a"]);
    for broken in [
        CONFIG.replace(r#""PreToolUse":5"#, r#""PreToolUse":0"#),
        CONFIG.replace(r#""manifest_path":"/m""#, r#""manifest_path":"""#),
        CONFIG.replace(r#"["a"]"#, "[]"),
        CONFIG.replace(r#""query":"q","#, ""),
        "[]".to_owned(),
    ] {
        assert!(bridge_config(&broken).is_none(), "{broken}");
    }
    let flagged = CONFIG.replace(r#""PreToolUse":5"#, r#""PreToolUse":true"#);
    assert!(bridge_config(&flagged).is_some());
}
