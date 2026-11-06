//! Replays `zcode/zcode_hook_surface_vectors.json`, recorded from the original
//! Python `ZCodeHarnessAdapter.prepare_install` and `uninstall`, through the
//! native kind: every surface's new text must equal the bytes the Python
//! wrote, with the same saved `enabled` record and the same refusals.

use serde_json::{json, Value};

use crate::runner_authority_op::ERR_INVALID;
use crate::zcode_hook_surface::dispatch;

const VECTORS: &str = include_str!("../../testdata/zcode/zcode_hook_surface_vectors.json");

#[test]
fn replays_vectors_recorded_from_the_python_adapter() {
    let vectors: Value = serde_json::from_str(VECTORS).expect("vectors");
    assert_eq!(vectors["schema"], "hol-guard-zcode-hook-surface-vectors.v1");
    let cases = vectors["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 55);
    for case in cases {
        let name = case["name"].as_str().expect("case name");
        let expected = &case["expected"];
        let answer = dispatch(&case["request"]).unwrap_or_else(|error| panic!("{name}: {error}"));
        if expected.get("refusal").is_some() {
            assert_eq!(&answer, expected, "{name}");
            continue;
        }
        assert_eq!(answer["text"], expected["text"], "{name}");
        match expected.get("enabled") {
            Some(record) => {
                let text = answer["enabled"].as_str().expect("enabled text");
                let enabled: Value = serde_json::from_str(text).expect("enabled json");
                assert_eq!(&enabled, record, "{name}");
                assert_eq!(answer.as_object().map(|map| map.len()), Some(2), "{name}");
            }
            None => assert_eq!(answer, json!({ "text": expected["text"] }), "{name}"),
        }
    }
}

fn install_request(text: Value) -> Value {
    json!({
        "op": "install",
        "text": text,
        "path": "/home/user/.zcode/cli/config.json",
        "history": null,
        "managed_config_path": null,
        "desktop": true,
        "matchers": ["Bash"],
        "command": "guard-hook-bridge",
        "timeouts": {"PreToolUse": 30, "UserPromptSubmit": 20},
    })
}

#[test]
fn renders_the_handler_and_the_live_record() {
    let answer = dispatch(&install_request(json!(r#"{"hooks": {"enabled": 1.0}}"#)))
        .expect("install answer");
    let want = r#"{
  "hooks": {
    "enabled": true,
    "events": {
      "PreToolUse": [
        {
          "hooks": [
            {
              "type": "command",
              "command": "guard-hook-bridge # HOL_GUARD_MANAGED_ZCODE",
              "timeout": 30,
              "statusMessage": "HOL Guard runtime policy enforcement"
            }
          ],
          "matcher": "Bash"
        }
      ],
      "UserPromptSubmit": [
        {
          "hooks": [
            {
              "type": "command",
              "command": "guard-hook-bridge # HOL_GUARD_MANAGED_ZCODE",
              "timeout": 20,
              "statusMessage": "HOL Guard runtime policy enforcement"
            }
          ]
        }
      ]
    }
  },
  "mcp": {},
  "plugins": {}
}
"#;
    assert_eq!(answer["text"], want);
    assert_eq!(
        answer["enabled"],
        "{\n  \"present\": true,\n  \"value\": 1.0\n}"
    );
}

#[test]
fn refuses_a_lone_surrogate_it_would_write_back() {
    let lone = json!(r#"{"theme": "\ud800"}"#);
    assert_eq!(dispatch(&install_request(lone)), Err(ERR_INVALID));
    let mut uninstall = install_request(json!(r#"{"theme": "\ud800", "hooks": []}"#));
    let map = uninstall.as_object_mut().expect("request");
    for key in ["desktop", "matchers", "command", "timeouts"] {
        map.remove(key);
    }
    map.insert("op".to_owned(), json!("uninstall"));
    assert_eq!(dispatch(&uninstall), Ok(json!({ "text": null })));
}

#[test]
fn keeps_a_genuine_noncharacter_and_refuses_a_lone_surrogate_key() {
    for text in [r#"{"theme": "\ufdd0"}"#, "{\"theme\": \"\u{fdd0}\"}"] {
        let answer = dispatch(&install_request(json!(text))).expect("rendered");
        assert!(answer["text"]
            .as_str()
            .expect("text")
            .contains("\"theme\": \"\\ufdd0\""));
    }
    let key = json!(r#"{"\udc00": 1}"#);
    assert_eq!(dispatch(&install_request(key)), Err(ERR_INVALID));
}

#[test]
fn refuses_malformed_requests() {
    let good = install_request(Value::Null);
    assert!(dispatch(&good).is_ok());
    let mut cases: Vec<Value> = Vec::new();
    for (key, value) in [
        ("op", json!("repair")),
        ("op", json!(1)),
        ("text", json!({})),
        ("path", json!(null)),
        ("desktop", json!("yes")),
        ("matchers", json!("Bash")),
        ("matchers", json!([1])),
        ("command", json!(null)),
        ("timeouts", json!({"PreToolUse": 30})),
        ("timeouts", json!({"PreToolUse": 30, "UserPromptSubmit": 0})),
        (
            "timeouts",
            json!({"PreToolUse": true, "UserPromptSubmit": 30}),
        ),
        ("timeouts", json!({"PreToolUse": 30, "Stop": 30})),
        ("timeouts", json!([30, 30])),
    ] {
        let mut request = good.clone();
        request[key] = value;
        cases.push(request);
    }
    let mut extra = good.clone();
    extra["extra"] = json!(true);
    cases.push(extra);
    let mut missing = good.clone();
    missing.as_object_mut().expect("request").remove("history");
    cases.push(missing);
    let mut uninstall_with_matchers = good.clone();
    uninstall_with_matchers["op"] = json!("uninstall");
    uninstall_with_matchers["text"] = json!("{}");
    cases.push(uninstall_with_matchers);
    let mut uninstall_null = json!({
        "op": "uninstall",
        "text": null,
        "path": "/home/user/.zcode/cli/config.json",
        "history": null,
        "managed_config_path": null,
    });
    cases.push(uninstall_null.clone());
    uninstall_null["text"] = json!("{}");
    assert_eq!(dispatch(&uninstall_null), Ok(json!({ "text": null })));
    cases.push(json!(["install"]));
    for request in cases {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
}
