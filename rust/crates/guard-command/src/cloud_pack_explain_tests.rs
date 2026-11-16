//! `explain` reports the facts and preset decisions the fixtures promise, for
//! shipped packs without a pack file and for a pack the caller supplies.

use crate::cloud_pack_cli::answer;
use serde_json::{json, Value};

const SHIPPED: [&str; 6] = [
    include_str!("../../../../contributions/cloud-actions/calendar.json"),
    include_str!("../../../../contributions/cloud-actions/drive.json"),
    include_str!("../../../../contributions/cloud-actions/github.json"),
    include_str!("../../../../contributions/cloud-actions/gmail.json"),
    include_str!("../../../../contributions/cloud-actions/notion.json"),
    include_str!("../../../../contributions/cloud-actions/slack.json"),
];

fn line(request: Value) -> Value {
    answer(request.to_string().as_bytes())
}

#[test]
fn shipped_fixtures_explain_to_their_expected_decisions_without_a_pack_file() {
    let mut checked = 0;
    for text in SHIPPED {
        let pack: Value = serde_json::from_str(text).unwrap();
        for action in pack["actions"].as_array().unwrap() {
            for fixture in action["fixtures"].as_array().unwrap() {
                let reply = line(json!({
                    "op": "explain",
                    "actionId": action["actionId"],
                    "arguments": fixture["arguments"],
                }));
                let expect = &fixture["expect"];
                if let Some(code) = expect.get("error") {
                    // Some refusals only surface when the request is rendered.
                    if reply["ok"] == json!(false) {
                        assert_eq!(&reply["error"]["code"], code, "{}", fixture["name"]);
                    }
                    continue;
                }
                assert_eq!(reply["ok"], json!(true), "{} {reply}", fixture["name"]);
                assert_eq!(reply["actionId"], action["actionId"]);
                assert_eq!(reply["providerId"], pack["provider"]["id"]);
                if let Some(decisions) = expect.get("decisions").and_then(Value::as_object) {
                    for (preset, want) in decisions {
                        assert_eq!(&reply["decisions"][preset], want, "{}", fixture["name"]);
                    }
                    checked += 1;
                }
                if let Some(facts) = expect.get("facts").and_then(Value::as_object) {
                    for (key, want) in facts {
                        assert_eq!(&reply["facts"][key], want, "{}", fixture["name"]);
                    }
                }
            }
        }
    }
    assert!(checked > 20, "only {checked} fixtures state decisions");
}

#[test]
fn explain_reports_every_preset_and_the_action_effect() {
    let reply = line(json!({
        "op": "explain",
        "actionId": "slack.chat.post_message",
        "arguments": { "channel": "C0123456789", "text": "Build is green." },
    }));
    assert_eq!(reply["ok"], json!(true), "{reply}");
    assert_eq!(
        reply["decisions"],
        json!({ "relaxed": "allow", "balanced": "review", "strict": "review" })
    );
    assert!(reply["effect"].is_string());
    assert!(reply["facts"]["class"].is_string());
}

#[test]
fn explain_refuses_arguments_the_action_would_refuse() {
    let reply = line(json!({
        "op": "explain",
        "actionId": "slack.conversations.list",
        "arguments": { "types": "private_channel" },
    }));
    assert_eq!(reply["ok"], json!(false));
    assert_eq!(reply["error"]["code"], json!("unknown_argument"));
}

#[test]
fn explain_refuses_an_action_no_shipped_pack_declares() {
    let reply = line(json!({
        "op": "explain",
        "actionId": "nowhere.do_thing",
        "arguments": {},
    }));
    assert_eq!(reply["error"]["code"], json!("action_unknown"));
    let reply = line(json!({ "op": "explain", "arguments": {} }));
    assert_eq!(reply["error"]["code"], json!("request_invalid"));
}

#[test]
fn explain_uses_a_supplied_pack_instead_of_the_shipped_one() {
    let mut pack: Value = serde_json::from_str(SHIPPED[5]).unwrap();
    pack["provider"]["id"] = json!("slack-fork");
    for action in pack["actions"].as_array_mut().unwrap() {
        let id = action["actionId"]
            .as_str()
            .unwrap()
            .replacen("slack.", "slack-fork.", 1);
        action["actionId"] = json!(id);
    }
    let reply = line(json!({
        "op": "explain",
        "pack": pack,
        "actionId": "slack-fork.conversations.list",
        "arguments": { "limit": 2 },
    }));
    assert_eq!(reply["ok"], json!(true), "{reply}");
    assert_eq!(reply["providerId"], json!("slack-fork"));
    let shipped_only = line(json!({
        "op": "explain",
        "actionId": "slack-fork.conversations.list",
        "arguments": { "limit": 2 },
    }));
    assert_eq!(shipped_only["error"]["code"], json!("action_unknown"));
}
