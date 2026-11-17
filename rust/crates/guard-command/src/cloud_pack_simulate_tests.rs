//! `simulate` decides stored facts the way the preset decides a fixture, names
//! the rules behind each decision and refuses input it cannot decide.

use crate::cloud_pack_cli::answer;
use crate::cloud_pack_simulate::MAX_SIMULATED_CALLS;
use serde_json::{json, Value};

const RELAXED: &str = include_str!("../../../../contributions/cloud-policy-packs/relaxed.json");

fn line(request: Value) -> Value {
    answer(request.to_string().as_bytes())
}

fn facts_of(action_id: &str, arguments: Value) -> Value {
    let reply = line(json!({ "op": "explain", "actionId": action_id, "arguments": arguments }));
    assert_eq!(reply["ok"], json!(true), "{reply}");
    reply["facts"].clone()
}

fn post_message() -> Value {
    json!({
        "provider": "slack",
        "actionId": "slack.chat.post_message",
        "facts": facts_of("slack.chat.post_message", json!({ "channel": "C0123456789", "text": "Build is green." })),
    })
}

fn relaxed_with_send_review() -> Value {
    let mut pack: Value = serde_json::from_str(RELAXED).unwrap();
    pack["rules"].as_array_mut().unwrap().push(json!({
        "family": "workspace",
        "summary": "Review sends in Slack.",
        "rule": {
            "rule_id": "relaxed.workspace.send_review",
            "action": "review",
            "match": { "action_id": "slack.*" },
            "facts": { "classes": ["send"] },
        },
    }));
    pack
}

#[test]
fn stored_facts_get_the_decision_explain_gives_each_preset() {
    for (preset, want) in [
        ("relaxed", "allow"),
        ("balanced", "review"),
        ("strict", "review"),
    ] {
        let reply = line(json!({ "op": "simulate", "preset": preset, "calls": [post_message()] }));
        assert_eq!(reply["ok"], json!(true), "{reply}");
        assert_eq!(reply["results"][0]["action"], json!(want), "{preset}");
    }
}

#[test]
fn a_draft_rule_names_the_calls_it_would_have_changed() {
    let read = json!({
        "provider": "slack",
        "actionId": "slack.conversations.list",
        "facts": facts_of("slack.conversations.list", json!({})),
    });
    let reply = line(json!({
        "op": "simulate",
        "policyPack": relaxed_with_send_review(),
        "calls": [post_message(), read, post_message()],
    }));
    assert_eq!(reply["ok"], json!(true), "{reply}");
    let results = reply["results"].as_array().unwrap();
    assert_eq!(results.len(), 3);
    for index in [0, 2] {
        assert_eq!(results[index]["action"], json!("review"));
        let matched = results[index]["matchedRuleIds"].as_array().unwrap();
        assert!(
            matched.contains(&json!("relaxed.workspace.send_review")),
            "{reply}"
        );
    }
    assert_eq!(results[1]["action"], json!("allow"));
    assert!(!results[1]["matchedRuleIds"]
        .as_array()
        .unwrap()
        .contains(&json!("relaxed.workspace.send_review")));
}

#[test]
fn a_flagged_session_is_read_from_the_stored_flow() {
    let mut call = post_message();
    call["sessionFlow"] = json!({
        "untrusted_content_seen": true,
        "sensitive_data_seen": true,
        "injection_signal_seen": false,
    });
    let clean = line(json!({ "op": "simulate", "preset": "strict", "calls": [post_message()] }));
    let flagged = line(json!({ "op": "simulate", "preset": "strict", "calls": [call] }));
    assert_eq!(flagged["ok"], json!(true), "{flagged}");
    let ids = |reply: &Value| reply["results"][0]["matchedRuleIds"].clone();
    assert!(
        !ids(&clean)
            .as_array()
            .unwrap()
            .contains(&json!("strict.r13.trifecta")),
        "{clean}"
    );
    assert!(
        ids(&flagged)
            .as_array()
            .unwrap()
            .contains(&json!("strict.r13.trifecta")),
        "{flagged}"
    );
}

#[test]
fn malformed_or_oversized_input_refuses_the_whole_request() {
    let mut bad_facts = post_message();
    bad_facts["facts"]["class"] = json!("teleport");
    let reply = line(
        json!({ "op": "simulate", "preset": "balanced", "calls": [post_message(), bad_facts] }),
    );
    assert_eq!(
        reply["error"],
        json!({ "code": "facts_invalid", "pointer": "/calls/1/facts" })
    );

    let mut payload = post_message();
    payload["arguments"] = json!({ "text": "never sent" });
    let reply = line(json!({ "op": "simulate", "preset": "balanced", "calls": [payload] }));
    assert_eq!(
        reply["error"],
        json!({ "code": "request_invalid", "pointer": "/calls/0" })
    );

    let mut provider = post_message();
    provider["provider"] = json!("Slack Workspace");
    let reply = line(json!({ "op": "simulate", "preset": "balanced", "calls": [provider] }));
    assert_eq!(reply["error"]["code"], json!("request_invalid"));

    let reply = line(json!({ "op": "simulate", "preset": "balanced" }));
    assert_eq!(
        reply["error"],
        json!({ "code": "request_invalid", "pointer": "/calls" })
    );

    let many: Vec<Value> = (0..=MAX_SIMULATED_CALLS).map(|_| post_message()).collect();
    let reply = line(json!({ "op": "simulate", "preset": "balanced", "calls": many }));
    assert_eq!(
        reply["error"],
        json!({ "code": "limit", "pointer": "/calls" })
    );
}

fn force_update() -> Value {
    json!({
        "provider": "github",
        "actionId": "github.git.force_update_branch",
        "facts": facts_of(
            "github.git.force_update_branch",
            json!({ "repository": "octo-org/widgets", "branch": "main", "sha": "0000000000000000000000000000000000000000" }),
        ),
    })
}

#[test]
fn the_declared_effect_outranks_the_fact_class() {
    // The action is destructive but records class `update`; reading the
    // effect from the class alone would report a laxer decision than explain.
    for (preset, want) in [
        ("relaxed", "review"),
        ("balanced", "block"),
        ("strict", "block"),
    ] {
        let reply = line(json!({ "op": "simulate", "preset": preset, "calls": [force_update()] }));
        assert_eq!(
            reply["results"][0]["action"],
            json!(want),
            "{preset} {reply}"
        );
    }
    let mut lowered = force_update();
    lowered["effect"] = json!("read");
    let reply = line(json!({ "op": "simulate", "preset": "balanced", "calls": [lowered] }));
    assert_eq!(reply["results"][0]["action"], json!("block"), "{reply}");
}

#[test]
fn an_action_no_shipped_pack_declares_needs_its_stored_effect() {
    let mut custom = post_message();
    custom["actionId"] = json!("acme.widgets.purge");
    custom["provider"] = json!("acme");
    let reply = line(json!({ "op": "simulate", "preset": "relaxed", "calls": [custom.clone()] }));
    assert_eq!(
        reply["error"],
        json!({ "code": "effect_unknown", "pointer": "/calls/0/effect" })
    );
    custom["effect"] = json!("admin");
    let reply = line(json!({ "op": "simulate", "preset": "relaxed", "calls": [custom] }));
    assert_eq!(reply["results"][0]["action"], json!("block"), "{reply}");
}

#[test]
fn a_connection_scoped_rule_matches_only_its_stored_connection() {
    let mut pack = relaxed_with_send_review();
    pack["rules"].as_array_mut().unwrap().last_mut().unwrap()["rule"]["match"]["connection_id"] =
        json!("production");
    let reply =
        line(json!({ "op": "simulate", "policyPack": pack.clone(), "calls": [post_message()] }));
    assert_eq!(
        reply["error"],
        json!({ "code": "scope_unknown", "pointer": "/calls/0/connectionId" })
    );
    let on = |connection: &str| {
        let mut call = post_message();
        call["connectionId"] = json!(connection);
        call
    };
    let reply = line(json!({
        "op": "simulate",
        "policyPack": pack,
        "calls": [on("production"), on("sandbox")],
    }));
    assert_eq!(reply["ok"], json!(true), "{reply}");
    let ids = |index: usize| reply["results"][index]["matchedRuleIds"].clone();
    assert!(
        ids(0)
            .as_array()
            .unwrap()
            .contains(&json!("relaxed.workspace.send_review")),
        "{reply}"
    );
    assert!(
        !ids(1)
            .as_array()
            .unwrap()
            .contains(&json!("relaxed.workspace.send_review")),
        "{reply}"
    );
}

#[test]
fn a_scoped_rule_needs_its_label_only_from_the_calls_it_covers() {
    let mut pack = relaxed_with_send_review();
    let rule = &mut pack["rules"].as_array_mut().unwrap().last_mut().unwrap()["rule"]["match"];
    rule["action_id"] = json!("slack.chat.post_message");
    rule["resource_id"] = json!("C0123456789");
    let mut other = post_message();
    other["actionId"] = json!("slack.conversations.list");
    other["facts"] = facts_of("slack.conversations.list", json!({}));
    let reply = line(json!({ "op": "simulate", "policyPack": pack.clone(), "calls": [other] }));
    assert_eq!(reply["ok"], json!(true), "{reply}");
    let reply =
        line(json!({ "op": "simulate", "policyPack": pack.clone(), "calls": [post_message()] }));
    assert_eq!(
        reply["error"],
        json!({ "code": "scope_unknown", "pointer": "/calls/0/resourceId" })
    );
    let named = |resource: Value| {
        let mut call = post_message();
        call["resourceId"] = resource;
        call
    };
    let reply = line(json!({
        "op": "simulate",
        "policyPack": pack,
        "calls": [named(Value::Null), named(json!("C0123456789"))],
    }));
    assert_eq!(reply["ok"], json!(true), "{reply}");
    let matched = |index: usize| {
        reply["results"][index]["matchedRuleIds"]
            .as_array()
            .unwrap()
            .contains(&json!("relaxed.workspace.send_review"))
    };
    assert!(!matched(0), "{reply}");
    assert!(matched(1), "{reply}");
}
