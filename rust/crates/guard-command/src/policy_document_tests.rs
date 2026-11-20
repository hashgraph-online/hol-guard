//! Replay frozen outcomes from the original Python implementation.

use std::time::{Duration, Instant};

use serde_json::{json, Value};

fn run(query: &str, body: &Value) -> Value {
    super::evaluate(query, body, Instant::now() + Duration::from_secs(30)).unwrap()
}

#[test]
fn original_python_policy_document_outcomes_replay() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/policy_document_parity.json"
    ))
    .unwrap();
    let vectors = fixture["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 1419);
    let mut failures = Vec::new();
    for (index, vector) in vectors.iter().enumerate() {
        let query = vector["query"].as_str().unwrap();
        let actual = run(query, &vector["body"]);
        if actual != vector["expected"] {
            failures.push(format!(
                "vector {index} {query}: {actual}, expected {}",
                vector["expected"]
            ));
        }
        if query == "from_mapping" && vector["expected"].get("ok").is_some() {
            let output = run(
                "to_mapping",
                &json!({
                    "class_name":vector["body"]["class_name"],"dto":vector["expected"]["ok"]["dto"]
                }),
            );
            if output["ok"] != vector["expected"]["ok"]["mapping"] {
                failures.push(format!("DTO serialization {index}: {output}"));
            }
        }
        if query == "compile"
            && vector["expected"]["ok"]
                .as_array()
                .is_some_and(|items| items.len() > 32)
        {
            let mut collected = Vec::new();
            let mut offset = 0;
            loop {
                let result = run(
                    "compile_page",
                    &json!({"document":vector["body"]["document"],"offset":offset,"limit":32}),
                );
                let page = &result["ok"];
                assert_eq!(page["offset"], offset);
                let items = page["items"].as_array().expect("bound page");
                assert!(!items.is_empty());
                collected.extend(items.iter().cloned());
                offset += items.len();
                if page["total"] == offset {
                    break;
                }
            }
            if json!(collected) != vector["expected"]["ok"] {
                failures.push(format!(
                    "paged compilation {index} differs from frozen original"
                ));
            }
        }
    }
    let boundary = &fixture["yaml_token_count_boundary"];
    assert_eq!(
        run(
            "validate_yaml_tokens",
            &json!({"tokens": vec![boundary["token"].clone(); boundary["count"].as_u64().unwrap() as usize]})
        ),
        boundary["expected"]
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn policy_document_deadlines_unknown_queries_and_page_bounds_fail_closed() {
    assert!(super::evaluate("canonical", &json!({"value":{}}), Instant::now()).is_err());
    assert_eq!(
        run("claimed_allow", &json!({}))["error"]["message"],
        "policy_document_query_invalid"
    );
    for (offset, limit) in [(0, 0), (0, 33), (10001, 32)] {
        assert!(run(
            "compile_page",
            &json!({"document":{},"offset":offset,"limit":limit})
        )
        .get("error")
        .is_some());
    }
}

#[test]
fn normative_policy_hashes_and_utf16_order_are_cross_language_stable() {
    for fixture in [
        include_str!("../../../../spec/guard-policy/v1alpha1/fixtures/hashes/basic.json"),
        include_str!(
            "../../../../spec/guard-policy/v1alpha1/fixtures/hashes/business-selector.json"
        ),
    ] {
        let vector: Value = serde_json::from_str(fixture).unwrap();
        let value: Value = serde_json::from_str(vector["canonicalJson"].as_str().unwrap()).unwrap();
        let parsed = run(
            "from_mapping",
            &json!({"class_name":"GuardPolicyDocument","value":value}),
        );
        let value = parsed["ok"]["mapping"].clone();
        assert_eq!(
            run("canonical", &json!({"value":value}))["ok"],
            vector["canonicalJson"]
        );
        assert_eq!(
            run("digest", &json!({"value":value}))["ok"],
            vector["sha256"]
        );
    }
    let result = run(
        "canonical",
        &json!({"value":{"\u{e000}":"bmp","😀":"astral"}}),
    );
    let encoded = result["ok"].as_str().unwrap();
    assert!(encoded.find("😀").unwrap() < encoded.find('\u{e000}').unwrap());
}

#[test]
fn extensions_round_trip_and_change_the_native_document_digest() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/policy_document_parity.json"
    ))
    .unwrap();
    let vector = fixture["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| {
            vector["query"] == "from_mapping"
                && vector["body"]["class_name"] == "GuardPolicyDocument"
                && vector["body"]["value"].get("x-extension").is_some()
        })
        .unwrap();
    let original = &vector["expected"]["ok"]["mapping"];
    assert!(original.get("x-extension").is_some());
    let mut dto = vector["expected"]["ok"]["dto"].clone();
    dto["extensions"] = json!([["x-document-note", "\"changed\""]]);
    let changed = run(
        "to_mapping",
        &json!({"class_name":"GuardPolicyDocument","dto":dto}),
    )["ok"]
        .clone();
    assert_eq!(changed["x-document-note"], "changed");
    assert_ne!(
        run("digest", &json!({"value":original}))["ok"],
        run("digest", &json!({"value":changed}))["ok"]
    );
}

fn document_with_commands(commands: Value) -> Value {
    json!({"spec":{"rules":[
        {"match":{"paths":["/tmp"]}},
        {"match":{"commands":commands}},
    ]}})
}

#[test]
fn every_command_expression_a_document_carries_comes_back_with_its_rule() {
    let output = run(
        "command_expressions",
        &json!({"value":document_with_commands(json!({
            "combinator":"any",
            "conditions":[
                {"field":"command","operator":"startsWith","value":"  docker   compose  "},
                {"field":"command","operator":"exact","value":"git push","caseSensitive":true},
            ],
        }))}),
    );

    assert_eq!(
        output["ok"],
        json!({"expressions":[{
            "index":1,
            "expression":{"combinator":"any","conditions":[
                {"operator":"startsWith","value":"docker compose","case_sensitive":false},
                {"operator":"exact","value":"git push","case_sensitive":true},
            ]},
        }]})
    );
}

#[test]
fn a_rule_outside_the_dialect_names_itself_on_the_ok_channel() {
    for (value, code) in [
        (
            json!({"field":"command","operator":"exact","value":" "}),
            "command_value_required",
        ),
        (
            json!({"field":"path","operator":"exact","value":"git push"}),
            "unsupported_command_condition_field",
        ),
        (
            json!({"field":"command","operator":"matches","value":"git push"}),
            "unsupported_command_pattern_operator",
        ),
    ] {
        let output = run(
            "command_expressions",
            &json!({"value":document_with_commands(json!({
                "combinator":"all","conditions":[value],
            }))}),
        );

        assert_eq!(output["ok"], json!({"invalid":{"index":1,"code":code}}));
    }
}

#[test]
fn a_document_without_command_rules_carries_no_expressions() {
    let output = run(
        "command_expressions",
        &json!({"value":json!({"spec":{"rules":[{"match":{"paths":["/tmp"]}}]}})}),
    );

    assert_eq!(output["ok"], json!({"expressions":[]}));
}

fn document_with_rule_match(effect: &str, matcher: Value) -> Value {
    json!({"document":{
        "apiVersion":"guard.hashgraphonline.com/v1alpha1","kind":"GuardPolicy",
        "metadata":{"id":"cloud-policy","name":"Cloud policy","revision":3},
        "spec":{"defaults":{"mode":"prompt"},"rules":[{
            "id":"block-install","enabled":true,"effect":effect,"match":matcher,
            "lifetime":{"mode":"permanent","expiresAt":null},
            "provenance":{"source":"cloud","createdAt":"2026-01-01T00:00:00Z"},
        }]},
    }})
}

fn exact_shell_id(command: &str) -> String {
    use sha2::{Digest, Sha256};
    format!(
        "memory:exact-shell-command:{}",
        hex::encode(Sha256::digest(command.as_bytes()))
    )
}

#[test]
fn an_exact_command_rule_compiles_to_the_key_the_hook_looks_up() {
    let command = "bun install --frozen-lockfile --ignore-scripts";
    let output = run(
        "compile",
        &document_with_rule_match("block", json!({"commands":[command]})),
    );

    let rows = output["ok"].as_array().expect("compiled rows");
    assert_eq!(rows.len(), 1, "{output}");
    let decision = &rows[0]["decision"];
    assert_eq!(decision["artifact_id"], exact_shell_id(command));
    assert_eq!(decision["action"], "block");
    assert_eq!(decision["scope"], "artifact");
    assert_eq!(decision["harness"], "*");
    assert_eq!(decision["workspace"], Value::Null);
    assert_eq!(rows[0]["rule_id"], "block-install");
}

#[test]
fn an_exact_command_rule_keeps_its_harness_and_workspace_narrowing() {
    let output = run(
        "compile",
        &document_with_rule_match(
            "block",
            json!({"commands":["git push","git push --force"],"harnesses":["codex","claude-code"],
                "workspaces":["/repo"]}),
        ),
    );

    let rows = output["ok"].as_array().expect("compiled rows");
    let mut keys: Vec<(String, String, String, String)> = rows
        .iter()
        .map(|row| {
            let decision = &row["decision"];
            (
                decision["artifact_id"].as_str().unwrap().to_owned(),
                decision["harness"].as_str().unwrap().to_owned(),
                decision["scope"].as_str().unwrap().to_owned(),
                decision["workspace"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    keys.sort();
    let mut expected = Vec::new();
    for command in ["git push", "git push --force"] {
        for harness in ["claude-code", "codex"] {
            expected.push((
                exact_shell_id(command),
                harness.to_owned(),
                "workspace".to_owned(),
                "/repo".to_owned(),
            ));
        }
    }
    expected.sort();
    assert_eq!(keys, expected);
}

#[test]
fn an_exact_command_cannot_be_combined_with_artifact_tool_or_publisher_selectors() {
    for (key, value) in [
        ("artifacts", json!(["npm:left-pad"])),
        ("tools", json!(["shell"])),
        ("publishers", json!(["acme"])),
    ] {
        let mut matcher = json!({"commands":["git push"]});
        matcher[key] = value;
        let output = run("compile", &document_with_rule_match("block", matcher));
        assert_eq!(
            output["error"]["code"], "unsupported_policy_match",
            "{key}: {output}"
        );
    }
}

#[test]
fn a_command_expression_still_needs_a_newer_runtime() {
    let output = run(
        "compile",
        &document_with_rule_match(
            "block",
            json!({"commands":{"combinator":"any","conditions":[
                {"field":"command","operator":"startsWith","value":"bun install"},
            ]}}),
        ),
    );
    assert_eq!(
        output["error"]["code"], "command_expression_requires_guard_3_1_runtime",
        "{output}"
    );
}

#[test]
fn a_local_policy_document_still_refuses_a_review_rule() {
    // Review rules arrive only in signed Cloud bundles (`compile_bundle`); a
    // local policy file or import keeps allowing or blocking.
    let output = run(
        "compile",
        &document_with_rule_match("review", json!({"tools":["mcp-tool"]})),
    );

    assert_eq!(
        output["error"]["code"], "unsupported_policy_effect",
        "{output}"
    );
}
