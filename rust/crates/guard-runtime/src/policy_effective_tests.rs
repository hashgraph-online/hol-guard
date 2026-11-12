use super::*;

const FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../tests/fixtures/policy_effective_parity.json"
));

fn call(request: &Value) -> Value {
    let bytes = evaluate(request.to_string().as_bytes()).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn base() -> Value {
    json!({"protection_posture": "protected", "security_level": "balanced", "mode": "prompt"})
}

/// The legacy composer reported a distinct reason for provider actions; the
/// caller treats every policy rejection alike, so both map to one reason.
fn reason(value: &Value) -> &str {
    match value.as_str().unwrap_or_default() {
        "native_policy_snapshot_provider_actions_invalid" => POLICY_INVALID,
        other => other,
    }
}

#[test]
fn python_parity_vectors_match() {
    let cases: Vec<Value> = serde_json::from_str(FIXTURE).unwrap();
    assert!(cases.len() > 80);
    let mut mismatches = Vec::new();
    for case in &cases {
        let request = json!({
            "schema": SCHEMA,
            "op": case["op"],
            "guard_config": case["guard_config"],
            "configs": case["configs"],
        });
        let actual = call(&request);
        let expected = &case["expected"];
        let matched = if expected["ok"] == json!(true) {
            actual["ok"] == json!(true) && actual["policy"] == expected["policy"]
        } else {
            actual["ok"] == json!(false) && reason(&actual["error"]) == reason(&expected["error"])
        };
        if !matched {
            mismatches.push(format!(
                "{}: expected {expected} got {actual}",
                case["name"]
            ));
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

#[test]
fn unknown_request_fields_and_schema_are_rejected() {
    let bad = json!({"schema": SCHEMA, "op": "effective", "configs": [base()], "extra": 1});
    assert!(evaluate(bad.to_string().as_bytes()).is_err());
    let wrong = json!({"schema": "other", "op": "effective", "configs": [base()]});
    assert_eq!(call(&wrong)["ok"], json!(false));
    let unknown_op = json!({"schema": SCHEMA, "op": "merge", "configs": [base()]});
    assert_eq!(call(&unknown_op)["ok"], json!(false));
}

#[test]
fn effective_needs_exactly_one_config_and_compose_at_least_one() {
    let two = json!({"schema": SCHEMA, "op": "effective", "configs": [base(), base()]});
    assert_eq!(call(&two)["ok"], json!(false));
    let none = json!({"schema": SCHEMA, "op": "compose", "configs": []});
    assert_eq!(call(&none)["ok"], json!(false));
}

#[test]
fn compose_never_downgrades_an_enforcing_posture() {
    let mut watch = base();
    watch["protection_posture"] = json!("watch");
    watch["mode"] = json!("observe");
    let request = json!({"schema": SCHEMA, "op": "compose", "configs": [watch, base()]});
    let response = call(&request);
    assert_eq!(response["policy"]["protection_posture"], json!("protected"));
    assert_eq!(response["policy"]["mode"], json!("enforce"));
}

#[test]
fn oversized_request_is_rejected_before_parsing() {
    let big = vec![b' '; MAX_REQUEST_BYTES as usize + 1];
    assert_eq!(
        run_command(&big[..]).unwrap_err(),
        "policy_effective_request_too_large"
    );
    assert_eq!(
        run_command(&b"not json"[..]).unwrap_err(),
        "policy_effective_request_invalid"
    );
}

#[test]
fn raw_observed_choices_have_their_own_budget() {
    let head = json!({"schema": SCHEMA, "op": "compose", "configs": [base()]}).to_string();
    let head = head.strip_suffix('}').unwrap();
    // Configuration that fills its whole budget, then more observed allows
    // than the composed policy can hold.
    let padding = " ".repeat(CONFIG_BUDGET_BYTES as usize - head.len() - 1);
    let observed: Map<String, Value> = (0..20_000)
        .map(|index| (format!("codex:mcp__server__tool_{index}"), json!("allow")))
        .collect();
    let tail = json!({"mcp_tool_actions": observed}).to_string();
    let request = format!("{head}{padding},\"observed\":{tail}}}");
    assert!(request.len() as u64 > CONFIG_BUDGET_BYTES);
    let response: Value =
        serde_json::from_slice(&run_command(request.as_bytes()).unwrap()).unwrap();
    assert_eq!(response["ok"], json!(true), "{response}");
    assert_eq!(
        response["policy"]["mcp_tool_actions"]
            .as_object()
            .unwrap()
            .len(),
        guard_policy_snapshot::POLICY_SNAPSHOT_MAX_MCP_TOOL_ACTIONS
    );
    // Without an overlay the configuration keeps its original limit.
    let alone = format!("{head}{padding}  }}");
    assert_eq!(
        run_command(alone.as_bytes()).unwrap_err(),
        "policy_effective_request_too_large"
    );
    // With one, the configuration still cannot take the overlay's room.
    let mut config = base();
    config["padding"] = json!("x".repeat(CONFIG_BUDGET_BYTES as usize));
    let crowded = json!({"schema": SCHEMA, "op": "compose", "configs": [config],
        "observed": {"mcp_tool_actions": {}}})
    .to_string();
    assert!(crowded.len() as u64 <= MAX_REQUEST_BYTES);
    assert_eq!(
        run_command(crowded.as_bytes()).unwrap_err(),
        "policy_effective_request_too_large"
    );
}

fn compose_with(configured: Value, observed: Value) -> Value {
    let mut config = base();
    config["mcp_tool_actions"] = configured;
    call(&json!({
        "schema": SCHEMA,
        "op": "compose",
        "configs": [config],
        "observed": observed,
    }))
}

#[test]
fn observed_choices_keep_configured_restrictions() {
    // An exact choice is read before a namespace, so a stored review under a
    // configured namespace block would lower that tool to review.
    for choice in ["allow", "review"] {
        for configured in [
            json!({"codex:mcp__server__read": "block", "codex:mcp__other__write": "block"}),
            json!({"codex:mcp__server__*": "block"}),
        ] {
            let response = compose_with(
                configured.clone(),
                json!({"mcp_tool_actions": {
                    "codex:mcp__server__read": choice,
                    "codex:mcp__unrelated__search": "allow",
                }}),
            );
            assert_eq!(response["ok"], json!(true), "{response}");
            let actions = &response["policy"]["mcp_tool_actions"];
            for (key, action) in configured.as_object().unwrap() {
                assert_eq!(&actions[key], action);
            }
            assert_eq!(actions["codex:mcp__unrelated__search"], json!("allow"));
            for looser in ["allow", "review"] {
                assert_ne!(
                    actions["codex:mcp__server__read"],
                    json!(looser),
                    "{choice}"
                );
            }
        }
    }
}

#[test]
fn a_choice_only_tightens_a_configured_action() {
    let response = compose_with(
        json!({"codex:mcp__server__read": "review"}),
        json!({"mcp_tool_actions": {
            "codex:mcp__server__read": "allow",
            "codex:mcp__server__write": "block",
        }}),
    );
    let actions = &response["policy"]["mcp_tool_actions"];
    assert_eq!(actions["codex:mcp__server__read"], json!("review"));
    assert_eq!(actions["codex:mcp__server__write"], json!("block"));
}

#[test]
fn full_capacity_keeps_every_block_and_drops_only_allows() {
    let configured = "codex:mcp__zz_configured__blocked";
    let namespace = "codex:mcp__zz_namespace__*";
    let mut observed: Map<String, Value> = (0..1100)
        .map(|index| (format!("codex:mcp__server__tool_{index}"), json!("allow")))
        .collect();
    observed.insert(namespace.into(), json!("block"));
    observed.insert("codex:mcp__server__allowed".into(), json!("allow"));
    let response = compose_with(
        json!({configured: "block"}),
        json!({"mcp_tool_actions": observed}),
    );
    assert_eq!(response["ok"], json!(true), "{response}");
    let actions = response["policy"]["mcp_tool_actions"].as_object().unwrap();
    assert_eq!(
        actions.len(),
        guard_policy_snapshot::POLICY_SNAPSHOT_MAX_MCP_TOOL_ACTIONS
    );
    assert_eq!(actions[configured], json!("block"));
    assert_eq!(actions[namespace], json!("block"));
}

#[test]
fn capacity_never_silently_discards_a_restriction() {
    for restriction in ["block", "review"] {
        let observed: Map<String, Value> = (0
            ..=guard_policy_snapshot::POLICY_SNAPSHOT_MAX_MCP_TOOL_ACTIONS)
            .map(|index| {
                (
                    format!("codex:mcp__server__tool_{index}"),
                    json!(restriction),
                )
            })
            .collect();
        let response = compose_with(json!({}), json!({"mcp_tool_actions": observed}));
        assert_eq!(response["ok"], json!(false));
        assert_eq!(
            response["error"],
            json!("native_mcp_permission_capacity_exceeded")
        );
    }
}

#[test]
fn an_unknown_observed_action_is_rejected() {
    let response = compose_with(
        json!({}),
        json!({"mcp_tool_actions": {"codex:mcp__server__read": "maybe"}}),
    );
    assert_eq!(response["error"], json!(POLICY_INVALID));
}

#[test]
fn provider_choices_tighten_and_the_catalog_hash_is_bound() {
    let send = "codex:mcp__codex_apps__composio__:composio:all-accounts:GMAIL_SEND";
    let read = "codex:mcp__codex_apps__composio__:composio:all-accounts:GMAIL_READ";
    let mut config = base();
    config["mcp_provider_actions"] = json!({send: "block"});
    let digest = "c".repeat(64);
    let response = call(&json!({
        "schema": SCHEMA,
        "op": "compose",
        "configs": [config],
        "observed": {
            "mcp_provider_actions": {send: "review", read: "review"},
            "mcp_provider_catalog_hash": digest,
        },
    }));
    assert_eq!(response["ok"], json!(true), "{response}");
    let policy = &response["policy"];
    assert_eq!(policy["mcp_provider_actions"][send], json!("block"));
    assert_eq!(policy["mcp_provider_actions"][read], json!("review"));
    assert_eq!(policy["mcp_provider_catalog_hash"], json!(digest));

    let allow = call(&json!({
        "schema": SCHEMA,
        "op": "compose",
        "configs": [base()],
        "observed": {"mcp_provider_actions": {read: "allow"}},
    }));
    assert_eq!(
        allow["error"],
        json!("native_policy_snapshot_provider_actions_invalid")
    );
}

#[test]
fn observed_choices_belong_only_to_a_composed_policy() {
    let request = json!({
        "schema": SCHEMA,
        "op": "effective",
        "configs": [base()],
        "observed": {"mcp_tool_actions": {}},
    });
    assert_eq!(call(&request)["ok"], json!(false));
    let unknown = json!({
        "schema": SCHEMA,
        "op": "compose",
        "configs": [base()],
        "observed": {"other": {}},
    });
    assert!(evaluate(unknown.to_string().as_bytes()).is_err());
}
