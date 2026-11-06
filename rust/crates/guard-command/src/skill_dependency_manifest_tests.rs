use super::*;

fn no_review(_name: &str) -> bool {
    false
}

fn statuses(value: &Value) -> Vec<(String, String)> {
    value["requirements"]
        .as_array()
        .expect("requirements")
        .iter()
        .map(|row| {
            (
                row["state"].as_str().expect("state").to_owned(),
                row["reason"].as_str().expect("reason").to_owned(),
            )
        })
        .collect()
}

fn manifest(tools: Value) -> String {
    json!({"schema_version": MANIFEST_SCHEMA, "tools": tools}).to_string()
}

fn declared(tools: Value) -> Value {
    parse_dependencies(true, Some(&manifest(tools)))
}

#[test]
fn an_absent_key_declares_nothing() {
    let parsed = parse_dependencies(false, None);
    assert_eq!(parsed["status"], "absent");
    assert_eq!(parsed["source"], DEPENDENCY_SOURCE);
    assert_eq!(parsed["tools"], json!([]));
}

#[test]
fn a_declaration_guard_cannot_read_is_invalid_not_absent() {
    assert_eq!(parse_dependencies(true, None)["status"], "invalid");
}

#[test]
fn a_well_formed_manifest_keeps_its_tools_in_order() {
    let parsed = declared(json!([
        {"connection_id": "local-cli.beta", "tool_name": "b.one"},
        {"connection_id": "local-cli.alpha", "tool_name": "a_one"},
    ]));
    assert_eq!(parsed["status"], "declared");
    assert_eq!(
        parsed["tools"],
        json!([
            {"connection_id": "local-cli.beta", "tool_name": "b.one"},
            {"connection_id": "local-cli.alpha", "tool_name": "a_one"},
        ])
    );
}

#[test]
fn one_bad_tool_invalidates_the_whole_declaration() {
    let parsed = declared(json!([
        {"connection_id": "local-cli.alpha", "tool_name": "fine"},
        {"connection_id": "local-cli.alpha", "tool_name": "-leading-dash"},
    ]));
    assert_eq!(parsed["status"], "invalid");
    assert_eq!(parsed["tools"], json!([]));
}

#[test]
fn a_repeated_pair_is_invalid_but_the_same_tool_on_another_cli_is_not() {
    let repeated = declared(json!([
        {"connection_id": "local-cli.alpha", "tool_name": "run"},
        {"connection_id": "local-cli.alpha", "tool_name": "run"},
    ]));
    assert_eq!(repeated["status"], "invalid");
    let distinct = declared(json!([
        {"connection_id": "local-cli.alpha", "tool_name": "run"},
        {"connection_id": "local-cli.beta", "tool_name": "run"},
    ]));
    assert_eq!(distinct["status"], "declared");
}

#[test]
fn the_manifest_shape_is_exact() {
    for text in [
        "",
        "[]",
        "\"declared\"",
        r#"{"schema_version": "guard.skill-dependencies.v1"}"#,
        r#"{"schema_version": "guard.skill-dependencies.v2", "tools": []}"#,
        r#"{"schema_version": "guard.skill-dependencies.v1", "tools": {}}"#,
        r#"{"schema_version": "guard.skill-dependencies.v1", "tools": [], "extra": 1}"#,
        r#"{"schema_version": "guard.skill-dependencies.v1", "tools": ["local-cli.alpha"]}"#,
        r#"{"schema_version": "guard.skill-dependencies.v1", "tools": [{"connection_id": "local-cli.alpha"}]}"#,
        r#"{"schema_version": "guard.skill-dependencies.v1", "tools": [{"connection_id": "local-cli.alpha", "tool_name": "run", "note": ""}]}"#,
        r#"{"schema_version": "guard.skill-dependencies.v1", "tools": [{"connection_id": "local-cli.alpha", "tool_name": 7}]}"#,
        r#"{"schema_version": "guard.skill-dependencies.v1", "tools": [{"connection_id": 7, "tool_name": "run"}]}"#,
    ] {
        assert_eq!(
            parse_dependencies(true, Some(text))["status"],
            "invalid",
            "{text}"
        );
    }
}

#[test]
fn a_duplicate_key_is_ambiguous_rather_than_last_one_wins() {
    let text = r#"{"schema_version": "guard.skill-dependencies.v1", "tools": [], "tools": []}"#;
    assert_eq!(parse_dependencies(true, Some(text))["status"], "invalid");
}

#[test]
fn a_nonfinite_value_never_reaches_the_tool_list() {
    let text = r#"{"schema_version": "guard.skill-dependencies.v1", "tools": [NaN]}"#;
    assert_eq!(parse_dependencies(true, Some(text))["status"], "invalid");
}

#[test]
fn the_reader_bounds_both_the_text_and_the_tool_count() {
    let padding = " ".repeat(8193);
    assert_eq!(
        parse_dependencies(true, Some(&format!("{padding}{}", manifest(json!([])))))["status"],
        "invalid"
    );
    let within: Vec<Value> = (0..50)
        .map(|index| json!({"connection_id": format!("local-cli.c{index}"), "tool_name": "run"}))
        .collect();
    let mut beyond = within.clone();
    beyond.push(json!({"connection_id": "local-cli.last", "tool_name": "run"}));
    assert_eq!(declared(Value::Array(within))["status"], "declared");
    assert_eq!(declared(Value::Array(beyond))["status"], "invalid");
}

#[test]
fn a_cli_id_is_a_dotted_prefix_and_up_to_nine_lowercase_parts() {
    for value in [
        "local-cli.alpha",
        "local-cli.a1",
        "local-cli.a-b-c-d-e-f-g-h-i",
    ] {
        assert!(is_local_cli_id(value), "{value}");
    }
    for value in [
        "",
        "local-cli.",
        "local-cli.Alpha",
        "local-cli.alpha_beta",
        "local-cli.a-",
        "local-cli.-a",
        "local-cli.a--b",
        "local-cli.a-b-c-d-e-f-g-h-i-j",
        "localcli.alpha",
        "local-cli.alpha\n",
        " local-cli.alpha",
    ] {
        assert!(!is_local_cli_id(value), "{value}");
    }
}

#[test]
fn a_tool_name_starts_alphanumeric_and_stays_within_the_punctuation_set() {
    let longest = "a".repeat(256);
    let beyond = "a".repeat(257);
    for value in ["a", "A9", "run.one_two:three-four", longest.as_str()] {
        assert!(is_tool_name(value), "{value}");
    }
    for value in ["", "_run", ".run", "run space", "rün", beyond.as_str()] {
        assert!(!is_tool_name(value), "{value}");
    }
}

fn connection(commands: Value) -> Value {
    json!({
        "cli_id": "local-cli.alpha",
        "identity_hash": "hash-alpha",
        "state": "allowed",
        "stale": false,
        "commands": commands,
    })
}

fn resolve(connections: &[Value], tool: &str) -> Value {
    let dependencies = declared(json!([{"connection_id": "local-cli.alpha", "tool_name": tool}]));
    preflight(&dependencies, connections, 12, &no_review)
}

#[test]
fn an_unobserved_connection_resolves_to_nothing_saved() {
    let resolved = resolve(&[], "run");
    assert_eq!(
        statuses(&resolved),
        [(
            "unresolved".to_owned(),
            "connection-not-observed".to_owned()
        )]
    );
    assert_eq!(resolved["requirements"][0]["identity_hash"], Value::Null);
    assert_eq!(resolved["dependency_status"], "declared");
    assert_eq!(resolved["authority_revision"], 12);
    assert_eq!(resolved["schema_version"], "guard.workflow-preflight.v1");
    assert_eq!(resolved["dependency_source"], DEPENDENCY_SOURCE);
    assert_eq!(resolved["requirements_complete"], false);
    assert_eq!(resolved["permissions_granted"], false);
    assert_eq!(resolved["runtime_checks_required"], true);
}

#[test]
fn a_saved_allow_still_requires_the_live_runtime_check() {
    let rows = [connection(json!([{"usage": "run", "state": "allow"}]))];
    let resolved = resolve(&rows, "run");
    assert_eq!(
        statuses(&resolved),
        [(
            "saved-allow".to_owned(),
            "live-runtime-check-still-required".to_owned()
        )]
    );
    assert_eq!(resolved["requirements"][0]["identity_hash"], "hash-alpha");
    assert_eq!(resolved["permissions_granted"], false);
}

#[test]
fn a_stale_connection_is_reported_before_any_saved_state() {
    let mut row = connection(json!([{"usage": "run", "state": "block"}]));
    row["stale"] = json!(true);
    let resolved = resolve(&[row], "run");
    assert_eq!(
        statuses(&resolved),
        [("unresolved".to_owned(), "connection-changed".to_owned())]
    );
}

#[test]
fn a_block_on_either_the_connection_or_the_command_denies() {
    let command = connection(json!([{"usage": "run", "state": "block"}]));
    assert_eq!(
        statuses(&resolve(&[command], "run")),
        [("deny".to_owned(), "saved-deny".to_owned())]
    );
    let mut whole = connection(json!([{"usage": "run", "state": "allow"}]));
    whole["state"] = json!("blocked");
    assert_eq!(
        statuses(&resolve(&[whole], "run")),
        [("deny".to_owned(), "saved-deny".to_owned())]
    );
}

#[test]
fn a_connection_denial_outranks_a_tool_it_never_observed() {
    let mut row = connection(json!([]));
    row["state"] = json!("blocked");
    assert_eq!(
        statuses(&resolve(&[row], "run")),
        [("deny".to_owned(), "saved-deny".to_owned())]
    );
}

#[test]
fn an_observed_connection_without_the_tool_resolves_to_nothing_saved() {
    for commands in [
        json!([]),
        json!([{"usage": "other", "state": "allow"}]),
        json!("none"),
    ] {
        assert_eq!(
            statuses(&resolve(&[connection(commands)], "run")),
            [("unresolved".to_owned(), "tool-not-observed".to_owned())]
        );
    }
}

#[test]
fn a_command_entry_that_is_not_an_observation_is_skipped() {
    let rows = [connection(
        json!(["run", {"usage": "run", "state": "allow"}]),
    )];
    assert_eq!(
        statuses(&resolve(&rows, "run")),
        [(
            "saved-allow".to_owned(),
            "live-runtime-check-still-required".to_owned()
        )]
    );
}

#[test]
fn an_observed_tool_without_a_saved_allow_still_needs_review() {
    let rows = [connection(json!([{"usage": "run", "state": "ask"}]))];
    assert_eq!(
        statuses(&resolve(&rows, "run")),
        [("ask".to_owned(), "permission-review-needed".to_owned())]
    );
    let mut unobserved = connection(json!([{"usage": "run", "state": "allow"}]));
    unobserved["state"] = json!("ask");
    assert_eq!(
        statuses(&resolve(&[unobserved], "run")),
        [("ask".to_owned(), "permission-review-needed".to_owned())]
    );
}

#[test]
fn a_provider_action_is_reviewed_even_where_the_saved_state_would_have_been_enough() {
    let dependencies = declared(json!([{"connection_id": "local-cli.alpha", "tool_name": "run"}]));
    let rows = [connection(json!([{"usage": "run", "state": "allow"}]))];
    let resolved = preflight(&dependencies, &rows, 12, &|name| name == "run");
    assert_eq!(
        statuses(&resolved),
        [(
            "ask".to_owned(),
            "provider-account-and-action-unverified".to_owned()
        )]
    );
}

#[test]
fn a_later_row_supersedes_an_earlier_one_for_the_same_cli() {
    let mut blocked = connection(json!([{"usage": "run", "state": "block"}]));
    blocked["identity_hash"] = json!("hash-old");
    let rows = [
        blocked,
        connection(json!([{"usage": "run", "state": "allow"}])),
    ];
    let resolved = resolve(&rows, "run");
    assert_eq!(
        statuses(&resolved),
        [(
            "saved-allow".to_owned(),
            "live-runtime-check-still-required".to_owned()
        )]
    );
    assert_eq!(resolved["requirements"][0]["identity_hash"], "hash-alpha");
}

#[test]
fn a_declaration_with_no_tools_draws_no_requirements() {
    for dependencies in [
        declared(json!([])),
        parse_dependencies(false, None),
        parse_dependencies(true, None),
        json!({}),
        json!("absent"),
    ] {
        let resolved = preflight(&dependencies, &[], 3, &no_review);
        assert_eq!(resolved["requirements"], json!([]));
        assert_eq!(resolved["runtime_checks_required"], true);
    }
    assert_eq!(
        preflight(&json!({}), &[], 3, &no_review)["dependency_status"],
        "absent"
    );
}

#[test]
fn a_request_that_is_not_a_declaration_row_is_skipped() {
    let dependencies = json!({
        "status": "declared",
        "tools": ["local-cli.alpha", {"connection_id": "local-cli.alpha", "tool_name": "run"}],
    });
    let resolved = preflight(&dependencies, &[], 3, &no_review);
    assert_eq!(resolved["requirements"].as_array().expect("rows").len(), 1);
}
