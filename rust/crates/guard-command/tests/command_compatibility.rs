//! Independent catalog/capability vectors; no production capability is enabled here.
use guard_command::{parse_command, CanonicalCommandV1, CommandModelRequestV1};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use command_compatibility::{compatibility_observations, compatibility_rule_ids};
use guard_command::command_compatibility;

fn model(command: &str) -> CanonicalCommandV1 {
    parse_command(&CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "compatibility-independent-vector".to_owned(),
    })
    .expect("bounded fixture must parse")
}

#[test]
fn frozen_independent_capability_and_admission_vectors() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/native-command-compatibility-v1.json"
    ))
    .unwrap();
    let mut exercised = BTreeSet::new();
    for case in fixture["cases"].as_array().unwrap() {
        let id = case["case_id"].as_str().unwrap();
        let parsed = model(case["command"].as_str().unwrap());
        let observed = compatibility_observations(&parsed, None)
            .unwrap_or_else(|error| panic!("{id}: {error}"));
        let rules: Vec<&str> = observed
            .rule_matches
            .iter()
            .map(|item| item.rule_id)
            .collect();
        let permissions: Vec<&str> = observed
            .permission_matches
            .iter()
            .map(|item| item.permission_id)
            .collect();
        let uncertain: Vec<&str> = observed
            .rule_matches
            .iter()
            .filter(|item| item.uncertainty)
            .map(|item| item.rule_id)
            .collect();
        assert_eq!(
            serde_json::json!(rules),
            case["expected_rules"],
            "{id}: rule attribution"
        );
        assert_eq!(
            serde_json::json!(permissions),
            case["expected_permissions"],
            "{id}: permission attribution"
        );
        assert_eq!(
            serde_json::json!(uncertain),
            case["uncertain_rules"],
            "{id}: admission outcome"
        );
        assert!(
            observed
                .permission_matches
                .iter()
                .all(|item| !item.uncertainty),
            "{id}"
        );
        assert!(
            observed
                .rule_matches
                .iter()
                .all(|item| item.segment_indexes == [0]),
            "{id}"
        );
        assert!(
            observed
                .permission_matches
                .iter()
                .all(|item| item.segment_indexes == [0]),
            "{id}"
        );
        exercised.extend(rules);
    }
    assert_eq!(
        exercised,
        compatibility_rule_ids().iter().copied().collect()
    );
}

#[test]
fn audited_inventory_is_exactly_the_null_matcher_catalog_subset() {
    let program: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/extensions/native-command-program.v1.json"
    ))
    .unwrap();
    let actual: BTreeSet<&str> = compatibility_rule_ids().iter().copied().collect();
    let expected: BTreeSet<&str> = program["rules"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|rule| rule["matcher"].is_null())
        .map(|rule| rule["rule_id"].as_str().unwrap())
        .collect();
    assert_eq!(actual.len(), 42);
    assert_eq!(actual, expected);
}

#[test]
fn github_reads_have_permission_attribution_without_fabricated_rules() {
    let observed = compatibility_observations(&model("gh pr view 123"), None).unwrap();
    assert!(observed.rule_matches.is_empty());
    assert_eq!(observed.permission_matches.len(), 1);
    assert_eq!(
        observed.permission_matches[0].permission_id,
        "command.github.permission.read-remote"
    );
    assert!(!observed.permission_matches[0].uncertainty);
}

#[test]
fn git_disabled_permission_attribution_is_not_lost_on_native_safe_commands() {
    for subcommand in ["status", "diff", "log", "show", "ls-files"] {
        let observed =
            compatibility_observations(&model(&format!("git {subcommand}")), None).unwrap();
        assert_eq!(observed.rule_matches.len(), 1, "{subcommand}");
        assert_eq!(
            observed.rule_matches[0].rule_id,
            format!("command.git.{subcommand}")
        );
        assert!(!observed.rule_matches[0].uncertainty);
    }
}

#[test]
fn compound_attribution_keeps_every_segment_and_deduplicates_identity() {
    let observed = compatibility_observations(
        &model("git status; gh pr view 1; git status; gh issue view 2"),
        None,
    )
    .unwrap();
    assert_eq!(observed.rule_matches[0].segment_indexes, [0, 2]);
    assert_eq!(observed.permission_matches[0].segment_indexes, [1, 3]);
}

#[test]
fn budget_and_parser_failures_cannot_become_empty_success() {
    let exact = model("pwd");
    assert_eq!(
        compatibility_observations(&exact, Some(Instant::now() - Duration::from_millis(1)))
            .unwrap_err(),
        "native_command_compatibility_deadline"
    );
    let mut oversized = exact.clone();
    oversized.segments[0].arguments.push("x".repeat(32_769));
    assert_eq!(
        compatibility_observations(&oversized, None).unwrap_err(),
        "native_command_compatibility_limit"
    );
    let mut uncertain = exact.clone();
    uncertain.confidence = "uncertain".to_owned();
    assert!(compatibility_observations(&uncertain, None).is_err());
    let mut overridden = exact;
    overridden.segments[0]
        .environment_names
        .push("GIT_CONFIG_GLOBAL".to_owned());
    assert!(compatibility_observations(&overridden, None).is_err());
}

#[test]
fn github_api_query_suffix_preserves_merge_authorization() {
    let observed = compatibility_observations(
        &model("gh api repos/o/r/pulls/17/merge?x=y --method PUT"),
        None,
    )
    .unwrap();
    assert_eq!(observed.rule_matches.len(), 1);
    assert_eq!(observed.rule_matches[0].rule_id, "command.github.merge");
    assert!(observed.permission_matches.is_empty());
    let program: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/extensions/native-command-program.v1.json"
    ))
    .unwrap();
    let merge = program["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|rule| rule["rule_id"] == "command.github.merge")
        .unwrap();
    assert_eq!(
        merge["permission_id"],
        "command.github.permission.merge-remote"
    );
}

#[test]
fn graphql_remains_owned_unsupported_instead_of_permissionless_allow() {
    let observed = compatibility_observations(
        &model("gh api graphql -f 'query=query{viewer{login}}'"),
        None,
    )
    .unwrap();
    assert_eq!(observed.rule_matches.len(), 1);
    assert_eq!(observed.rule_matches[0].rule_id, "command.github.unknown");
    assert!(observed.rule_matches[0].uncertainty);
    assert!(observed.permission_matches.is_empty());
}
