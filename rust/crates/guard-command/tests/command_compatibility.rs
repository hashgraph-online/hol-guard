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
    let program: serde_json::Value = serde_json::from_slice(
        guard_command::native_command_program::packaged_command_program_bytes(),
    )
    .unwrap();
    let actual: BTreeSet<&str> = compatibility_rule_ids().iter().copied().collect();
    let expected: BTreeSet<&str> = program["rules"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|rule| rule["matcher"].is_null())
        .map(|rule| rule["rule_id"].as_str().unwrap())
        .collect();
    assert_eq!(actual.len(), 43);
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
fn github_reads_keep_their_permission_after_a_stderr_merge() {
    for command in [
        "gh api repos/o/r/actions/jobs/1/logs 2>&1 | grep -A 6 \"Diff in\" | head -40",
        "gh pr view 123 2>&1",
    ] {
        let observed = compatibility_observations(&model(command), None).unwrap();
        assert!(observed.rule_matches.is_empty(), "{command}");
        assert_eq!(observed.permission_matches.len(), 1, "{command}");
        assert_eq!(
            observed.permission_matches[0].permission_id,
            "command.github.permission.read-remote"
        );
        assert!(!observed.permission_matches[0].uncertainty, "{command}");
    }
    // A quoted `2>&1` is an operand, not a redirect.
    let quoted = compatibility_observations(&model("gh api repos/o/r '2>&1'"), None).unwrap();
    assert_eq!(quoted.rule_matches[0].rule_id, "command.github.unknown");
    assert!(quoted.rule_matches[0].uncertainty);
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
    overridden.segments[0].path_overridden = true;
    assert!(compatibility_observations(&overridden, None).is_err());
}

#[test]
fn assignment_prefixes_are_attributed_as_uncertainty_not_evaluation_failure() {
    for command in ["X=1 ls", "TODO_FILE=/tmp/todo.json ./todo.py list"] {
        let observed = compatibility_observations(&model(command), None).unwrap();
        assert!(observed.rule_matches.is_empty(), "{command}");
        assert!(observed.permission_matches.is_empty(), "{command}");
    }
    let push =
        compatibility_observations(&model("GIT_DIR=/tmp/x git push origin main"), None).unwrap();
    assert!(!push.rule_matches.is_empty());
    assert!(push.rule_matches.iter().all(|item| item.uncertainty));
    let view =
        compatibility_observations(&model("GH_HOST=example.com gh pr view 12"), None).unwrap();
    assert!(!view.permission_matches.is_empty());
    assert!(view.permission_matches.iter().all(|item| item.uncertainty));
    // Only the steered segment loses certainty.
    let mixed = compatibility_observations(&model("X=1 ls && git push"), None).unwrap();
    assert_eq!(mixed.rule_matches.len(), 1);
    assert!(!mixed.rule_matches[0].uncertainty);
    assert!(compatibility_observations(&model("PATH=/tmp git status"), None).is_err());
}

/// `OUT=build/report.json && ...` runs no program in its first list item, so
/// it is attributed like the rest of the chain instead of failing evaluation.
#[test]
fn a_list_item_that_only_sets_an_ordinary_variable_runs_no_program() {
    for command in [
        "OUT=build/report.json && ls",
        "TODO_FILE=\"/tmp/t.json\"; ./todo.py list",
        "A=1 B=2; ls",
    ] {
        let observed = compatibility_observations(&model(command), None).unwrap();
        assert!(observed.rule_matches.is_empty(), "{command}");
        assert!(observed.permission_matches.is_empty(), "{command}");
    }
    // A later program inherits the value when the session already exported
    // the name, so it is steered as a prefix would steer it.
    let push = compatibility_observations(&model("OUT=x; git push origin main"), None).unwrap();
    assert!(!push.rule_matches.is_empty());
    assert!(push.rule_matches.iter().all(|item| item.uncertainty));
    let inert = compatibility_observations(&model("CI=1; git push origin main"), None).unwrap();
    assert!(!inert.rule_matches.is_empty());
    assert!(inert.rule_matches.iter().all(|item| !item.uncertainty));
    for command in [
        "GIT_DIR=/tmp/x; git push origin main",
        "GH_HOST=example.com; gh pr view 12",
        "KUBECONFIG=/tmp/k; kubectl get pods",
        "LD_PRELOAD=./x.so; ls",
        "HOME=/tmp; ls",
        "IFS=,; ls",
        "PATH=/tmp; ls",
        "X=$GIT_DIR; ls",
        "X=${GIT_DIR:=/tmp/x}; git status",
    ] {
        assert!(
            compatibility_observations(&model(command), None).is_err(),
            "{command}"
        );
    }
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
    let program: serde_json::Value = serde_json::from_slice(
        guard_command::native_command_program::packaged_command_program_bytes(),
    )
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
fn graphql_queries_are_remote_reads_and_mutations_are_owned_rules() {
    let query = compatibility_observations(
        &model("gh api graphql -f 'query=query{viewer{login}}'"),
        None,
    )
    .unwrap();
    assert!(query.rule_matches.is_empty());
    assert_eq!(query.permission_matches.len(), 1);
    assert_eq!(
        query.permission_matches[0].permission_id,
        "command.github.permission.read-remote"
    );
    let mutation = compatibility_observations(
        &model("gh api graphql -f 'query=mutation{addStar(input:{starrableId:\"X\"}){clientMutationId}}'"),
        None,
    )
    .unwrap();
    assert_eq!(mutation.rule_matches.len(), 1);
    assert_eq!(mutation.rule_matches[0].rule_id, "command.github.mutation");
    assert!(!mutation.rule_matches[0].uncertainty);
    assert!(mutation.permission_matches.is_empty());
    let unread_input =
        compatibility_observations(&model("gh api graphql --input -"), None).unwrap();
    assert_eq!(
        unread_input.rule_matches[0].rule_id,
        "command.github.unknown"
    );
    assert!(unread_input.rule_matches[0].uncertainty);
}

#[test]
fn printing_a_credential_variable_reads_the_secret() {
    let reads_secret = |command: &str| {
        compatibility_observations(&model(command), None)
            .unwrap()
            .rule_matches
            .iter()
            .any(|item| item.rule_id == "command.shell-mutations.process-environment-secret-read")
    };
    // The redirect projection hands this layer the command without `> file`.
    assert!(reads_secret("echo \"$GITHUB_TOKEN\""));
    assert!(reads_secret("printf '%s' \"${NPM_TOKEN}\""));
    assert!(!reads_secret("echo \"$PATH\""));
    assert!(!reads_secret("echo hello"));
}

#[test]
fn a_port_variable_read_names_no_dotenv_file() {
    let writes_sensitive = |command: &str| {
        compatibility_observations(&model(command), None)
            .unwrap()
            .rule_matches
            .iter()
            .any(|matched| matched.rule_id == "command.shell-mutations.sensitive-file-write")
    };
    for command in [
        "node -e \"require('node:http').createServer((q,r)=>r.end('ok')).listen(Number(process.env.PORT)||3000)\"",
        "node -e \"require('node:http').createServer((q,r)=>r.end('ok')).listen(process.env.DEV_PORT||3000)\"",
    ] {
        assert!(!writes_sensitive(command), "{command}");
    }
    for command in [
        "node -e \"require('node:http').createServer((q,r)=>r.end(JSON.stringify(process.env))).listen(3000)\"",
        "node -e \"require('node:http').createServer((q,r)=>r.end(require('fs').readFileSync('.env'))).listen(process.env.PORT)\"",
        "node -e \"require('fs').promises.writeFile('.env',String(process.env.PORT)).then(()=>0)\"",
    ] {
        assert!(writes_sensitive(command), "{command}");
    }
}
