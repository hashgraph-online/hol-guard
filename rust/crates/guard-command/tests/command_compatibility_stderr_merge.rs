//! A trailing `2>&1` joins stderr to the command's own stdout. It is not an
//! operand and writes no file, so it never changes which capability the Git
//! or GitHub CLI grammar attributes to the command.
use guard_command::command_compatibility::{compatibility_observations, CompatibilityObservations};
use guard_command::{parse_command, CommandModelRequestV1};

const READ_REMOTE: &str = "command.github.permission.read-remote";

fn observe(command: &str) -> CompatibilityObservations {
    let model = parse_command(&CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "compatibility-stderr-merge-vector".to_owned(),
    })
    .unwrap_or_else(|error| panic!("{command}: {error}"));
    assert_eq!(model.confidence, "exact", "{command}");
    compatibility_observations(&model, None).unwrap_or_else(|error| panic!("{command}: {error}"))
}

fn reads_remote(observed: &CompatibilityObservations) -> bool {
    observed
        .permission_matches
        .iter()
        .any(|item| item.permission_id == READ_REMOTE && !item.uncertainty)
}

#[test]
fn github_api_reads_keep_their_read_attribution_with_merged_stderr() {
    for command in [
        "gh api repos/example/app/actions/jobs/123/logs 2>&1",
        "gh api repos/example/app/actions/jobs/123/logs 2>&1 | tail -50",
        "gh api \"repos/example/app/check-runs/1/annotations\" --paginate 2>&1",
        "gh api repos/example/app/pulls/1/comments 2>&1",
        "gh api -X GET repos/example/app/pulls/1/comments --jq '.[].body' 2>&1",
        "gh api graphql -f 'query=query{viewer{login}}' 2>&1",
    ] {
        let observed = observe(command);
        assert!(
            observed.rule_matches.is_empty(),
            "{command}: {:?}",
            observed.rule_matches
        );
        assert!(reads_remote(&observed), "{command}");
    }
}

#[test]
fn merged_stderr_matches_the_command_without_it() {
    for command in [
        "gh api repos/example/app/pulls/1/comments",
        "gh pr view 1 --json title",
        "gh api -X POST repos/example/app/issues/1/comments -f body=done",
        "git log --oneline -5",
        "git status --short",
    ] {
        let plain = observe(command);
        let merged = observe(&format!("{command} 2>&1"));
        let ids = |observed: &CompatibilityObservations| {
            (
                observed
                    .rule_matches
                    .iter()
                    .map(|item| (item.rule_id, item.uncertainty))
                    .collect::<Vec<_>>(),
                observed
                    .permission_matches
                    .iter()
                    .map(|item| (item.permission_id, item.uncertainty))
                    .collect::<Vec<_>>(),
            )
        };
        assert_eq!(ids(&plain), ids(&merged), "{command}");
    }
}

#[test]
fn github_api_writes_stay_owned_rules_with_merged_stderr() {
    for command in [
        "gh api -X POST repos/example/app/issues/1/comments -f body=done 2>&1",
        "gh api --method PATCH repos/example/app/issues/1 -f state=closed 2>&1",
        "gh api -X PUT repos/example/app/pulls/1/merge 2>&1",
        "gh api -X DELETE repos/example/app/git/refs/heads/topic 2>&1",
        // A field on a REST endpoint is an implicit POST.
        "gh api repos/example/app/issues/1/comments -f body=done 2>&1",
        "gh api repos/example/app/contents/notes.txt --input body.json 2>&1",
        "gh api graphql -f 'query=mutation{addStar(input:{starrableId:\"X\"}){clientMutationId}}' 2>&1",
    ] {
        let observed = observe(command);
        assert!(!observed.rule_matches.is_empty(), "{command}");
        assert!(!reads_remote(&observed), "{command}");
    }
}

#[test]
fn a_quoted_merge_operand_is_still_an_argument() {
    // `"2>&1"` is a literal second endpoint operand, not a redirect.
    let observed = observe("gh api repos/example/app/pulls/1/comments \"2>&1\"");
    assert_eq!(observed.rule_matches.len(), 1);
    assert_eq!(observed.rule_matches[0].rule_id, "command.github.unknown");
    assert!(observed.rule_matches[0].uncertainty);
    assert!(!reads_remote(&observed));
}
