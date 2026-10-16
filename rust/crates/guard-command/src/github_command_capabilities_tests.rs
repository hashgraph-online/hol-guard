//! Parity test: `classify_github_cli` vs the Python oracle corpus.
//! Oracle generated from `github_command_capabilities.py::classify_github_cli`
//! over `testdata/github_command_capabilities_oracle.json`.

use crate::github_command_capabilities::classify_github_cli;
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize)]
struct OracleRow {
    argv: Vec<String>,
    capability: Option<String>,
    reason_code: Option<String>,
    detail: Option<String>,
    capabilities: Option<Vec<String>>,
}

fn cap_from_str(s: &str) -> Option<crate::github_capability_contract::GitHubCommandCapability> {
    use crate::github_capability_contract::GitHubCommandCapability as C;
    C::ALL.iter().copied().find(|c| c.as_str() == s)
}

#[test]
fn github_cli_classification_matches_python_oracle() {
    let rows: Vec<OracleRow> = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/github_command_capabilities_oracle.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let mut mismatches = Vec::new();
    for (i, row) in rows.iter().enumerate() {
        let Some(expected_cap) = row.capability.as_deref().and_then(cap_from_str) else {
            mismatches.push(format!(
                "#{i} {:?}: oracle had no capability (error row)",
                row.argv
            ));
            continue;
        };
        let got = classify_github_cli(&row.argv);
        let exp_caps: Vec<_> = row
            .capabilities
            .as_deref()
            .unwrap_or_default()
            .iter()
            .filter_map(|s| cap_from_str(s))
            .collect();
        if got.capability != expected_cap
            || got.capabilities != exp_caps
            || got.reason_code != row.reason_code.as_deref().unwrap_or("")
            || got.detail != row.detail.as_deref().unwrap_or("")
        {
            mismatches.push(format!(
                "#{i} {:?}\n  rust: cap={:?} caps={:?} reason={:?} detail={:?}\n  py:   cap={:?} caps={:?} reason={:?} detail={:?}",
                row.argv,
                got.capability, got.capabilities.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
                got.reason_code, got.detail,
                row.capability, row.capabilities, row.reason_code, row.detail,
            ));
        }
    }
    let mut by_reason = BTreeMap::new();
    for m in &mismatches {
        *by_reason.entry(m.clone()).or_insert(0u32) += 1;
    }
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

fn graphql_capability(args: &[&str]) -> crate::github_capability_contract::GitHubCommandCapability {
    let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
    classify_github_cli(&args).capability
}

#[test]
fn graphql_endpoint_with_leading_slash_matches_the_bare_endpoint() {
    use crate::github_capability_contract::GitHubCommandCapability as C;
    let query = "query{repository(owner:\"example-org\",name:\"example-repo\"){id}}";
    for endpoint in ["graphql", "/graphql"] {
        assert_eq!(
            graphql_capability(&["api", endpoint, "-f", &format!("query={query}")]),
            C::ReadRemote,
            "{endpoint}"
        );
    }
    let mutation = "mutation{addStar(input:{starrableId:\"X\"}){clientMutationId}}";
    for endpoint in ["graphql", "/graphql"] {
        assert_ne!(
            graphql_capability(&["api", endpoint, "-f", &format!("query={mutation}")]),
            C::ReadRemote,
            "{endpoint}"
        );
        assert_ne!(
            graphql_capability(&[
                "api",
                endpoint,
                "-X",
                "POST",
                "-f",
                &format!("query={query}")
            ]),
            C::ReadRemote,
            "{endpoint}"
        );
        assert_ne!(
            graphql_capability(&["api", endpoint, "-F", "query=@query.graphql"]),
            C::ReadRemote,
            "{endpoint}"
        );
    }
    // A REST endpoint with a body stays a write, and blob creation stays review.
    assert_ne!(
        graphql_capability(&[
            "api",
            "/repos/example-org/example-repo/git/blobs",
            "-F",
            "content=@file.txt"
        ]),
        C::ReadRemote
    );
}

#[test]
fn only_a_bare_private_repository_creation_is_prompt_free() {
    use crate::github_capability_contract::GitHubCommandCapability as C;
    for command in [
        "repo create todo-app --private",
        "repo create todo-app --private --source=.",
        "repo create todo-app --private --source . --remote origin",
        "repo create todo-app --private -s . -r upstream -d \"A small todo app\"",
        "repo create todo_app.v2 --private --add-readme --license mit --gitignore Node",
        "repo create todo-app --disable-wiki --private --disable-issues",
    ] {
        let args: Vec<&str> = split(command);
        assert_eq!(
            graphql_capability(&args),
            C::CreatePrivateRemote,
            "{command}"
        );
    }
    for command in [
        "repo create todo-app",
        "repo create todo-app --public",
        "repo create todo-app --private --public",
        "repo create todo-app --internal",
        "repo create todo-app --private --push --source=.",
        "repo create todo-app --private --source=../other",
        "repo create todo-app --private --source /tmp/x",
        "repo create example-org/todo-app --private",
        "repo create todo-app --private --template example-org/base",
        "repo create todo-app --private --clone",
        "repo create todo-app --private --team core",
        "repo create todo-app --private --homepage https://example.com",
        "repo create todo-app --private=true",
        "repo create --private",
        "repo create . --private",
        "repo create todo-app other --private",
        "repo create todo-app --private -d $SECRET",
        "repo create todo-app --private --description=@notes.txt",
        "repo create todo-app --private --remote",
        "repo create todo-app --private -sp .",
    ] {
        let args: Vec<&str> = split(command);
        assert_ne!(
            graphql_capability(&args),
            C::CreatePrivateRemote,
            "{command}"
        );
    }
}

/// Whitespace split that keeps one double-quoted word together.
fn split(command: &str) -> Vec<&str> {
    let mut words = Vec::new();
    let mut rest = command;
    while let Some(start) = rest.find(|c: char| !c.is_whitespace()) {
        rest = &rest[start..];
        if let Some(quoted) = rest.strip_prefix('"') {
            let end = quoted.find('"').unwrap();
            words.push(&quoted[..end]);
            rest = &quoted[end + 1..];
        } else {
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            words.push(&rest[..end]);
            rest = &rest[end..];
        }
    }
    words
}

#[test]
fn api_jq_filters_that_read_the_environment_are_no_static_reads() {
    let reason = |option: &str, filter: &str| {
        let argv = ["repos/o/r/pulls", option, filter].map(String::from);
        crate::github_command_capabilities::classify_github_api(&argv).reason_code
    };
    for filter in ["$ENV.GH_TOKEN", "env.GH_TOKEN", ".[0] | env", "$ENV | keys"] {
        for option in ["--jq", "-q"] {
            assert_eq!(
                reason(option, filter),
                "github.api.dynamic-option-value",
                "{filter}"
            );
        }
    }
    for filter in [".[].number", ".[].env", ".[].environment"] {
        assert_ne!(
            reason("--jq", filter),
            "github.api.dynamic-option-value",
            "{filter}"
        );
    }
}
