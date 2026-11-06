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

/// A trailing `--help` prints the subcommand's help and runs nothing. Two rows
/// of the oracle above recorded the opposite, and that is the false positive
/// this fix removes rather than a behaviour worth keeping.
#[test]
fn a_trailing_help_flag_keeps_the_command_local() {
    for command in [
        "repo delete owner/name --help",
        "release delete v1 --help",
        "secret set FIXTURE --help",
        "issue view --help",
        "secret --help",
        "auth switch --help",
        "workflow run release.yml --help",
        "--help",
        "-h",
        // The option and its value are gh's, and what is left is a name gh
        // owns, so gh is still the one reading the flag.
        "issue -R owner/name --help",
        "issue -R owner/name list --help",
        "issue --repo=owner/name view 1 --help",
        // A subcommand that is a group itself still prints its own help, and
        // the names underneath it are gh's too.
        "repo deploy-key --help",
        "repo deploy-key add key.pub --help",
        "codespace ports forward 8080:8080 --help",
    ] {
        let argv: Vec<String> = command.split(' ').map(String::from).collect();
        let got = classify_github_cli(&argv);
        assert_eq!(
            (got.capability, got.reason_code.as_str()),
            (
                crate::github_capability_contract::GitHubCommandCapability::ReadLocal,
                "github.command.local-help"
            ),
            "{command}"
        );
    }
}

/// The trailing `--help` is only gh's own help when gh is the one reading it.
/// After `--` the flag is a positional, and aliases, installed extensions and
/// `gh extension exec` are registered with flag parsing disabled, so gh hands
/// the flag to the command it runs. An alias can also sit under a built-in
/// group, where only the group's own subcommands are safe from it.
#[test]
fn a_help_gh_itself_does_not_print_still_classifies_the_command() {
    use crate::github_capability_contract::GitHubCommandCapability as C;
    for command in [
        // Uploads a file named `--help` and publishes the release.
        "release create v1.0.0 -- notes.txt --help",
        // An alias set with `--shell` runs its shell command.
        "nuke --help",
        // An installed extension runs its binary.
        "my-ext purge --help",
        "extension exec my-ext delete target --help",
        // `gh alias set --shell "issue mine" …` is accepted, and gh then runs
        // the alias's shell command with `--help` as an argument.
        "issue mine --help",
        "run teardown --help",
        // Cobra takes an option and its value out of the way before it matches
        // a subcommand, so a written option in front of the alias does not stop
        // gh from expanding it: these all run the `issue mine` alias.
        "issue -R owner/name mine --help",
        "issue --repo owner/name mine --help",
        "issue --repo=owner/name mine --help",
        "issue -Rowner/name mine --help",
        // An option gh does not publish an arity for here could take the next
        // word or leave it as the name of an alias.
        "issue --json state mine --help",
        // An alias can sit under a subcommand that is a group itself.
        "repo deploy-key zap --help",
        "repo autolink zap --help",
        "repo gitignore zap --help",
        "repo license zap --help",
        "codespace ports zap --help",
        // gh matches a name byte for byte, so a differently cased spelling is
        // an alias lookup rather than the built-in command it resembles.
        "ISSUE delete owner/name --help",
        "issue VIEW 1 --help",
    ] {
        let argv: Vec<String> = command.split(' ').map(String::from).collect();
        let got = classify_github_cli(&argv);
        assert_ne!(got.capability, C::ReadLocal, "{command}");
        assert_ne!(got.reason_code, "github.command.local-help", "{command}");
    }
    // An unrecognised top-level name keeps the unknown-command floor.
    for command in ["nuke --help", "my-ext purge --help"] {
        let argv: Vec<String> = command.split(' ').map(String::from).collect();
        assert_eq!(
            classify_github_cli(&argv).capability,
            C::Unknown,
            "{command}"
        );
    }
}

/// The two readings a trailing `--help` does not have: an option's value, and
/// the `--hostname` that `gh` reads `-h` as past the first token.
#[test]
fn a_help_flag_that_is_not_help_still_classifies_the_command() {
    use crate::github_capability_contract::GitHubCommandCapability as C;
    for command in [
        // `gh issue create --title --help` opens an issue titled `--help`.
        "issue create --title --help",
        "secret set FIXTURE --body --help",
        // Past the first token `-h` names an alternate host, not help.
        "repo delete owner/name -h",
        "pr list -h ghes.com",
    ] {
        let argv: Vec<String> = command.split(' ').map(String::from).collect();
        let got = classify_github_cli(&argv);
        assert_ne!(got.capability, C::ReadLocal, "{command}");
        assert_ne!(got.reason_code, "github.command.local-help", "{command}");
    }
}
