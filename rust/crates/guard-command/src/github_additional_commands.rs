//! Explicit ownership for CLI families formerly treated as aliases or mutations.
//! Listing secret names never returns secret values. Downloads,
//! browser/editor launches and extension execution are deliberately not reads.

use crate::github_capability_contract::GitHubCommandCapability as Cap;

pub(crate) fn classify(args: &[String]) -> Option<Cap> {
    let group = args.first()?.as_str();
    let command = args.get(1)?.as_str();
    let tail = &args[2..];
    let (capability, flags, values): (Cap, &[&str], &[&str]) = match (group, command) {
        ("cache", "list") => (
            Cap::ReadRemote,
            &[],
            &[
                "--key",
                "-k",
                "--ref",
                "-r",
                "--limit",
                "-L",
                "--sort",
                "--order",
                "--json",
                "--jq",
                "-q",
                "--template",
                "-t",
            ],
        ),
        ("label", "list") => (
            Cap::ReadRemote,
            &[],
            &[
                "--search",
                "-S",
                "--limit",
                "-L",
                "--sort",
                "--order",
                "--json",
                "--jq",
                "-q",
                "--template",
                "-t",
            ],
        ),
        ("secret" | "variable", "list") => (
            Cap::ReadRemote,
            &[],
            &[
                "--app",
                "-a",
                "--env",
                "-e",
                "--org",
                "-o",
                "--json",
                "--jq",
                "-q",
                "--template",
                "-t",
            ],
        ),
        ("codespace", "list") => (
            Cap::ReadRemote,
            &[],
            &[
                "--limit",
                "-L",
                "--org",
                "-o",
                "--user",
                "-u",
                "--json",
                "--jq",
                "-q",
                "--template",
                "-t",
            ],
        ),
        ("org", "list") => (Cap::ReadRemote, &[], &["--limit", "-L"]),
        ("project", "list") => (
            Cap::ReadRemote,
            &["--closed"],
            &[
                "--owner",
                "--limit",
                "-L",
                "--format",
                "--jq",
                "-q",
                "--template",
                "-t",
            ],
        ),
        ("alias" | "extension", "list") => (Cap::ReadLocal, &[], &[]),
        ("config", "list") => (Cap::ReadLocal, &[], &[]),
        ("config", "get")
            if tail.len() == 1
                && matches!(
                    tail[0].as_str(),
                    "git_protocol"
                        | "editor"
                        | "prompt"
                        | "prefer_editor_prompt"
                        | "pager"
                        | "http_unix_socket"
                        | "browser"
                        | "color_labels"
                        | "accessible_colors"
                        | "accessible_prompter"
                        | "spinner"
                        | "show_political_message"
                ) =>
        {
            return Some(Cap::ReadLocal)
        }
        ("config", "get") if tail.first().is_some_and(|key| key == "oauth_token") => {
            return Some(Cap::SecretRemote);
        }
        ("config", "get") => return None,
        // `variable list` already prints every value, so reading one by name
        // shows no more. Exactly one name, and only the options that select
        // where it is read from or how it is printed.
        ("variable", "get") => return Some(variable_get(tail)),
        ("config", "set" | "clear-cache") | ("alias", "set" | "delete" | "import") => {
            return Some(Cap::WriteLocal)
        }
        // Installing/upgrading an extension can run code; retain explicit review.
        ("extension", "create" | "install" | "remove" | "upgrade" | "exec") => {
            return Some(Cap::Unknown)
        }
        ("pr", "update-branch") => return Some(Cap::MutateRemote),
        ("pr", "revert") => return Some(Cap::ContentRemote),
        ("release", "delete-asset")
        | ("project", "delete" | "field-delete" | "item-delete")
        | ("gist", "delete") => return Some(Cap::DeleteRemote),
        (
            "project",
            "close" | "copy" | "create" | "edit" | "field-create" | "item-add" | "item-archive"
            | "item-create" | "item-edit" | "link" | "mark-template" | "unlink",
        )
        | ("gist", "create" | "edit" | "rename") => return Some(Cap::ContentRemote),
        _ => return None,
    };
    Some(if metadata_options(tail, flags, values) {
        capability
    } else {
        Cap::Unknown
    })
}

fn variable_get(tail: &[String]) -> Cap {
    const VALUES: &[&str] = &[
        "--env",
        "-e",
        "--org",
        "-o",
        "--json",
        "--jq",
        "-q",
        "--template",
        "-t",
    ];
    let mut rest = tail.to_vec();
    let mut index = 0;
    let mut name = None;
    while index < rest.len() {
        let option = rest[index].split('=').next().unwrap_or_default();
        if rest[index].starts_with('-') {
            let takes_value = (VALUES.contains(&option) || matches!(option, "--repo" | "-R"))
                && !rest[index].contains('=');
            index += 1 + usize::from(takes_value);
            continue;
        }
        if name.is_some() {
            return Cap::Unknown;
        }
        name = Some(rest.remove(index));
    }
    let plain = name.is_some_and(|name| {
        !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    });
    if plain && metadata_options(&rest, &[], VALUES) {
        Cap::ReadRemote
    } else {
        Cap::Unknown
    }
}

fn metadata_options(args: &[String], flags: &[&str], values: &[&str]) -> bool {
    let mut index = 0;
    while let Some(argument) = args.get(index) {
        let (option, inline) = argument
            .split_once('=')
            .map_or((argument.as_str(), None), |(key, value)| (key, Some(value)));
        if flags.contains(&option) {
            if inline.is_some_and(|value| !matches!(value, "true" | "false")) {
                return false;
            }
        } else if values.contains(&option) || matches!(option, "--repo" | "-R") {
            let value = match inline {
                Some(value) => value,
                None => {
                    index += 1;
                    let Some(value) = args.get(index) else {
                        return false;
                    };
                    value.as_str()
                }
            };
            if value.is_empty() || value.starts_with('-') || value.contains(['\0', '$', '`']) {
                return false;
            }
        } else {
            return false;
        }
        index += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_reads_have_explicit_owners() {
        for (command, expected) in [
            ("cache list --limit 5", Cap::ReadRemote),
            ("label list --json name", Cap::ReadRemote),
            ("secret list --env preview", Cap::ReadRemote),
            ("variable list", Cap::ReadRemote),
            ("variable get MERGE_FREEZE", Cap::ReadRemote),
            (
                "variable get MERGE_FREEZE --repo example-org/app",
                Cap::ReadRemote,
            ),
            ("variable get --env preview DEPLOY_REGION", Cap::ReadRemote),
            (
                "variable get REGION --json name,value --jq .value",
                Cap::ReadRemote,
            ),
            ("codespace list", Cap::ReadRemote),
            ("org list", Cap::ReadRemote),
            (
                "project list --owner example-org --closed=false",
                Cap::ReadRemote,
            ),
            ("alias list", Cap::ReadLocal),
            ("extension list", Cap::ReadLocal),
            ("config list", Cap::ReadLocal),
            ("config get editor", Cap::ReadLocal),
        ] {
            let args: Vec<String> = command.split_whitespace().map(str::to_owned).collect();
            assert_eq!(
                crate::github_command_capabilities::classify_github_cli(&args).capability,
                expected,
                "{command}"
            );
            assert!(
                crate::command_compatibility::github_arguments_are_read_only(
                    &args,
                    &format!("gh {command}")
                ),
                "{command}"
            );
        }
    }

    #[test]
    fn unknown_options_and_launches_never_inherit_a_read() {
        for command in [
            "cache list --web",
            "secret list --show-token",
            "codespace list --limit",
            "label list --json --web",
            "project list --closed=invalid",
            "extension exec list",
            "variable get",
            "variable get ONE TWO",
            "variable get NAME --web",
            "variable get NAME --repo",
            "variable get ''",
            "variable get ../NAME",
        ] {
            let args: Vec<String> = command.split_whitespace().map(str::to_owned).collect();
            assert_eq!(classify(&args), Some(Cap::Unknown), "{command}");
            assert!(
                !crate::command_compatibility::github_arguments_are_read_only(
                    &args,
                    &format!("gh {command}")
                ),
                "{command}"
            );
        }
        let args = ["config", "get", "credential"].map(str::to_owned);
        assert!(
            !crate::command_compatibility::github_arguments_are_read_only(
                &args,
                "gh config get credential"
            )
        );
    }

    #[test]
    fn token_config_reads_and_mutations_cannot_use_metadata_permissions() {
        for (command, expected) in [
            (
                "config get oauth_token --host github.com",
                Cap::SecretRemote,
            ),
            ("secret set FIXTURE", Cap::SecretRemote),
            ("cache delete fixture", Cap::DeleteRemote),
            ("label create fixture", Cap::ContentRemote),
            ("variable set FIXTURE", Cap::WorkflowRemote),
            ("codespace stop", Cap::MutateRemote),
            ("pr update-branch 12", Cap::MutateRemote),
            ("release delete-asset v1 asset.zip", Cap::DeleteRemote),
        ] {
            let args: Vec<String> = command.split_whitespace().map(str::to_owned).collect();
            assert_eq!(
                crate::github_command_capabilities::classify_github_cli(&args).capability,
                expected,
                "{command}"
            );
            assert!(
                !crate::command_compatibility::github_arguments_are_read_only(
                    &args,
                    &format!("gh {command}")
                ),
                "{command}"
            );
        }
    }
}
