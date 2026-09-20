//! Static REST capability attribution. GraphQL and external bodies need a richer proof.
use super::{one, Capabilities};

fn field_is_static(value: &str) -> bool {
    !value.contains(['$', '`', '@', '\0', '\n', '\r'])
}

fn safe_header(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    let Some((name, value)) = lowered.split_once(':') else {
        return false;
    };
    let value = value.trim_start();
    if name.trim_end() == "accept" {
        return value
            .strip_prefix("application/vnd.github")
            .is_some_and(|tail| {
                matches!(tail.as_bytes().first(), Some(b'+') | Some(b'.'))
                    && tail.len() > 1
                    && tail[1..].bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".+-".contains(&byte)
                    })
            });
    }
    name.trim_end() == "x-github-api-version"
        && value.len() == 10
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 4 | 7) {
                byte == b'-'
            } else {
                byte.is_ascii_digit()
            }
        })
}

pub(super) fn classify(arguments: &[String]) -> Capabilities {
    let mut endpoint: Option<&str> = None;
    let mut method: Option<&str> = None;
    let mut fields: Vec<(&str, &str)> = Vec::new();
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        if argument == "--" {
            if endpoint.is_some() || index + 2 != arguments.len() {
                return None;
            }
            endpoint = Some(&arguments[index + 1]);
            break;
        }
        let (mut name, mut attached) = argument
            .split_once('=')
            .map_or((argument.as_str(), None), |(a, b)| (a, Some(b)));
        if attached.is_none()
            && argument.len() > 2
            && ["-f", "-F", "-H", "-X", "-h", "-p"]
                .iter()
                .any(|prefix| argument.starts_with(prefix))
        {
            name = &argument[..2];
            attached = Some(&argument[2..]);
        }
        if matches!(
            name,
            "--include" | "--paginate" | "--silent" | "--slurp" | "--verbose" | "-i"
        ) {
            if attached.is_some() {
                return None;
            }
            index += 1;
            continue;
        }
        if matches!(
            name,
            "--cache"
                | "--field"
                | "--header"
                | "--hostname"
                | "--input"
                | "--jq"
                | "--method"
                | "--preview"
                | "--raw-field"
                | "--template"
                | "-F"
                | "-H"
                | "-X"
                | "-f"
                | "-h"
                | "-p"
        ) {
            let value = if let Some(value) = attached {
                value
            } else {
                index += 1;
                arguments.get(index)?.as_str()
            };
            if !field_is_static(value) {
                return None;
            }
            match name {
                "--method" | "-X" => method = Some(value),
                "--field" | "--raw-field" | "-f" | "-F" => {
                    let (key, value) = value.split_once('=')?;
                    if key.is_empty() {
                        return None;
                    }
                    fields.push((key, value));
                }
                "--header" | "-H" if !safe_header(value) => return None,
                "--input" => return None,
                _ => {}
            }
        } else if argument.starts_with('-') || endpoint.is_some() {
            return None;
        } else {
            endpoint = Some(argument);
        }
        index += 1;
    }
    let endpoint = endpoint?;
    if endpoint.is_empty()
        || endpoint.starts_with('-')
        || endpoint.contains("://")
        || !endpoint
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_./{}:+,@=?&-".contains(&byte))
        || endpoint.eq_ignore_ascii_case("graphql")
    {
        return None;
    }
    let method = method
        .unwrap_or(if fields.is_empty() { "GET" } else { "POST" })
        .to_ascii_uppercase();
    if matches!(method.as_str(), "GET" | "HEAD") {
        return one("read_remote");
    }
    Some(mutation_capabilities(endpoint, &method, &fields))
}

fn mutation_capabilities(
    endpoint: &str,
    method: &str,
    fields: &[(&str, &str)],
) -> Vec<&'static str> {
    let endpoint_path = endpoint.split_once('?').map_or(endpoint, |(path, _)| path);
    let lowered = endpoint_path.trim_matches('/').to_ascii_lowercase();
    let segments: Vec<&str> = lowered
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    let mut capabilities = Vec::new();
    let issue_lock = segments.len() == 6
        && segments[0] == "repos"
        && segments[3] == "issues"
        && segments[5] == "lock";
    let maintenance = issue_lock && matches!(method, "PUT" | "DELETE");
    let merge = segments.contains(&"merges")
        || (segments.contains(&"pulls") && segments.last() == Some(&"merge"));
    let content_index = segments.iter().position(|segment| *segment == "contents");
    let workflow_file = content_index.is_some_and(|index| {
        segments.get(index + 1) == Some(&".github") && segments.get(index + 2) == Some(&"workflows")
    });
    let workflow = workflow_file
        || ((segments.contains(&"actions") || segments.contains(&"workflows"))
            && segments.iter().any(|segment| {
                matches!(
                    *segment,
                    "cancel" | "disable" | "dispatches" | "enable" | "rerun" | "rerun-failed-jobs"
                )
            }))
        || (segments.len() >= 4 && segments[0] == "repos" && segments[3] == "dispatches");
    let secret = segments.contains(&"secrets")
        || (segments.contains(&"runners")
            && segments
                .last()
                .is_some_and(|segment| matches!(*segment, "registration-token" | "remove-token")));
    let access = segments.iter().any(|segment| {
        matches!(
            *segment,
            "collaborators"
                | "memberships"
                | "permissions"
                | "protection"
                | "rulesets"
                | "deployments"
                | "hooks"
                | "keys"
                | "transfer"
        )
    }) || (method == "PATCH" && segments.len() == 3 && segments[0] == "repos");
    let content = if content_index.is_some() {
        !workflow_file
    } else {
        segments.iter().any(|segment| {
            matches!(
                *segment,
                "comments" | "discussions" | "gists" | "issues" | "labels" | "milestones" | "pulls"
            )
        })
    };
    if method == "DELETE" && !maintenance {
        capabilities.push("delete_remote");
    }
    if merge {
        capabilities.push("merge_remote");
    }
    if workflow {
        capabilities.push("workflow_remote");
    }
    if segments.contains(&"releases") || segments.contains(&"release-assets") {
        capabilities.push("publish_remote");
    }
    if secret {
        capabilities.push("secret_remote");
    }
    if access {
        capabilities.push("access_remote");
    }
    if segments.contains(&"refs")
        && fields.iter().any(|(key, value)| {
            key.eq_ignore_ascii_case("force") && value.eq_ignore_ascii_case("true")
        })
    {
        capabilities.push("force_remote");
    }
    if content && !merge && !issue_lock {
        capabilities.push("content_remote");
    }
    if maintenance {
        capabilities.push("maintain_remote");
    }
    if capabilities.is_empty() {
        capabilities.push("mutate_remote");
    }
    capabilities
}
