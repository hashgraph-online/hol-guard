//! Value ownership is explicit; unsupported clustered selectors cannot imply a read.
use super::{one, Capabilities};

pub(super) fn has_option(arguments: &[String], expected: &str) -> bool {
    arguments.iter().any(|argument| {
        argument == expected
            || argument
                .strip_prefix(expected)
                .is_some_and(|tail| tail.starts_with('='))
    })
}

fn repository(value: &str) -> bool {
    let parts: Vec<&str> = value.split('/').collect();
    let components = if parts.len() == 3 && parts[0].eq_ignore_ascii_case("github.com") {
        &parts[1..]
    } else {
        &parts[..]
    };
    components.len() == 2
        && components.iter().all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
        })
}

pub(super) fn validate_selectors(arguments: &[String]) -> Option<()> {
    let mut selectors = 0;
    let mut host: Option<&str> = None;
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        let mut selector = None;
        let mut hostname = None;
        if matches!(argument.as_str(), "--repo" | "-R") {
            index += 1;
            selector = Some(arguments.get(index)?.as_str());
        } else if let Some(value) = argument.strip_prefix("--repo=") {
            selector = Some(value);
        } else if let Some(value) = argument.strip_prefix("-R") {
            // Python rejects the -R=owner/repo spelling as an invalid selector.
            if !value.is_empty() {
                selector = Some(value);
            }
        } else if argument == "--hostname" || (argument == "-h" && index > 0) {
            index += 1;
            hostname = Some(arguments.get(index)?.as_str());
        } else if let Some(value) = argument.strip_prefix("--hostname=") {
            hostname = Some(value);
        } else if index > 0 && argument.starts_with("-h") && argument != "--help" {
            hostname = Some(&argument[2..]);
        } else if argument.starts_with('-')
            && !argument.starts_with("--")
            && argument[1..].contains('R')
        {
            // Per-subcommand boolean/value short clusters need their own proof.
            return None;
        }
        if let Some(value) = selector {
            selectors += 1;
            if selectors > 1 || !repository(value) {
                return None;
            }
        }
        if let Some(value) = hostname {
            if !value.eq_ignore_ascii_case("github.com") || host.is_some_and(|old| old != value) {
                return None;
            }
            host = Some(value);
        }
        index += 1;
    }
    Some(())
}

pub(super) fn strip_globals(arguments: &[String]) -> Option<&[String]> {
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        if argument.starts_with("-R") && argument != "-R" {
            index += 1;
        } else if matches!(argument.split('=').next()?, "--hostname" | "--repo" | "-R") {
            if argument.contains('=') {
                index += 1;
            } else {
                arguments.get(index + 1)?;
                index += 2;
            }
        } else {
            break;
        }
    }
    Some(&arguments[index..])
}

fn positive_number(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 20
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.bytes().any(|byte| byte != b'0')
}

fn boolean_token(argument: &str, option: &str) -> Result<Option<bool>, ()> {
    if argument == option {
        return Ok(Some(true));
    }
    let Some(value) = argument
        .strip_prefix(option)
        .and_then(|tail| tail.strip_prefix('='))
    else {
        return Ok(None);
    };
    match value {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Ok(Some(true)),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Ok(Some(false)),
        _ => Err(()),
    }
}

fn boolean_state(arguments: &[String], option: &str) -> Result<Option<bool>, ()> {
    let mut state = None;
    for argument in arguments
        .iter()
        .take_while(|argument| argument.as_str() != "--")
    {
        if let Some(value) = boolean_token(argument, option)? {
            state = Some(value);
        }
    }
    Ok(state)
}

fn routine_merge(arguments: &[String]) -> bool {
    let mut number = false;
    let mut squash = false;
    let mut cleanup = false;
    let mut repo = false;
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        let Ok(delete) = boolean_token(argument, "--delete-branch") else {
            return false;
        };
        if argument == "--squash" && !squash {
            squash = true;
        } else if delete.is_some() && !cleanup {
            cleanup = true;
        } else if matches!(argument.as_str(), "--repo" | "-R") && !repo {
            index += 1;
            let Some(value) = arguments.get(index) else {
                return false;
            };
            if value.len() > 255 || !repository(value) {
                return false;
            }
            repo = true;
        } else if let Some(value) = argument.strip_prefix("--repo=") {
            if repo || value.len() > 255 || !repository(value) {
                return false;
            }
            repo = true;
        } else if !number && positive_number(argument) {
            number = true;
        } else {
            return false;
        }
        index += 1;
    }
    number && squash
}

pub(super) fn merge(arguments: &[String]) -> Capabilities {
    if routine_merge(arguments) {
        return one("routine_merge_remote");
    }
    let Ok(admin) = boolean_state(arguments, "--admin") else {
        return one("unknown");
    };
    let Ok(delete) = boolean_state(arguments, "--delete-branch") else {
        return one("unknown");
    };
    let mut values = vec![if admin == Some(true) {
        "admin_merge_remote"
    } else {
        "merge_remote"
    }];
    if delete == Some(true) {
        values.push("delete_remote");
    }
    Some(values)
}

pub(super) fn routine_rerun(original: &[String], arguments: &[String]) -> bool {
    if !original
        .iter()
        .any(|value| value == "--repo" || value.starts_with("--repo=") || value.starts_with("-R"))
    {
        return false;
    }
    let mut number = false;
    let mut failed = false;
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        if argument == "--failed" && !failed {
            failed = true;
        } else if matches!(argument.as_str(), "--repo" | "-R") {
            index += 1;
            if arguments.get(index).is_none() {
                return false;
            }
        } else if argument.starts_with("--repo=") || argument.starts_with("-R") {
        } else if !number && positive_number(argument) {
            number = true;
        } else {
            return false;
        }
        index += 1;
    }
    number && failed
}

pub(super) fn inline_proposal(arguments: &[String]) -> Option<bool> {
    let mut title = false;
    let mut body = false;
    // Compatibility deliberately scans these spellings even in another option's
    // value. A more permissive role-aware interpretation here would newly turn
    // Python's reviewed content mutation into an allowed proposal.
    let mut derived = arguments.iter().any(|argument| {
        [
            "--body-file",
            "--template",
            "--fill",
            "--fill-first",
            "--fill-verbose",
            "--recover",
            "--web",
            "--editor",
            "--dry-run",
        ]
        .iter()
        .any(|option| {
            argument == option
                || argument
                    .strip_prefix(option)
                    .is_some_and(|tail| tail.starts_with('='))
        }) || argument.starts_with("-F")
            || argument.starts_with("-T")
    });
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        let (name, attached) = argument
            .split_once('=')
            .map_or((argument.as_str(), None), |(a, b)| (a, Some(b)));
        if matches!(
            name,
            "--fill" | "--fill-first" | "--fill-verbose" | "--web" | "--editor" | "--dry-run"
        ) {
            derived = true;
            index += 1;
            continue;
        }
        let value_option = matches!(
            name,
            "--title"
                | "-t"
                | "--body"
                | "-b"
                | "--body-file"
                | "-F"
                | "--template"
                | "-T"
                | "--recover"
                | "--assignee"
                | "--base"
                | "--head"
                | "--label"
                | "--milestone"
                | "--project"
                | "--repo"
                | "-R"
                | "--reviewer"
        );
        if !value_option {
            return None;
        }
        let value = if let Some(value) = attached {
            value
        } else {
            index += 1;
            arguments.get(index)?.as_str()
        };
        if matches!(name, "--title" | "-t") {
            title |= !value.is_empty();
        }
        if matches!(name, "--body" | "-b") {
            body |= !value.is_empty();
        }
        if matches!(
            name,
            "--body-file" | "-F" | "--template" | "-T" | "--recover"
        ) {
            derived = true;
        }
        index += 1;
    }
    Some(title && body && !derived)
}
