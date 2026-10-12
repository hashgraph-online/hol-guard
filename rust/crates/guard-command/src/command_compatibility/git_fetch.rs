use crate::CommandSegmentV1;

const MAX_ARGUMENTS: usize = 16;
const MAX_REFS: usize = 12;
const MAX_REF_LENGTH: usize = 256;

/// True only for a plain named-origin refresh: a bare `git` invocation with no
/// global options, wrappers, or environment, the literal `origin` remote,
/// quiet/prune style flags, and simple named refs. This mirrors Python's
/// `origin_shaped_git_fetch_args`. It does not prove repository configuration,
/// so the observation stays a review rule an administrator must allow.
pub(super) fn plain_origin_refresh(segment: &CommandSegmentV1, command_index: usize) -> bool {
    if command_index != 0
        || segment.executable.as_deref() != Some("git")
        || segment.path_overridden
        || !segment.wrapper_chain.is_empty()
        || !segment.environment_names.is_empty()
    {
        return false;
    }
    let Some(rest) = segment.arguments.get(1..) else {
        return false;
    };
    origin_shaped_arguments(rest)
}

fn origin_shaped_arguments(arguments: &[String]) -> bool {
    if arguments.is_empty() || arguments.len() > MAX_ARGUMENTS {
        return false;
    }
    let mut remote_seen = false;
    let mut refs = 0usize;
    for argument in arguments {
        if matches!(
            argument.as_str(),
            "-q" | "--quiet" | "--no-tags" | "--prune" | "-p"
        ) {
            continue;
        }
        if argument.starts_with('-') || (!remote_seen && argument != "origin") {
            return false;
        }
        if !remote_seen {
            remote_seen = true;
            continue;
        }
        if !named_ref(argument) {
            return false;
        }
        refs += 1;
    }
    remote_seen && refs <= MAX_REFS
}

fn named_ref(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value.len() <= MAX_REF_LENGTH
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || b"._/-".contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segment(command: &str) -> CommandSegmentV1 {
        let model = crate::parse_command(
            &serde_json::from_value(serde_json::json!({"command": command})).unwrap(),
        )
        .unwrap();
        model.segments[0].clone()
    }

    #[test]
    fn plain_origin_refresh_accepts_only_named_origin_forms() {
        for command in [
            "git fetch origin",
            "git fetch origin main",
            "git fetch --quiet origin",
            "git fetch -q origin main release/3.0",
            "git fetch origin --prune --no-tags",
        ] {
            assert!(plain_origin_refresh(&segment(command), 0), "{command}");
        }
    }

    #[test]
    fn plain_origin_refresh_rejects_everything_else() {
        for command in [
            "git fetch",
            "git fetch --all",
            "git fetch upstream",
            "git fetch https://example.invalid/project.git",
            "git fetch origin --upload-pack=payload",
            "git fetch origin -c core.sshCommand=payload",
            "git fetch origin --config=x=y",
            "git fetch origin --force",
            "git fetch origin +main:main",
            "git fetch origin $HOME",
            "git -c core.sshCommand=payload fetch origin",
            "git --exec-path=/tmp fetch origin",
            "git -C workspace fetch origin",
            "GIT_SSH_COMMAND=payload git fetch origin",
            "/tmp/git fetch origin",
            "sudo git fetch origin",
        ] {
            assert!(!plain_origin_refresh(&segment(command), 0), "{command}");
        }
        assert!(!plain_origin_refresh(&segment("git fetch origin"), 1));
    }
}
