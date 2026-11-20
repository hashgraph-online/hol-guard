use crate::CommandSegmentV1;

const MAX_ARGUMENTS: usize = 16;
const MAX_REFS: usize = 12;
const MAX_REF_LENGTH: usize = 256;

/// How far a refresh reaches. `Origin` names the remote in the command
/// itself. `EveryRemote` is the refresh spelled without one: `git fetch`
/// contacts the remote the current branch tracks, and `git fetch --all`
/// contacts every remote the repository configures. Neither names a remote
/// the command line could point somewhere else, but both leave the choice to
/// configuration, so the proof pairs this reach with a reading of it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Reach {
    Origin,
    EveryRemote,
}

/// True only for a plain refresh: a bare `git` invocation with no global
/// options, wrappers, or environment, the literal `origin` remote or no
/// remote at all, quiet/prune/tags/dry-run style flags, and simple named
/// refs. It reads the shape the retired `origin_shaped_git_fetch_args` read,
/// plus the dry run that describes the same refresh. It does not prove
/// repository configuration, so the observation stays a review rule an
/// administrator must allow.
pub(super) fn plain_refresh(segment: &CommandSegmentV1, command_index: usize) -> Option<Reach> {
    if command_index != 0
        || segment.executable.as_deref() != Some("git")
        || segment.path_overridden
        || !segment.wrapper_chain.is_empty()
        || !segment.environment_names.is_empty()
    {
        return None;
    }
    reach(segment.arguments.get(1..)?)
}

/// The same refresh after leading `-C` routes the caller already proved stay
/// within the workspace; the remote, flags and refs follow the same shape.
pub(super) fn routed_refresh(segment: &CommandSegmentV1, command_index: usize) -> Option<Reach> {
    if segment.executable.as_deref() != Some("git")
        || segment.path_overridden
        || !segment.wrapper_chain.is_empty()
        || !segment.environment_names.is_empty()
        || !segment.arguments[..command_index]
            .chunks(2)
            .all(|pair| matches!(pair, [flag, _] if flag == "-C"))
    {
        return None;
    }
    reach(segment.arguments.get(command_index + 1..)?)
}

pub(super) fn reach(arguments: &[String]) -> Option<Reach> {
    if origin_shaped_arguments(arguments) {
        return Some(Reach::Origin);
    }
    default_remote_arguments(arguments).then_some(Reach::EveryRemote)
}

/// Flags that change what the refresh prints or how much of the remote it
/// copies, and nothing else. `--dry-run` reports what the same refresh would
/// bring and updates no ref. `--tags` and `--no-tags` only widen or narrow
/// the refs copied, and a tag carries no program. Fetch spells the dry run
/// long only: its `-n` is `--no-tags`.
fn inert_flag(argument: &str) -> bool {
    matches!(
        argument,
        "-q" | "--quiet"
            | "-v"
            | "--verbose"
            | "--progress"
            | "--no-progress"
            | "--no-tags"
            | "-n"
            | "--tags"
            | "-t"
            | "--prune"
            | "-p"
            | "--dry-run"
    )
}

/// The refresh spelled without a remote or a ref: `git fetch`, `git fetch
/// --all`, and those flags. `--prune-tags` is not among them; it deletes
/// local tags rather than remote-tracking refs.
fn default_remote_arguments(arguments: &[String]) -> bool {
    arguments.len() <= MAX_ARGUMENTS
        && arguments
            .iter()
            .all(|argument| inert_flag(argument) || argument == "--all")
}

pub(super) fn origin_shaped_arguments(arguments: &[String]) -> bool {
    if arguments.is_empty() || arguments.len() > MAX_ARGUMENTS {
        return false;
    }
    let mut remote_seen = false;
    let mut refs = 0usize;
    for argument in arguments {
        if inert_flag(argument) {
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
    fn a_named_origin_refresh_reaches_origin() {
        for command in [
            "git fetch origin",
            "git fetch origin main",
            "git fetch --quiet origin",
            "git fetch -q origin main release/3.0",
            "git fetch origin --prune --no-tags",
            "git fetch --dry-run origin",
            "git fetch origin main --dry-run",
            "git fetch -n origin",
            "git fetch --tags origin",
            "git fetch origin --tags --prune",
            "git fetch -t origin main",
            "git fetch --progress origin",
            "git fetch -v origin",
        ] {
            assert_eq!(
                plain_refresh(&segment(command), 0),
                Some(Reach::Origin),
                "{command}"
            );
        }
    }

    #[test]
    fn a_refresh_that_names_no_remote_reaches_whatever_configuration_names() {
        for command in [
            "git fetch",
            "git fetch --all",
            "git fetch --prune",
            "git fetch --all --prune",
            "git fetch --tags",
            "git fetch --all --prune --quiet",
            "git fetch --dry-run",
        ] {
            assert_eq!(
                plain_refresh(&segment(command), 0),
                Some(Reach::EveryRemote),
                "{command}"
            );
        }
    }

    #[test]
    fn a_refresh_reaches_nowhere_the_proof_can_follow() {
        for command in [
            "git fetch upstream",
            "git fetch --all upstream",
            "git fetch https://example.invalid/project.git",
            "git fetch origin --upload-pack=payload",
            "git fetch origin -c core.sshCommand=payload",
            "git fetch origin --config=x=y",
            "git fetch origin --force",
            "git fetch --force",
            "git fetch --prune-tags",
            "git fetch -P",
            "git fetch origin --dry-run=payload",
            "git fetch origin +main:main",
            "git fetch origin $HOME",
            "git -c core.sshCommand=payload fetch origin",
            "git --exec-path=/tmp fetch origin",
            "git -C workspace fetch origin",
            "GIT_SSH_COMMAND=payload git fetch origin",
            "/tmp/git fetch origin",
            "sudo git fetch origin",
        ] {
            assert_eq!(plain_refresh(&segment(command), 0), None, "{command}");
        }
        assert_eq!(plain_refresh(&segment("git fetch origin"), 1), None);
    }
}
