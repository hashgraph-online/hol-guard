//! `git config` writes of plain keys, proven without review.
//!
//! Git runs or connects to what a fixed set of sections names: `core.pager`,
//! `alias.*`, `credential.*`, `filter.*`, `url.*`, `remote.*`, `include*` and
//! the rest of the sections Git documents. A key in a section Git does not
//! define, whose name carries no program, path, URL or credential marker and
//! whose value is a short plain word, configures nothing Git runs. Setting or
//! unsetting such a key in the repository's own file is how agents mark a
//! checkout while they test it. Writes to the global, system or a named file,
//! and every key in a known section, keep their review.

use crate::CanonicalCommandV1;
use std::time::Instant;

pub(crate) const REASON: &str = "native_exact_safe_git_config_write";

/// Sections Git and its bundled commands read, lowercase. A key in any of
/// them may change what Git runs or where it connects.
#[rustfmt::skip]
const KNOWN_SECTIONS: &[&str] = &[
    "add", "advice", "alias", "am", "apply", "attr", "author", "bitmappseudomerge", "blame",
    "branch", "browser", "bundle", "checkout", "clean", "clone", "color", "column", "commit",
    "commitgraph", "committer", "completion", "core", "credential", "credentialcache",
    "credentialstore", "cvsimport", "diff", "difftool", "extensions", "fastimport", "feature",
    "fetch", "filter", "format", "fsck", "fsmonitor", "gc", "git-p4", "gitcvs", "gitflow",
    "gitweb", "gpg", "grep", "gui", "guitool", "hasconfig", "help", "hook", "http", "i18n",
    "imap", "include", "includeif", "index", "init", "instaweb", "interactive", "lfs", "log",
    "lsrefs", "mailinfo", "mailmap", "maintenance", "man", "merge", "mergetool", "notes", "p4",
    "pack", "pager", "pretty", "promisor", "protocol", "pull", "push", "rebase", "receive",
    "receivepack", "reftable", "remote", "remotes", "repack", "replay", "rerere", "revert",
    "safe", "sendemail", "sendpack", "sequence", "showbranch", "sparse", "splitindex", "ssh",
    "stash", "status", "submodule", "svn", "svn-remote", "tag", "tar", "trace2", "trailer",
    "transfer", "uploadarchive", "uploadpack", "uploadpackfilter", "url", "user",
    "versionsort", "web", "worktree",
];

/// Lowercase fragments of a key that names a program, a location or a
/// secret, whatever its section.
#[rustfmt::skip]
const MARKERS: &[&str] = &[
    "askpass", "auth", "cmd", "command", "credential", "driver", "editor", "exec", "filter",
    "gpg", "helper", "hook", "include", "insteadof", "key", "pager", "password", "path",
    "program", "prog", "provider", "proxy", "script", "secret", "shell", "sign", "ssh",
    "textconv", "token", "tool", "url",
];

const MAX_KEY_BYTES: usize = 128;
const MAX_VALUE_BYTES: usize = 256;

/// The key a plain repository-file write sets or unsets, given the
/// arguments after `config`; `None` for every other form.
pub(crate) fn plain_write(arguments: &[String]) -> Option<&str> {
    let words: Vec<&str> = arguments
        .iter()
        .map(String::as_str)
        .filter(|word| *word != "--local")
        .collect();
    if arguments.len() - words.len() > 1 {
        return None;
    }
    let key = match words.as_slice() {
        ["unset" | "--unset" | "--unset-all", key] => *key,
        ["set", key, value] | [key, value] if plain_value(value) => *key,
        _ => return None,
    };
    plain_key(key).then_some(key)
}

fn plain_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    let Some((section, rest)) = lower.split_once('.') else {
        return false;
    };
    let (subsection, name) = rest.rsplit_once('.').unwrap_or(("", rest));
    let word = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    };
    key.len() <= MAX_KEY_BYTES
        && word(section)
        && section.starts_with(|c: char| c.is_ascii_alphabetic())
        && word(name)
        && name.starts_with(|c: char| c.is_ascii_alphabetic())
        && (!rest.contains('.')
            || (!subsection.is_empty()
                && subsection
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))))
        && !KNOWN_SECTIONS.contains(&section)
        && !MARKERS.iter().any(|marker| lower.contains(marker))
}

fn plain_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_VALUE_BYTES
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._,:@+=-".contains(&byte))
}

/// A command whose Git segments are plain writes at the head of their
/// pipelines, each in a repository the agent's own Git resolves through a
/// proven route, and whose other segments are proven on their own.
pub(in crate::pretool) fn exact_safe_command(
    model: &CanonicalCommandV1,
    context: super::super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<(&'static str, &'static str)> {
    if model.confidence != "exact"
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
        || model.segments.is_empty()
    {
        return None;
    }
    let mut writes = Vec::new();
    for original in &model.segments {
        let stripped = super::super::segment_proof::without_stderr_merge(original);
        let segment = stripped.as_ref().unwrap_or(original);
        match write_leading(segment, context) {
            Some(count) => writes.push((
                original.executable.as_deref()?,
                original.arguments.get(..count)?,
            )),
            None if segment.executable.as_deref() == Some("cd") => return None,
            None if super::super::segment_proof::exact_safe_segment_with_context(
                model, original, false, context,
            ) => {}
            None => return None,
        }
    }
    if writes.is_empty() {
        return None;
    }
    // The probe runs the agent's own Git through the same routes and must
    // find a repository whose configuration it can read.
    let repository = writes.iter().all(|(executable, leading)| {
        super::super::git_session_probe::Probe::new(
            executable,
            leading,
            context,
            deadline,
            execution_environment,
        )
        .is_some_and(|probe| {
            probe.text(&["rev-parse", "--absolute-git-dir"]).is_some() && probe.config().is_some()
        })
    });
    repository.then_some((
        REASON,
        "The Rust command authority proved this Git command only records a plain setting Git never runs, in a repository reached through a proven route.",
    ))
}

/// How many leading routing options a plain config write has, or `None`.
fn write_leading(
    segment: &crate::CommandSegmentV1,
    context: super::super::PathContext<'_>,
) -> Option<usize> {
    if super::super::executable_basename(segment.executable.as_deref()?) != "git"
        || segment.pipeline_index != 0
        || segment.path_overridden
        || !segment.wrapper_chain.is_empty()
        || !segment.environment_names.is_empty()
        || segment.text.contains(['>', '<', '$', '`', '\n', '\r'])
        || !super::super::directory_targets::drive_targets_quoted(segment)
        || !super::super::directory_targets::home_targets_unquoted(segment)
    {
        return None;
    }
    let remaining =
        crate::command_compatibility::git_routed_arguments(&segment.arguments, context)?;
    let (command, rest) = remaining.split_first()?;
    (command == "config" && plain_write(rest).is_some())
        .then(|| segment.arguments.len() - remaining.len())
}

#[cfg(test)]
mod tests {
    fn words(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn only_plain_keys_in_the_repository_file_are_plain_writes() {
        for arguments in [
            "rehearsal.probe true",
            "--local review.lane fix-1",
            "set rehearsal.probe 1",
            "--unset rehearsal.probe",
            "unset rehearsal.probe",
            "agent.session-3.state ready",
        ] {
            assert!(
                super::plain_write(&words(arguments)).is_some(),
                "{arguments}"
            );
        }
        for arguments in [
            "core.pager less",
            "user.name someone",
            "alias.st !id",
            "url.https://evil.example/.insteadOf https://github.com/",
            "credential.helper store",
            "include.path extra",
            "includeIf.gitdir:/tmp/.path extra",
            "remote.origin.url https://evil.example/app.git",
            "filter.lfs.process id",
            "rehearsal.editor vim",
            "rehearsal.hooksDir hooks",
            "rehearsal.tokenFile x",
            "rehearsal.probe /tmp/x",
            "rehearsal.probe -x",
            "--global rehearsal.probe true",
            "--system rehearsal.probe true",
            "--file /tmp/x rehearsal.probe true",
            "--local --local rehearsal.probe true",
            "--add rehearsal.probe true",
            "rehearsal true",
            "rehearsal.1probe true",
            "--list",
            "rehearsal.probe",
        ] {
            assert!(
                super::plain_write(&words(arguments)).is_none(),
                "{arguments}"
            );
        }
    }
}
