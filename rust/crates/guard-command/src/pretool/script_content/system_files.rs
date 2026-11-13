//! Inline programs that name a system file.
//!
//! The workspace sandbox withholds the home directory and the network, but a
//! contained program can still read most system files: account and group
//! databases, kernel and process state, system logs and package state. A
//! program whose own source names one of those files (`open('/etc/passwd')`,
//! `open('/root/.bashrc', 'a')`) is asking for exactly what containment does
//! not take away, so its review is kept. Only inline source and programs fed
//! on standard input are read here; a script file keeps its own route.

use std::sync::LazyLock;

use regex::Regex;

use super::destructive_git::without_comments;
use super::{assess_programs, sent_model, PathContext};
use crate::CanonicalCommandV1;
use guard_contracts::PreToolResultV1;

/// A quoted absolute path under a system root, in single, double or
/// backtick quotes.
static SYSTEM_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"["'`](/(?:private/)?(?:etc|root|proc|sys|boot|var|usr)(?:/[^"'`\s]*)?)["'`]"#)
        .unwrap()
});

/// Prefixes under the system roots that hold programs, libraries and scratch
/// space rather than system state. A path below one of them is not a system
/// file for this check.
const NOT_SYSTEM_STATE: &[&str] = &[
    "/var/folders/",
    "/var/tmp/",
    "/private/var/folders/",
    "/private/var/tmp/",
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/lib/",
    "/usr/libexec/",
    "/usr/include/",
    "/usr/local/",
];

/// `path` with `.` and `..` components resolved, as the kernel would resolve
/// them before following any link.
fn lexical(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    format!("/{}", parts.join("/"))
}

/// Whether `code` names a system file by a literal path.
pub(super) fn names_system_file(code: &str) -> bool {
    SYSTEM_PATH.captures_iter(code).any(|captures| {
        let path = &lexical(&captures[1]);
        let path = path.as_str();
        !matches!(path, "/usr" | "/var" | "/private/var")
            && !NOT_SYSTEM_STATE.iter().any(|prefix| {
                // `/var/tmp/` resolves to `/var/tmp`: the directory itself
                // is as much scratch space as anything below it.
                path.starts_with(prefix) || path == prefix.trim_end_matches('/')
            })
    })
}

fn programs_name_system_file(model: &CanonicalCommandV1, context: PathContext<'_>) -> bool {
    let modeled = assess_programs(model, context, false).iter().any(|found| {
        found.sources.iter().any(|source| match found.language {
            Some(language) => names_system_file(&without_comments(language, source)),
            None => names_system_file(source),
        })
    });
    modeled
        || super::destructive_git::other_inline_sources(model, context)
            .iter()
            .any(|source| names_system_file(source))
}

/// Whether an inline program the POSIX shell text `command` launches names a
/// system file, for a caller that judges a projection with the program's
/// heredoc or input redirect removed.
pub(in crate::pretool) fn text_names_system_file(command: &str, context: PathContext<'_>) -> bool {
    crate::parse_command(&crate::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })
    .is_ok_and(|model| programs_name_system_file(&model, context))
}

/// Keeps the review of a command whose inline program names a system file.
pub(in crate::pretool) fn keeps_system_file_review(
    result: &mut PreToolResultV1,
    model: &CanonicalCommandV1,
    command_text: Option<&str>,
    context: PathContext<'_>,
) -> bool {
    let named = |model: &CanonicalCommandV1| programs_name_system_file(model, context);
    if !named(model) && !sent_model(model, command_text).is_some_and(|sent| named(&sent)) {
        return false;
    }
    result.reason = concat!(
        "HOL Guard needs your review because this program reads or changes a ",
        "system file, which Guard's sandbox does not hide."
    )
    .into();
    true
}

#[cfg(test)]
#[path = "system_files_tests.rs"]
mod tests;
