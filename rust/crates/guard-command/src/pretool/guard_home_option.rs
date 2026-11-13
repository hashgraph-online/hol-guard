//! A `--home` option that names the Guard home the command already uses.
//!
//! Guard's inspection commands read the store under their home. Without
//! `--home` that is the account's own `.hol-guard` directory, once it exists
//! and no home left by an older release sits beside it. Another home is one
//! the command may create or that holds someone else's state, so root
//! overrides stay under review. A `--home` that spells that same directory
//! as an absolute path reads the store the plain command reads, so it is set
//! aside before the subcommand is checked: `hol-guard approvals wait <id>
//! --home /Users/me/.hol-guard` is proven the way `hol-guard approvals wait
//! <id>` is.

/// [`super::guard_diagnostics::safe_hol_guard_segment`] for `segment`, read
/// once as written and once more with a `--home` naming the account's own
/// Guard home set aside.
pub(super) fn safe_hol_guard_segment(
    basename: &str,
    segment: &crate::CommandSegmentV1,
    context: super::PathContext<'_>,
) -> bool {
    let proven = |arguments: &[String]| {
        super::guard_diagnostics::safe_hol_guard_segment(
            basename,
            arguments,
            context.cwd,
            segment.pipeline_index,
        )
    };
    proven(&segment.arguments)
        || without_own_home(&segment.arguments, context.home_dir).is_some_and(|rest| proven(&rest))
}

/// Home directories older releases kept Guard's state in, beside the user's
/// home. When one exists the launcher may still resolve to it, or move it
/// into `.hol-guard` on its next start (`guard_home_resolve` in the runtime
/// crate), so a `--home` naming `.hol-guard` is not proven to be the home it
/// uses.
const LEGACY_DIRNAMES: [&str; 3] = [
    ".config/.ai-plugin-scanner-guard",
    ".ai-plugin-scanner-guard",
    ".holguard",
];

/// `arguments` without their one `--home` option, when that option names the
/// Guard home the launcher uses without it: `.hol-guard` under the account's
/// home, which already exists, with no legacy home beside it. `None` when
/// there is no such option, when it names any other directory, or when it is
/// given more than once.
pub(super) fn without_own_home(
    arguments: &[String],
    home_dir: Option<&str>,
) -> Option<Vec<String>> {
    let home = normal_home(home_dir?)?;
    let own = format!("{home}/.hol-guard");
    let launcher_home = std::path::Path::new(&own).is_dir()
        && !LEGACY_DIRNAMES
            .iter()
            .any(|legacy| std::path::Path::new(&format!("{home}/{legacy}")).exists());
    if !launcher_home {
        return None;
    }
    without_home_option(arguments, &own)
}

/// The account's home as an absolute path with `/` separators and no
/// trailing one: a POSIX path, or a Windows drive path whose `\` separators
/// are rewritten. `None` for anything else.
fn normal_home(home: &str) -> Option<String> {
    let home = if drive_path(home) {
        home.replace('\\', "/")
    } else if home.starts_with('/') {
        home.to_owned()
    } else {
        return None;
    };
    let home = home.trim_end_matches('/');
    (!home.is_empty() && !home.ends_with(':')).then(|| home.to_owned())
}

fn drive_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
}

/// `arguments` without their one `--home` option when it names `own`. A
/// Windows drive path matches with either separator and in any letter case,
/// as Windows resolves it.
fn without_home_option(arguments: &[String], own: &str) -> Option<Vec<String>> {
    let same = |value: &str| {
        if drive_path(own) {
            drive_path(value)
                && value
                    .replace('\\', "/")
                    .trim_end_matches('/')
                    .eq_ignore_ascii_case(own)
        } else {
            value.trim_end_matches('/') == own
        }
    };
    let mut rest = Vec::with_capacity(arguments.len());
    let mut found = false;
    let mut words = arguments.iter();
    while let Some(word) = words.next() {
        let value = if word == "--home" {
            words.next()?.as_str()
        } else if let Some(value) = word.strip_prefix("--home=") {
            value
        } else {
            rest.push(word.clone());
            continue;
        };
        if found || !same(value) {
            return None;
        }
        found = true;
    }
    found.then_some(rest)
}

#[cfg(test)]
#[path = "guard_home_option_tests.rs"]
mod tests;
