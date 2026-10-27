//! The options a Node package manager reads before its verb.
//!
//! `pnpm --silent build` and `pnpm --filter web test` run exactly the work
//! `pnpm build` and `pnpm test` run; the words in front only say how loud the
//! run is or which of the workspace's own projects it covers. The verb check
//! in [`super::package`] reads the first argument, so without a way past them
//! every one of these spellings hid the verb and left ordinary script work
//! outside the sandbox.

/// How many leading arguments a `manager` run may skip to reach its verb.
///
/// The lists are allowlists and the walk stops at the first word neither one
/// holds, so an option this module does not know still hides the verb and
/// keeps the command out, where it keeps the admission it has today. uv is
/// read the same way by `UV_GLOBAL_FLAGS`.
///
/// The directory options are deliberately absent. `--prefix`, `--dir`, `-C`
/// and `--cwd` move the project the verb works on, and
/// [`super::super::package_directory_flags`] already rewrites those into the
/// `cd <dir> && <manager> <rest>` form this module then judges in the
/// directory they name. Skipping one here instead would judge the command
/// against the directory it was typed in rather than the one it runs in.
pub(super) fn skip_inert_options(manager: &str, arguments: &[&str]) -> usize {
    let (flags, value_options) = inert_options(manager);
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        let (name, inline) = match argument.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (*argument, None),
        };
        if inline.is_none() && flags.contains(&name) {
            index += 1;
            continue;
        }
        if !value_options.contains(&name) {
            break;
        }
        match inline {
            Some(value) if inert_value(value) => index += 1,
            None if arguments.get(index + 1).copied().is_some_and(inert_value) => index += 2,
            _ => break,
        }
    }
    index
}

/// Whether `value` is one an inert option may carry: a log level, a reporter
/// name, or a package name or glob naming the workspace's own projects.
///
/// A value that names a path is refused. pnpm and npm both select a project
/// by directory as well as by name — `--filter ./packages/web` — and a
/// directory operand is how a selector would reach a project the workspace
/// does not hold, whose scripts the sandbox would then run unreviewed. So
/// every spelling of a directory is read: a leading `.`, `/` or `~`, a parent
/// step, a Windows separator, a drive letter in `C:/other`, and the braces of
/// pnpm's own `{<dir>}` selector, whose contents are a directory by
/// definition. The braces are not only a prefix. pnpm accepts the directory
/// selector after a name pattern, a changed-since ref or an exclusion, as in
/// `web{/opt/other}`, `[origin/main]{/opt/other}` and `!{/opt/other}`, so a
/// brace anywhere in the value is a directory. A value carrying `$` is
/// refused with them, since what it names is not in the text. A scoped name
/// such as `@acme/web` still passes, and so does a changed-since selector
/// such as `[origin/main]`, which names a git ref rather than a place on disk.
fn inert_value(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with(['-', '.', '/', '~'])
        && !value.contains("..")
        && !value.contains(['\\', '$', '{', '}'])
        && !is_drive_prefixed(value)
        && !value.chars().any(char::is_whitespace)
}

/// Whether `value` opens with a Windows drive letter, as `C:/other` does.
fn is_drive_prefixed(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() > 1 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

/// The flags and value-taking options `manager` reads before its verb.
fn inert_options(manager: &str) -> (&'static [&'static str], &'static [&'static str]) {
    match manager {
        "npm" => (NPM_FLAGS, NPM_VALUE_OPTIONS),
        "pnpm" => (PNPM_FLAGS, PNPM_VALUE_OPTIONS),
        "yarn" => (YARN_FLAGS, &[]),
        "bun" => (BUN_FLAGS, &[]),
        _ => (&[], &[]),
    }
}

// npm's own output and workspace options. `--no-audit` and `--no-fund` only
// drop reporting an install would have printed, and an install is refused by
// the registry verbs regardless.
const NPM_FLAGS: &[&str] = &[
    "--silent",
    "-s",
    "--quiet",
    "--color",
    "--no-color",
    "--no-audit",
    "--no-fund",
    "--no-progress",
    "--no-update-notifier",
    "--workspaces",
    "--ws",
    "--include-workspace-root",
];
const NPM_VALUE_OPTIONS: &[&str] = &["--loglevel", "--workspace", "-w"];

// pnpm's output options, and the recursive options that run a script in every
// workspace project instead of one. Which projects those are is the
// workspace's own `pnpm-workspace.yaml`, so the work stays where the sandbox
// already bounds it.
const PNPM_FLAGS: &[&str] = &[
    "--silent",
    "-s",
    "--color",
    "--no-color",
    "--recursive",
    "-r",
    "--parallel",
    "--stream",
    "--aggregate-output",
    "--no-bail",
];
const PNPM_VALUE_OPTIONS: &[&str] = &[
    "--loglevel",
    "--reporter",
    "--filter",
    "-F",
    "--filter-prod",
    "--workspace-concurrency",
];

// yarn's output options. `--frozen-lockfile` and the rest of the install
// options are absent on purpose: a bare `yarn` installs, so a run carrying
// only options still has no verb and stays out.
const YARN_FLAGS: &[&str] = &[
    "--silent",
    "-s",
    "--no-progress",
    "--non-interactive",
    "--no-color",
    "--verbose",
];

// bun's output options, and `--bun` for a script the project pins to node.
const BUN_FLAGS: &[&str] = &["--silent", "--bun", "--no-progress"];

#[cfg(test)]
#[path = "workspace_contained_package_options_tests.rs"]
mod tests;
