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
/// name, or a package name, glob or directory naming the workspace's own
/// projects.
///
/// What is refused is a value that reaches *out* of the workspace. pnpm and
/// npm both select a project by directory as well as by name — `--filter
/// ./packages/web` — and a directory operand is how a selector would reach a
/// project the workspace does not hold, whose scripts the sandbox would then
/// run unreviewed. A directory below where the command was typed is not that
/// reach: `packages/web` already carried the verb past this walk, and
/// `./packages/web` names the same project. So the test is where the value
/// can land, not whether it looks like a path. An absolute path, a `~` home
/// spelling, a drive letter in `C:/other` and a `..` step back are each
/// refused, under either separator.
///
/// The braces of pnpm's own `{<dir>}` selector hold a directory by
/// definition, and they are not only a prefix: pnpm accepts the directory
/// selector after a name pattern, a changed-since ref or an exclusion, as in
/// `web{/opt/other}`, `[origin/main]{/opt/other}` and `!{/opt/other}`. So
/// each piece a brace separates is read on its own, and one of them reaching
/// out refuses the whole value. A comma separates pieces for the same reason,
/// one step earlier: the shell expands `--filter={web,../sibling}` into two
/// words before pnpm sees either, so the second selector never appears in the
/// text this reads. Splitting on the comma reads it anyway. A value carrying
/// `$` is refused outright, since what it names is not in the text. A scoped
/// name such as `@acme/web` still passes, and so does a changed-since
/// selector such as `[origin/main]`, which names a git ref rather than a
/// place on disk.
pub(super) fn inert_value(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && !value.contains('$')
        && !value.chars().any(char::is_whitespace)
        && value
            .split(['{', '}', ','])
            .filter(|piece| !piece.is_empty())
            .all(stays_below_the_workspace)
}

/// Whether `piece` can only name a place below where the command runs.
///
/// A selector is not all path: a name pattern, an exclusion mark and a
/// changed-since ref in brackets are read here too. Reading each of them as a
/// relative path is what makes one test enough — a name never climbs
/// anywhere, so the only pieces this can refuse are the directory spellings
/// it is here to bound.
///
/// pnpm removes its own decorations before it decides whether what is left
/// names a place, so this removes them first too. `...../other` is the `...`
/// that adds a project's dependents in front of `../other`, and pnpm resolves
/// that against the directory the command ran in. Read whole, its components
/// are `.....` and `other` and neither is a step back, so the value has to be
/// read the way pnpm reads it as well as the way it is written.
fn stays_below_the_workspace(piece: &str) -> bool {
    climbs_nowhere(piece) && climbs_nowhere(undecorated(piece))
}

/// `piece` with pnpm's selector decorations removed: a leading exclusion, the
/// `...` or `...^` that adds dependents, and the trailing `...` or `^...`
/// that adds dependencies.
fn undecorated(piece: &str) -> &str {
    let piece = piece.strip_prefix('!').unwrap_or(piece);
    let piece = match piece.strip_prefix("...") {
        Some(rest) => rest.strip_prefix('^').unwrap_or(rest),
        None => piece,
    };
    match piece.strip_suffix("...") {
        Some(rest) => rest.strip_suffix('^').unwrap_or(rest),
        None => piece,
    }
}

/// Whether `piece` names no place above where the command runs.
fn climbs_nowhere(piece: &str) -> bool {
    !piece.starts_with(['/', '\\', '~'])
        && !is_drive_prefixed(piece)
        && !piece.split(['/', '\\']).any(|component| component == "..")
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
