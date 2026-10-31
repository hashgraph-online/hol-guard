//! A package manager printing its own usage text.
//!
//! `npm install --help`, `pip install --help`, `cargo add --help` and their
//! neighbours never install anything. The manager's own argument parser sees
//! the help flag, prints the text it carries for that subcommand and exits:
//! no registry is contacted, no lockfile is read and no project script runs.
//! Reading a manual page is the step before deciding whether to install, and
//! sending it to review teaches nothing about the install that may follow.
//!
//! Three limits keep that reading narrow.
//!
//! The subcommand has to be one the manager carries itself. `npm`, `pnpm`,
//! `cargo` and `brew` all hand an unknown first word to something else -- a
//! project script, a `cargo-<name>` binary, a tap's command -- and that
//! program decides for itself what `--help` means. Only the names listed
//! below reach the manager's own parser.
//!
//! Nothing may stand between the subcommand and the flag. `npm run build
//! --help` is a script named on the line, and npm forwards the tail to it,
//! so the flag is no longer npm's to answer. Requiring the flag to follow
//! the subcommand directly keeps every operand -- a package, a script, a
//! path -- out of this reading.
//!
//! Four managers are absent on purpose, because their help path loads code
//! from the project before it can print anything: Yarn Berry resolves the
//! plugins named in `.yarnrc.yml`, Poetry loads its entry-point plugins,
//! Composer's plugin manager loads vendor PHP to discover commands, and
//! Bundler shells out to `man`. Their usage pages keep their review.

/// The subcommands each manager answers itself.
///
/// Verbs that run code chosen on the line -- `run`, `exec`, `test`, `init`,
/// `create` and their neighbours -- are left out even where the manager does
/// print usage for them, because the reading cannot tell the harmless page
/// from the script that shares the name.
const BUILTIN_SUBCOMMANDS: &[(&str, &[&str])] = &[
    (
        "npm",
        &[
            "access",
            "audit",
            "bugs",
            "cache",
            "ci",
            "config",
            "dedupe",
            "deprecate",
            "diff",
            "dist-tag",
            "docs",
            "doctor",
            "explain",
            "find-dupes",
            "fund",
            "help",
            "home",
            "i",
            "install",
            "link",
            "list",
            "login",
            "logout",
            "ls",
            "org",
            "outdated",
            "owner",
            "pack",
            "ping",
            "pkg",
            "prefix",
            "profile",
            "prune",
            "publish",
            "query",
            "rebuild",
            "repo",
            "root",
            "sbom",
            "search",
            "shrinkwrap",
            "star",
            "stars",
            "team",
            "token",
            "uninstall",
            "unpublish",
            "unstar",
            "update",
            "version",
            "view",
            "whoami",
        ],
    ),
    (
        "pnpm",
        &[
            "add",
            "audit",
            "bin",
            "config",
            "dedupe",
            "doctor",
            "env",
            "fetch",
            "import",
            "install",
            "licenses",
            "link",
            "list",
            "ls",
            "outdated",
            "pack",
            "patch",
            "patch-commit",
            "patch-remove",
            "prune",
            "publish",
            "rebuild",
            "remove",
            "root",
            "store",
            "unlink",
            "update",
            "why",
        ],
    ),
    (
        "pip",
        &[
            "cache",
            "check",
            "config",
            "debug",
            "download",
            "freeze",
            "hash",
            "index",
            "inspect",
            "install",
            "list",
            "show",
            "uninstall",
            "wheel",
        ],
    ),
    (
        "cargo",
        &[
            "add",
            "bench",
            "build",
            "check",
            "clean",
            "doc",
            "fetch",
            "fix",
            "generate-lockfile",
            "install",
            "locate-project",
            "login",
            "logout",
            "metadata",
            "owner",
            "package",
            "pkgid",
            "publish",
            "remove",
            "report",
            "rustc",
            "rustdoc",
            "search",
            "tree",
            "uninstall",
            "update",
            "vendor",
            "verify-project",
            "yank",
        ],
    ),
    (
        "uv",
        &[
            "add", "build", "cache", "export", "lock", "pip", "publish", "python", "remove",
            "sync", "tool", "tree", "venv", "version",
        ],
    ),
    (
        "gem",
        &[
            "build",
            "cleanup",
            "contents",
            "dependency",
            "environment",
            "fetch",
            "info",
            "install",
            "list",
            "lock",
            "mirror",
            "outdated",
            "owner",
            "pristine",
            "push",
            "query",
            "search",
            "signin",
            "signout",
            "sources",
            "specification",
            "stale",
            "uninstall",
            "unpack",
            "update",
            "which",
            "yank",
        ],
    ),
    (
        "brew",
        &[
            "cleanup",
            "config",
            "deps",
            "desc",
            "doctor",
            "fetch",
            "info",
            "install",
            "leaves",
            "link",
            "list",
            "ls",
            "missing",
            "options",
            "outdated",
            "pin",
            "reinstall",
            "remove",
            "search",
            "tap",
            "uninstall",
            "unlink",
            "unpin",
            "untap",
            "update",
            "upgrade",
            "uses",
        ],
    ),
    (
        "apt",
        &[
            "autoclean",
            "autoremove",
            "build-dep",
            "check",
            "clean",
            "depends",
            "dist-upgrade",
            "download",
            "full-upgrade",
            "install",
            "list",
            "policy",
            "purge",
            "rdepends",
            "remove",
            "search",
            "show",
            "source",
            "update",
            "upgrade",
        ],
    ),
    // `go build -h` and its neighbours route through the toolchain's own flag
    // set, and `go generate` runs whatever the source directs. Only the text
    // verb is read here.
    ("go", &[]),
];

pub(super) fn safe_manager_segment(
    executable: &str,
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
) -> bool {
    let Some(subcommands) = manager_subcommands(executable) else {
        return false;
    };
    model.dialect == "posix"
        && segment.pipeline_index == 0
        && !segment
            .arguments
            .iter()
            .any(|argument| argument.contains(['$', '`', '\n', '\r']))
        && usage_only(
            subcommands,
            &segment
                .arguments
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        )
}

/// The subcommand table for a manager, under the spellings its own installer
/// leaves on `PATH`.
fn manager_subcommands(executable: &str) -> Option<&'static [&'static str]> {
    let name = match executable {
        "pip3" => "pip",
        "apt-get" => "apt",
        other => other,
    };
    BUILTIN_SUBCOMMANDS
        .iter()
        .find(|(manager, _)| *manager == name)
        .map(|(_, subcommands)| *subcommands)
}

/// `<manager> --help`, `<manager> help [subcommand]`, or a subcommand the
/// manager carries followed directly by a help flag.
fn usage_only(subcommands: &[&str], words: &[&str]) -> bool {
    let Some((first, rest)) = words.split_first() else {
        return false;
    };
    if matches!(*first, "--help" | "-h") {
        return rest.is_empty();
    }
    if *first == "help" {
        return rest.len() <= 2 && rest.iter().all(|word| plain_subcommand(word));
    }
    subcommands.contains(first) && matches!(rest, [flag] if matches!(*flag, "--help" | "-h"))
}

/// A word that can only name a subcommand: no option, no path, no package
/// reference and no version specifier.
fn plain_subcommand(word: &str) -> bool {
    !word.is_empty()
        && !word.starts_with('-')
        && word.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

#[cfg(test)]
#[path = "manager_usage_tests.rs"]
mod tests;
