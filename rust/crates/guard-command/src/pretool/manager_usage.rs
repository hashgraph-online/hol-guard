//! A package manager printing its own usage text.
//!
//! `npm install --help`, `pip install --help`, `brew install --help` and
//! their neighbours never install anything. The manager's own argument parser
//! sees the help flag, prints the text it carries for that subcommand and
//! exits: no registry is contacted, no lockfile is read and no project script
//! runs. Reading a manual page is the step before deciding whether to install,
//! and sending it to review teaches nothing about the install that may follow.
//!
//! Four limits keep that reading narrow.
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
//! Managers are absent on purpose when their help path loads code from the
//! project, or picks the binary to run, before it can print anything. Yarn
//! Berry resolves the plugins named in `.yarnrc.yml`, Poetry loads its
//! entry-point plugins, Composer's plugin manager loads vendor PHP to
//! discover commands, and Bundler shells out to `man`. `pnpm` is selected by
//! Corepack's `packageManager` field, `cargo` by a `rust-toolchain.toml`
//! `path` entry and `go` by a `go.mod` `toolchain` line, each of which runs a
//! workspace-supplied binary before the flag is read -- the same reason
//! [`super::help_probes`] and [`super::version_probes`] refuse them. Their
//! usage pages keep their review.
//!
//! The `help` verb is read only where it prints to stdout, and only for a
//! subcommand the table already carries. npm's `help` opens its configured
//! viewer -- `man` on Unix -- so npm answers only the flag. Every other
//! manager's `help` takes at most one word, and that word must be a listed
//! subcommand, because `brew help <tap-command>` and `gem help <plugin>` reach
//! the same program the flag reading refuses.
//!
//! npm and pip read a configuration while they are still working out what to
//! print, so this proof asks for the same files
//! [`super::help_probes::configuration_inert`] reads: a project `.npmrc`
//! `onload-script` runs during the help path, and a `pip.conf` `log` entry
//! writes a file the command never named.

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
];

pub(super) fn safe_manager_segment(
    executable: &str,
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    context: super::PathContext<'_>,
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
            executable,
            subcommands,
            &segment
                .arguments
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        )
        && super::help_probes::configuration_inert(executable, context)
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
///
/// The word after `help` is read against the same table, because an unknown
/// name is not the manager's to answer: `brew help <word>` loads a tap's
/// command and `cargo help <word>` runs a `cargo-<word>` binary. Only one
/// such word is accepted, since no manager here documents a second level.
fn usage_only(executable: &str, subcommands: &[&str], words: &[&str]) -> bool {
    let Some((first, rest)) = words.split_first() else {
        return false;
    };
    if matches!(*first, "--help" | "-h") {
        return rest.is_empty();
    }
    if *first == "help" {
        return help_verb_prints_usage(executable)
            && rest.len() <= 1
            && rest.iter().all(|word| subcommands.contains(word));
    }
    subcommands.contains(first) && matches!(rest, [flag] if matches!(*flag, "--help" | "-h"))
}

/// Whether this manager's `help` verb writes the page itself.
///
/// npm's opens the viewer named by its `viewer` setting, which is `man` on
/// Unix, so the page comes from a program the command never names. Only its
/// `--help` flag prints to stdout.
fn help_verb_prints_usage(executable: &str) -> bool {
    executable != "npm"
}

#[cfg(test)]
#[path = "manager_usage_tests.rs"]
mod tests;
