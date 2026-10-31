//! Read-only RubyGems queries.
//!
//! `gem list`, `gem search`, `gem info`, `gem which`, `gem contents`,
//! `gem dependency`, `gem specification`, `gem outdated`, `gem environment`
//! and `gem sources --list` print what is installed, what the index carries
//! and where RubyGems keeps it. None of them installs, uninstalls, builds,
//! pushes, yanks or unpacks a gem, and none writes outside what it prints.
//! Looking a gem up is the step before deciding whether to install it, and
//! sending the question to review teaches nothing about the install that may
//! follow.
//!
//! The remote domain is part of the reading. `gem search -r rails` asks the
//! index the same question `npm search` asks its registry, and like that read
//! it fetches and prints without writing a lockfile or a cache entry the
//! command never named.
//!
//! Still reviewed:
//! - every other subcommand: `install`, `update`, `uninstall`, `cleanup`,
//!   `pristine`, `build`, `push`, `yank`, `owner`, `fetch`, `unpack`,
//!   `mirror`, `signin`, `signout`, `open` (which starts an editor),
//!   `exec` (which installs what it runs) and `generate_index`.
//! - `sources` with anything but `--list`: `--add`, `--remove`, `--clear-all`
//!   and `--update` all rewrite the configured sources, and `-r` spells
//!   `--remove` here while it spells `--remote` everywhere else.
//! - `-u`/`--update-sources` and `--clear-sources`, which rewrite the local
//!   source cache on a command that otherwise only prints.
//! - every option that carries a value: `--source`, `--http-proxy`,
//!   `--bulk-threshold`, `--config-file`, `--spec-dir`, `--platform` and the
//!   version requirement. A screen that admitted them would have to tell a
//!   requirement from a path, a URL or a second source.
//! - operands that are not a plain gem name, so a path, a `.gem` or
//!   `.gemspec` file and a URL all keep their review.

/// Options every allowed query accepts.
const OUTPUT_FLAGS: &[&str] = &[
    "--quiet",
    "-q",
    "--silent",
    "--verbose",
    "--no-verbose",
    "-V",
    "--norc",
];

/// Picks the local gems, the index, or both.
const DOMAIN_FLAGS: &[&str] = &["--local", "-l", "--remote", "-r", "--both", "-b"];

/// Shared by the three verbs that answer "which versions carry this name".
const QUERY_FLAGS: &[&str] = &[
    "--installed",
    "--no-installed",
    "-i",
    "-I",
    "--versions",
    "--no-versions",
    "--all",
    "-a",
    "--exact",
    "-e",
    "--prerelease",
    "--no-prerelease",
];

const DETAIL_FLAGS: &[&str] = &["--details", "--no-details", "-d"];

const WHICH_FLAGS: &[&str] = &[
    "--all",
    "--no-all",
    "-a",
    "--gems-first",
    "--no-gems-first",
    "-g",
];

const CONTENTS_FLAGS: &[&str] = &[
    "--all",
    "--lib-only",
    "--no-lib-only",
    "-l",
    "--prefix",
    "--no-prefix",
    "--show-install-dir",
    "--no-show-install-dir",
];

const DEPENDENCY_FLAGS: &[&str] = &[
    "--prerelease",
    "--no-prerelease",
    "--reverse-dependencies",
    "--no-reverse-dependencies",
    "-R",
    "--pipe",
];

const SPECIFICATION_FLAGS: &[&str] = &[
    "--all",
    "--ruby",
    "--yaml",
    "--marshal",
    "--prerelease",
    "--no-prerelease",
];

/// The names `gem environment` prints one value for.
const ENVIRONMENT_KEYS: &[&str] = &[
    "gemdir",
    "gempath",
    "home",
    "path",
    "platform",
    "packageversion",
    "remotesources",
    "user_gemhome",
    "version",
];

pub(super) fn safe_gem_segment(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
) -> bool {
    model.dialect == "posix"
        && segment.pipeline_index == 0
        && safe_gem_arguments(&segment.arguments)
}

pub(super) fn safe_gem_arguments(arguments: &[String]) -> bool {
    let words: Vec<&str> = arguments.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["list" | "search" | "query", rest @ ..] => {
            query(rest, &[QUERY_FLAGS, DETAIL_FLAGS, DOMAIN_FLAGS], true)
        }
        ["info", rest @ ..] => query(rest, &[QUERY_FLAGS, DOMAIN_FLAGS], true),
        ["which", rest @ ..] => query(rest, &[WHICH_FLAGS], true) && names(rest) > 0,
        ["contents", rest @ ..] => {
            query(rest, &[CONTENTS_FLAGS], true) && (names(rest) > 0 || rest.contains(&"--all"))
        }
        ["dependency", rest @ ..] => query(rest, &[DEPENDENCY_FLAGS, DOMAIN_FLAGS], true),
        ["specification", rest @ ..] => {
            query(rest, &[SPECIFICATION_FLAGS, DOMAIN_FLAGS], true) && names(rest) > 0
        }
        ["outdated", rest @ ..] => query(rest, &[DOMAIN_FLAGS], false),
        ["environment", rest @ ..] => match rest {
            [] => true,
            [key] => ENVIRONMENT_KEYS.contains(key),
            _ => false,
        },
        ["sources", rest @ ..] => rest
            .iter()
            .all(|word| OUTPUT_FLAGS.contains(word) || matches!(*word, "--list" | "-l")),
        _ => false,
    }
}

/// Every word is an allowed option, or a plain gem name when `operands` is set.
fn query(words: &[&str], flag_sets: &[&[&str]], operands: bool) -> bool {
    words.iter().all(|word| {
        OUTPUT_FLAGS.contains(word)
            || flag_sets.iter().any(|flags| flags.contains(word))
            || (operands && plain_name(word))
    })
}

fn names(words: &[&str]) -> usize {
    words.iter().filter(|word| plain_name(word)).count()
}

/// A gem name such as `rake`, `RedCloth` or `net-http-persistent`.
///
/// A `/` would name a path, a `:` a URL, and a `.gem` or `.gemspec` suffix a
/// local file RubyGems reads as a package rather than a name.
fn plain_name(word: &str) -> bool {
    let lowered = word.to_ascii_lowercase();
    word.len() <= 128
        && word
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_alphanumeric())
        && word
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_.".contains(character))
        && !lowered.ends_with(".gem")
        && !lowered.ends_with(".gemspec")
        && !word.contains("..")
}

#[cfg(test)]
#[path = "gem_reads_tests.rs"]
mod tests;
