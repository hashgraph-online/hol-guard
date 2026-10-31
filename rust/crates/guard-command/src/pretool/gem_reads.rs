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
//! - `gem specification <gem> <field>` for any field outside
//!   [`SPECIFICATION_FIELDS`]: RubyGems answers that word with `send`, so it
//!   names a method on the specification rather than data.
//! - every option that carries a value: `--source`, `--http-proxy`,
//!   `--bulk-threshold`, `--config-file`, `--spec-dir`, `--platform` and the
//!   version requirement. A screen that admitted them would have to tell a
//!   requirement from a path, a URL or a second source.
//! - operands that are not a plain gem name, so a path, a `.gem` or
//!   `.gemspec` file and a URL all keep their review.
//! - every query a session could have pointed elsewhere before it ran.
//!   `gem` is a Ruby program that loads a configuration first, so an
//!   inherited `GEMRC`, `RUBYOPT`, `RUBYLIB` or `RUBYGEMS_GEMDEPS`, and a
//!   `gemrc` carrying anything but the switches [`INERT_DEFAULT_ARGUMENTS`]
//!   lists, leave the query reviewed: both can put back the `--source`,
//!   `--config-file` and `-u` this module refuses on the line, and `RUBYOPT`
//!   can require a file before the query starts.

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

/// The specification attributes a query may name.
///
/// Each reads a field the gemspec declares. Methods that act -- building an
/// extension, activating the gem, writing a cache file -- are absent, as are
/// the ones that re-render the whole specification, which is what the
/// `--ruby`, `--yaml` and `--marshal` flags already print.
const SPECIFICATION_FIELDS: &[&str] = &[
    "authors",
    "bindir",
    "date",
    "dependencies",
    "description",
    "development_dependencies",
    "email",
    "executables",
    "extensions",
    "extra_rdoc_files",
    "files",
    "full_name",
    "homepage",
    "licenses",
    "metadata",
    "name",
    "platform",
    "require_paths",
    "required_ruby_version",
    "required_rubygems_version",
    "requirements",
    "rubygems_version",
    "runtime_dependencies",
    "specification_version",
    "summary",
    "test_files",
    "version",
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
    context: super::PathContext<'_>,
) -> bool {
    model.dialect == "posix"
        && segment.pipeline_index == 0
        && safe_gem_arguments(&segment.arguments)
        && context.gem_config_absent
        && context.shell_home_matches
        && configuration_inert(context)
}

/// Whether the `gemrc` files RubyGems loads leave the query as it was
/// written.
///
/// RubyGems reads `/etc/gemrc` and then the user's `~/.gemrc`, and both
/// carry the same two kinds of entry: settings such as `:sources:` and
/// `:update_sources:`, and a list of default arguments under `gem:` or under
/// a command's own name, which RubyGems adds to the line before its parser
/// sees it. Those defaults put back exactly what this module refuses --
/// `--source`, `--config-file`, `-u` -- so a file that carries anything but
/// the words below leaves the query reviewed. There is no per-directory
/// `gemrc`, so only these two paths are read, and the home is the one the
/// shell would expand.
fn configuration_inert(context: super::PathContext<'_>) -> bool {
    let Some(home) = context.home_dir.map(std::path::Path::new) else {
        return false;
    };
    home.is_absolute()
        && gemrc_inert(&home.join(".gemrc"))
        && gemrc_inert(std::path::Path::new("/etc/gemrc"))
}

/// The longest `gemrc` this screen reads.
const MAX_GEMRC_BYTES: u64 = 64 * 1024;

/// A missing file is inert. Anything unreadable, oversized or not a regular
/// file is not.
fn gemrc_inert(path: &std::path::Path) -> bool {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        // A path whose parent is not a directory reports `ENOTDIR` rather
        // than "no such file", and RubyGems reads nothing there either.
        Err(error) => {
            return matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            )
        }
    };
    if !metadata.is_file() || metadata.len() > MAX_GEMRC_BYTES {
        return false;
    }
    std::fs::read_to_string(path).is_ok_and(|text| text.lines().all(inert_gemrc_line))
}

/// Settings whose value says how much a command prints or how many
/// connections it opens, and nothing about where it reads from or writes to.
const INERT_SETTINGS: &[&str] = &["backtrace", "benchmark", "bulk_threshold", "verbose"];

/// The default arguments a `gemrc` may carry.
///
/// Each one is a flag that takes no value, so none of them can name a
/// source, a file or a directory, and none asks for the source-cache write
/// `--update-sources` performs.
const INERT_DEFAULT_ARGUMENTS: &[&str] = &[
    "--backtrace",
    "--document",
    "--no-document",
    "--no-rdoc",
    "--no-ri",
    "--norc",
    "--no-suggestions",
    "--suggestions",
    "--no-user-install",
    "--no-verbose",
    "--quiet",
    "--silent",
    "--user-install",
    "--verbose",
    "-V",
    "-q",
];

/// One line of a `gemrc`.
///
/// A key written as a Ruby symbol (`:verbose:`) and one written plainly
/// (`gem:`) reach the same reading. An indented line belongs to a structure
/// this screen did not read -- the items under `:sources:`, a nested mapping
/// -- so it keeps the review, and so does any value that is not a listed
/// scalar or a list of listed flags.
fn inert_gemrc_line(line: &str) -> bool {
    let trimmed = line.trim_end();
    let body = trimmed.trim_start();
    if body.is_empty() || body.starts_with('#') || body == "---" {
        return true;
    }
    if trimmed.starts_with([' ', '\t']) {
        return false;
    }
    let Some((key, value)) = body.strip_prefix(':').unwrap_or(body).split_once(':') else {
        return false;
    };
    let value = value.trim();
    if INERT_SETTINGS.contains(&key.trim().to_ascii_lowercase().as_str()) {
        return inert_setting_value(value);
    }
    !value.is_empty()
        && value
            .split_whitespace()
            .all(|word| INERT_DEFAULT_ARGUMENTS.contains(&word))
}

/// A setting's value is read only where it is a plain switch or a count. A
/// key whose value names anything else is not one this screen knows.
fn inert_setting_value(value: &str) -> bool {
    matches!(value, "true" | "false" | "nil" | "~")
        || (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
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
            query(rest, &[SPECIFICATION_FLAGS, DOMAIN_FLAGS], true) && specification_operands(rest)
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

/// `gem specification <gem> [field]`.
///
/// RubyGems answers the optional second operand with `send` on the
/// specification object, so that word is a method name rather than data, and
/// a specification carries more than its fields: `build_extensions` compiles
/// and runs the gem's own `extconf.rb`. Only the attributes that read a field
/// are accepted, and only one gem name before them.
fn specification_operands(words: &[&str]) -> bool {
    let operands = words
        .iter()
        .copied()
        .filter(|word| plain_name(word))
        .collect::<Vec<_>>();
    match operands.as_slice() {
        [_] => true,
        [_, field] => SPECIFICATION_FIELDS.contains(field),
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
