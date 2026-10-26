//! Read-only Homebrew status queries.
//!
//! `brew list`, `brew info`, `brew desc`, `brew deps`, `brew uses --installed`,
//! `brew leaves`, `brew --prefix`, `brew --cellar`, `brew --version` and
//! `brew services list|info` print what is installed or what a formula
//! declares. None installs, upgrades, taps, links, cleans up, starts a service
//! or runs `brew update`. `brew info` may fetch formula metadata from the
//! Homebrew API, which it verifies and only prints.
//!
//! None of these reads the working directory: Homebrew's configuration lives
//! in its prefix and in the home directory, so writing it is itself a
//! reviewed action. Like `DOCKER_HOST`, inherited `HOMEBREW_*` variables are
//! host trust inputs; an environment prefix in the command keeps the review
//! through the generic segment checks.
//!
//! Still reviewed:
//! - every other subcommand, including `config` and `doctor` (which print the
//!   host environment), `outdated`, `update`, `upgrade`, `install`, `tap`,
//!   `link`, `cleanup`, `bundle` (which reads a workspace `Brewfile`), `sh`,
//!   `ruby`, `irb`, `exec`, and external `brew-<name>` commands.
//! - `services start|stop|restart|run|kill|cleanup`.
//! - any option not listed below, such as `info --github` (opens a browser),
//!   `deps --graph`, and `--eval-all` (evaluates every tap formula).
//! - operands that name a path, URL, tap or Ruby file: Homebrew loads a
//!   `.rb` path or a tap-qualified name as formula code, and may tap a
//!   missing tap first.

/// Options every allowed query accepts.
const OUTPUT_FLAGS: &[&str] = &["--quiet", "-q", "--verbose", "-v"];

/// Restricts a query to formulae or casks.
const KIND_FLAGS: &[&str] = &["--formula", "--formulae", "--cask", "--casks"];

const LIST_FLAGS: &[&str] = &[
    "--versions",
    "--full-name",
    "--pinned",
    "--multiple",
    "--installed-on-request",
    "--installed-as-dependency",
    "--poured-from-bottle",
    "--built-from-source",
    "-1",
    "-l",
    "-r",
    "-t",
];

const INFO_FLAGS: &[&str] = &["--json", "--json=v1", "--json=v2", "--installed"];

const DEPS_FLAGS: &[&str] = &[
    "--tree",
    "--installed",
    "--direct",
    "-1",
    "-n",
    "--topological",
    "--union",
    "--full-name",
    "--for-each",
    "--annotate",
    "--missing",
    "--include-build",
    "--include-test",
    "--include-optional",
    "--include-requirements",
    "--skip-recommended",
];

const USES_FLAGS: &[&str] = &[
    "--installed",
    "--recursive",
    "--missing",
    "--include-build",
    "--include-test",
    "--include-optional",
    "--skip-recommended",
];

const LEAVES_FLAGS: &[&str] = &[
    "--installed-on-request",
    "--installed-as-dependency",
    "-r",
    "-p",
];

const SERVICES_LIST_FLAGS: &[&str] = &["--json"];

const SERVICES_INFO_FLAGS: &[&str] = &["--json", "--all"];

pub(super) fn safe_brew_segment(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
) -> bool {
    model.dialect == "posix"
        && segment.pipeline_index == 0
        && safe_brew_arguments(&segment.arguments)
}

pub(super) fn safe_brew_arguments(arguments: &[String]) -> bool {
    let words: Vec<&str> = arguments.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["--version"] | ["--cellar"] => true,
        ["--prefix" | "--cellar", rest @ ..] => query(rest, &[], true),
        ["list" | "ls", rest @ ..] => query(rest, &[LIST_FLAGS, KIND_FLAGS], true),
        ["info" | "abv", rest @ ..] => query(rest, &[INFO_FLAGS, KIND_FLAGS], true),
        ["desc", rest @ ..] => query(rest, &[KIND_FLAGS], true) && names(rest) > 0,
        // Without a name or `--installed`, `deps` evaluates every available
        // formula and cask, tap definitions included.
        ["deps", rest @ ..] => {
            query(rest, &[DEPS_FLAGS, KIND_FLAGS], true)
                && (names(rest) > 0 || rest.contains(&"--installed"))
        }
        // Without `--installed`, `uses` evaluates every available formula.
        ["uses", rest @ ..] => rest.contains(&"--installed") && query(rest, &[USES_FLAGS], true),
        ["leaves", rest @ ..] => query(rest, &[LEAVES_FLAGS], false),
        ["services", "list", rest @ ..] => query(rest, &[SERVICES_LIST_FLAGS], false),
        ["services", "info", rest @ ..] => {
            query(rest, &[SERVICES_INFO_FLAGS], true)
                && (names(rest) > 0 || rest.contains(&"--all"))
        }
        _ => false,
    }
}

/// Every word is an allowed option, or a plain name when `operands` is set.
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

/// A formula or cask name such as `wget`, `postgresql@16` or `python@3.12`.
/// A `/` would name a tap or path, a `:` a URL, and a `.rb` or `.json`
/// suffix a local file Homebrew loads as a package definition.
fn plain_name(word: &str) -> bool {
    let lowered = word.to_ascii_lowercase();
    word.len() <= 128
        && word
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_alphanumeric())
        && word.chars().all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || "+-_.@".contains(character)
        })
        && !lowered.ends_with(".rb")
        && !lowered.ends_with(".json")
        && !word.contains("..")
}

#[cfg(test)]
mod tests {
    use super::safe_brew_arguments;

    fn safe(command: &str) -> bool {
        let arguments: Vec<String> = command.split_whitespace().map(str::to_owned).collect();
        safe_brew_arguments(&arguments)
    }

    #[test]
    fn status_queries_are_read_only() {
        for command in [
            "list",
            "ls --versions",
            "list --formula -1",
            "list --cask",
            "list --versions postgresql@16 node",
            "services list",
            "services list --json",
            "services info postgresql@16",
            "services info --all --json",
            "info wget",
            "info --json=v2 --installed",
            "desc wget python@3.12",
            "--prefix",
            "--prefix postgresql@16",
            "--cellar",
            "--version",
            "deps --tree --installed wget",
            "uses --installed openssl@3",
            "leaves",
            "leaves -r",
        ] {
            assert!(safe(command), "brew {command}");
        }
    }

    #[test]
    fn changes_and_environment_dumps_stay_reviewed() {
        for command in [
            "",
            "config",
            "doctor",
            "outdated",
            "update",
            "upgrade",
            "install wget",
            "uninstall wget",
            "tap acme/tools",
            "untap acme/tools",
            "link wget",
            "cleanup",
            "bundle",
            "bundle check",
            "sh",
            "ruby -e 1",
            "irb",
            "exec env",
            "services",
            "services start postgresql@16",
            "services stop postgresql@16",
            "services restart postgresql@16",
            "services run postgresql@16",
            "services cleanup",
            "services info",
            "services list --debug",
            "info --github wget",
            "info --eval-all",
            "info ./formula.rb",
            "info formula.rb",
            "info acme/tools/widget",
            "info https://example.invalid/widget.rb",
            "deps --graph wget",
            "uses openssl@3",
            "desc",
            "list --versions $(id)",
            "--version --debug",
            "--repository",
        ] {
            assert!(!safe(command), "brew {command}");
        }
    }
}
