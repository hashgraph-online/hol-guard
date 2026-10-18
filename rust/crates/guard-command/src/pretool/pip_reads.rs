//! Read-only pip queries: `pip list`, `pip show`, `pip freeze`, `pip check`,
//! `pip cache dir|info|list` and `pip --version`.
//!
//! Each of these reads the metadata already installed in the environment and
//! prints it. None resolves, downloads, builds or installs a distribution, so
//! none runs packaging code from the index or from a source tree. Agents run
//! them constantly to see what an environment holds before and after real
//! work, and a person adds nothing by confirming a listing.
//!
//! Still reviewed:
//! - every other subcommand, `install`, `uninstall`, `download`, `wheel` and
//!   `index` among them, and `config`, which prints index URLs that may carry
//!   credentials, and `debug`, which dumps the host environment.
//! - `list --outdated|--uptodate`, which query the configured index, and
//!   every option that chooses an index, a proxy, a certificate, a log file
//!   or another interpreter.
//! - `freeze --requirement`, which prints the contents of a file operand, and
//!   any option taking a path.
//! - `cache purge|remove`, which delete cached wheels.
//!
//! pip reads its configuration before any of this, and configuration is an
//! option by another name: `PIP_<OPTION>` and a `pip.conf` key set the same
//! options the command line does, so `[list] outdated = true` turns a listing
//! into an index query and `[global] log = <path>` writes a file the command
//! never named. So the proof also needs pip's environment and the user
//! configuration file to leave the command alone.
//!
//! The site configuration beside the interpreter, and the global files under
//! `/etc` and `/Library`, are not checked: writing any of them already means
//! controlling the `pip` the command runs, which is the larger capability.
//! The `XDG_` variables that would move the global files somewhere a user can
//! write are rejected with the rest of pip's environment. See
//! [`super::npm_reads`] for the same proof over `.npmrc`.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

const MAX_PIP_CONF_BYTES: u64 = 64 * 1024;

/// Options that only change how the listing prints, accepted by every query.
const QUIET_FLAGS: &[&str] = &[
    "--disable-pip-version-check",
    "--no-color",
    "--no-input",
    "--isolated",
    "--require-virtualenv",
    "--quiet",
    "-q",
    "--verbose",
    "-v",
];

/// Which installed distributions a listing covers.
const SCOPE_FLAGS: &[&str] = &["--local", "-l", "--user"];

const LIST_FLAGS: &[&str] = &["--not-required", "--editable", "-e", "--include-editable"];

const FREEZE_FLAGS: &[&str] = &["--all", "--exclude-editable"];

const SHOW_FLAGS: &[&str] = &["--files", "-f"];

const LIST_FORMATS: &[&str] = &["columns", "freeze", "json"];

const CACHE_FORMATS: &[&str] = &["human", "abspath"];

pub(super) fn safe_pip_segment(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    context: super::PathContext<'_>,
) -> bool {
    model.dialect == "posix"
        && segment.pipeline_index == 0
        && safe_pip_arguments(&segment.arguments)
        // pip finds the user configuration through its own HOME, so the one
        // checked below must be that HOME.
        && context.pip_config_inert
        && context.shell_home_matches
        && configuration_inert(context)
}

/// pip reads the legacy `~/.pip/pip.conf` and the file under whichever
/// configuration directory platformdirs hands the running interpreter:
/// `~/.config/pip/pip.conf` on Linux, `~/Library/Application Support/pip/
/// pip.conf` on macOS. Both are checked on every platform, since the proof
/// cannot see which interpreter the command reaches. The `XDG_` names that
/// move them are already part of [`super::PathContext::pip_config_inert`].
fn configuration_inert(context: super::PathContext<'_>) -> bool {
    let Some(home) = context.home_dir.map(Path::new) else {
        return false;
    };
    home.is_absolute()
        && [
            home.join(".config").join("pip").join("pip.conf"),
            home.join(".pip").join("pip.conf"),
            home.join("Library")
                .join("Application Support")
                .join("pip")
                .join("pip.conf"),
        ]
        .iter()
        .all(|path| pip_conf_inert(path))
}

/// A missing file is inert. Anything unreadable, oversized or not a regular
/// file is not.
fn pip_conf_inert(path: &Path) -> bool {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => return error.kind() == ErrorKind::NotFound,
    };
    if !metadata.is_file() || metadata.len() > MAX_PIP_CONF_BYTES {
        return false;
    }
    fs::read_to_string(path).is_ok_and(|text| text.lines().all(inert_line))
}

/// Keys that only change how pip prints. Every other key is an option the
/// command did not ask for, so the command goes back to review rather than
/// this check guessing what the option does.
const INERT_KEYS: &[&str] = &[
    "disable-pip-version-check",
    "require-virtualenv",
    "no-color",
    "no-input",
    "quiet",
    "verbose",
    "format",
    "progress-bar",
];

fn inert_line(line: &str) -> bool {
    let line = line.trim();
    if line.is_empty() || line.starts_with(['#', ';']) || line.starts_with('[') {
        return true;
    }
    let key = line
        .split(['=', ':'])
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .replace('_', "-");
    INERT_KEYS.contains(&key.as_str())
}

pub(super) fn safe_pip_arguments(arguments: &[String]) -> bool {
    let words: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let (command, rest) = match split_subcommand(&words) {
        Some(split) => split,
        None => return false,
    };
    match command {
        // `pip --version` and `pip -V` print pip's own version and path.
        None => true,
        Some("list") => query(
            rest,
            &[SCOPE_FLAGS, LIST_FLAGS],
            &[("--format", LIST_FORMATS)],
            0,
        ),
        Some("freeze") => query(rest, &[SCOPE_FLAGS, FREEZE_FLAGS], &[("--exclude", &[])], 0),
        Some("show") => query(rest, &[SHOW_FLAGS], &[], usize::MAX) && names(rest) > 0,
        Some("check") => rest.is_empty(),
        Some("cache") => cache_query(rest),
        _ => false,
    }
}

/// Splits the leading quiet options off, then the subcommand. `--version`
/// stands in for a subcommand and takes nothing after it.
fn split_subcommand<'a>(words: &'a [&'a str]) -> Option<(Option<&'a str>, &'a [&'a str])> {
    let mut index = 0;
    while words
        .get(index)
        .is_some_and(|word| QUIET_FLAGS.contains(word))
    {
        index += 1;
    }
    match words.get(index) {
        Some(&"--version" | &"-V") => words[index + 1..]
            .iter()
            .all(|word| QUIET_FLAGS.contains(word))
            .then_some((None, &[][..])),
        Some(word) => Some((Some(*word), &words[index + 1..])),
        None => None,
    }
}

/// Every word is an allowed option, an allowed `--option value` pair, or one
/// of at most `operands` plain distribution names.
fn query(
    words: &[&str],
    flag_sets: &[&[&str]],
    valued: &[(&str, &[&str])],
    operands: usize,
) -> bool {
    let mut seen = 0;
    let mut index = 0;
    while let Some(word) = words.get(index) {
        index += 1;
        if QUIET_FLAGS.contains(word) || flag_sets.iter().any(|flags| flags.contains(word)) {
            continue;
        }
        let (name, inline) = match word.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (*word, None),
        };
        if let Some((_, values)) = valued.iter().find(|(option, _)| *option == name) {
            let value = match inline {
                Some(value) => value,
                None => match words.get(index) {
                    Some(value) => {
                        index += 1;
                        value
                    }
                    None => return false,
                },
            };
            // An empty value set means any plain distribution name.
            if values.is_empty() {
                if !plain_name(value) {
                    return false;
                }
            } else if !values.contains(&value) {
                return false;
            }
            continue;
        }
        if inline.is_some() || !plain_name(word) || seen >= operands {
            return false;
        }
        seen += 1;
    }
    true
}

/// `pip cache dir|info|list`; `purge` and `remove` delete cached files.
fn cache_query(words: &[&str]) -> bool {
    match words.split_first() {
        Some((&"dir" | &"info", rest)) => rest.iter().all(|word| QUIET_FLAGS.contains(word)),
        Some((&"list", rest)) => query(rest, &[], &[("--format", CACHE_FORMATS)], usize::MAX),
        _ => false,
    }
}

fn names(words: &[&str]) -> usize {
    words.iter().filter(|word| plain_name(word)).count()
}

/// A distribution name such as `requests`, `ruamel.yaml` or `zope-interface`.
/// Version specifiers, extras, paths and URLs all need a character outside
/// this set, so none of them reaches a query.
fn plain_name(word: &str) -> bool {
    word.len() <= 128
        && word
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_alphanumeric())
        && word
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_.".contains(character))
        && !word.contains("..")
}

#[cfg(test)]
mod tests {
    use super::safe_pip_arguments;

    fn safe(command: &str) -> bool {
        let arguments: Vec<String> = command.split_whitespace().map(str::to_owned).collect();
        safe_pip_arguments(&arguments)
    }

    #[test]
    fn installed_metadata_queries_are_read_only() {
        for command in [
            "list",
            "list --format=json",
            "list --format json",
            "list --format=freeze",
            "list --local",
            "list -l --not-required",
            "list --user --disable-pip-version-check",
            "--quiet list",
            "freeze",
            "freeze --local",
            "freeze --all --exclude-editable",
            "freeze --exclude setuptools",
            "freeze --exclude=setuptools",
            "show requests",
            "show -f requests",
            "show requests ruamel.yaml zope-interface",
            "check",
            "cache dir",
            "cache info",
            "cache list",
            "cache list requests",
            "cache list --format=abspath",
            "--version",
            "-V",
        ] {
            assert!(safe(command), "pip {command}");
        }
    }

    #[test]
    fn index_queries_and_changes_stay_reviewed() {
        for command in [
            "",
            "install requests",
            "install -r requirements.txt",
            "uninstall requests",
            "download requests",
            "wheel .",
            "index versions requests",
            "config list",
            "config set global.index-url https://example.invalid/simple",
            "debug",
            "list --outdated",
            "list -o",
            "list --uptodate",
            "list --u",
            "list --index-url https://example.invalid/simple",
            "list --extra-index-url https://example.invalid/simple",
            "list --find-links /tmp/wheels",
            "list --path /tmp/site-packages",
            "list --trusted-host example.invalid",
            "list --format=table",
            "list --format",
            "list requests",
            "--log /tmp/pip.log list",
            "--python /tmp/python list",
            "--proxy http://example.invalid list",
            "freeze -r requirements.txt",
            "freeze --requirement requirements.txt",
            "freeze --path /tmp/site-packages",
            "freeze --exclude ../escape",
            "show",
            "show -f",
            "show ./local-dir",
            "show requests==2.31.0",
            "show 'requests[security]'",
            "check --verbose extra",
            "cache",
            "cache purge",
            "cache remove requests",
            "cache list --format=json",
            "--version install requests",
        ] {
            assert!(!safe(command), "pip {command}");
        }
    }
}
