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
//! write are rejected with the rest of pip's environment. `XDG_CONFIG_HOME`
//! is the exception: it moves the *user* file, the stamp carries the
//! directory it names, so [`redirected_configuration_inert`] reads the
//! `pip.conf` there and the proof covers the file pip itself would read. A
//! session that exports it — every Linux agent that follows the base
//! directory specification — keeps its listings quiet instead of losing them
//! all to review. See [`super::npm_reads`] for the same proof over `.npmrc`.

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

// pip's user site lives under the home directory, so a read of it answers
// for whichever home the command runs with.
const USER_SCOPE_FLAG: &str = "--user";
/// Which installed distributions a listing covers.
const SCOPE_FLAGS: &[&str] = &["--local", "-l", USER_SCOPE_FLAG];

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

/// Report that a redirected user configuration directory adds no option.
///
/// `XDG_CONFIG_HOME` moves the file platformdirs hands pip out of the
/// directories [`configuration_inert`] reads, so the proof follows it to the
/// `pip.conf` the command would actually read. The redirect is provable only
/// when the stamp carries an absolute directory for it: a session that
/// exports the name without a stamped value, or with a relative one the proof
/// cannot resolve, leaves the listing reviewed.
pub(super) fn redirected_configuration_inert(directory: Option<&str>, exported: bool) -> bool {
    match directory {
        Some(directory) => {
            let directory = Path::new(directory);
            directory.is_absolute() && pip_conf_inert(&directory.join("pip").join("pip.conf"))
        }
        None => !exported,
    }
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
///
/// The value does not matter, because a key is listed here only when both of
/// its values leave the command doing what it would do with no file at all.
/// `disable-pip-version-check = false` is pip's own default, so reading it
/// reviews a machine that writes the default down while admitting the machine
/// that leaves it out, and both run the same command. A key whose value could
/// add work the command did not ask for belongs outside this list instead.
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
    safe_pip_words(&words)
}

/// The same reading surface, for a caller that already holds the words. `uv
/// pip` puts pip's subcommands in front of the project environment, so one
/// allowlist decides both spellings.
pub(super) fn safe_pip_words(words: &[&str]) -> bool {
    let (command, rest) = match split_subcommand(words) {
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

/// Whether the read stays inside the environment the command names.
///
/// A contained run is given the workspace as its `HOME`, so a read that
/// resolves out of the home directory reports the sandbox's own layout
/// instead of the developer's: the cache lives under `~/.cache`, and the
/// user site under `~/.local`. A listing of the wrong environment is a worse
/// answer than the review it replaces, so those two forms keep the review
/// they have today, where they run against the real home. Everything else a
/// query reads is the environment's own metadata, which the interpreter
/// finds from its own prefix.
pub(super) fn environment_read_words(words: &[&str]) -> bool {
    safe_pip_words(words)
        && !matches!(split_subcommand(words), Some((Some("cache"), _)))
        && !words.contains(&USER_SCOPE_FLAG)
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

const XDG_CONFIG_HOME_NAME: &str = "XDG_CONFIG_HOME";

/// Whether nothing outside the command line can add an option to the listing.
///
/// A stamped environment carries the names the session exported and the
/// directory `XDG_CONFIG_HOME` names; without one the runtime's own
/// environment is the session's. Either way a variable pip reads keeps the
/// command out, and a redirected configuration directory is read where pip
/// would read it.
pub(super) fn environment_configuration_inert(
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    match execution_environment {
        Some(environment) => {
            environment.has_valid_shape()
                && !environment
                    .environment_names
                    .iter()
                    .any(|name| pip_selector(name))
                && redirected_configuration_inert(
                    environment.xdg_config_home.as_deref(),
                    environment
                        .environment_names
                        .iter()
                        .any(|name| name.eq_ignore_ascii_case(XDG_CONFIG_HOME_NAME)),
                )
        }
        None => {
            !std::env::vars_os()
                .any(|(name, value)| !value.is_empty() && pip_selector(&name.to_string_lossy()))
                && exported_configuration_inert(std::env::var_os(XDG_CONFIG_HOME_NAME).as_deref())
        }
    }
}

/// Whether the session's own `XDG_CONFIG_HOME` leaves pip's file where it is.
///
/// A value this runtime cannot read as text still moves the file pip reads,
/// so the export is taken as an `OsStr` and only its text is read on: a
/// redirect whose directory cannot be read is never inert.
fn exported_configuration_inert(exported: Option<&std::ffi::OsStr>) -> bool {
    let exported = exported.filter(|value| !value.is_empty());
    redirected_configuration_inert(
        exported.and_then(|value| value.to_str()),
        exported.is_some(),
    )
}

/// Variables pip reads before any option on the command line, beyond the ones
/// that only change how it prints.
///
/// pip asks platformdirs where its user and global configuration files live,
/// so the names platformdirs resolves those directories from move a
/// `pip.conf` out of the directories the file check reads: the config names
/// on Linux, and the data names on macOS, where a configuration directory is
/// a data directory. `XDG_CONFIG_HOME` is not among them, because the stamp
/// carries the directory it names and
/// [`redirected_configuration_inert`] reads the `pip.conf`
/// there, which is the file pip itself would read. The remaining `XDG_`
/// names, `XDG_RUNTIME_DIR` among them, name no directory pip reads
/// configuration from.
fn pip_selector(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    if matches!(
        upper.as_str(),
        "XDG_CONFIG_DIRS" | "XDG_DATA_HOME" | "XDG_DATA_DIRS"
    ) {
        return true;
    }
    upper.starts_with("PIP_")
        && !matches!(
            upper.as_str(),
            "PIP_DISABLE_PIP_VERSION_CHECK"
                | "PIP_REQUIRE_VIRTUALENV"
                | "PIP_NO_COLOR"
                | "PIP_NO_INPUT"
                | "PIP_QUIET"
                | "PIP_VERBOSE"
        )
}

#[cfg(test)]
mod tests {
    use super::{inert_line, safe_pip_arguments};

    fn safe(command: &str) -> bool {
        let arguments: Vec<String> = command.split_whitespace().map(str::to_owned).collect();
        safe_pip_arguments(&arguments)
    }

    #[test]
    fn a_printing_key_is_inert_whichever_value_it_carries() {
        for line in [
            "",
            "   ",
            "# a comment",
            "; a comment",
            "[list]",
            "disable-pip-version-check = false",
            "disable-pip-version-check = true",
            "disable_pip_version_check: no",
            "require-virtualenv = false",
            "format = freeze",
        ] {
            assert!(inert_line(line), "{line}");
        }
    }

    #[test]
    fn a_key_that_adds_work_the_command_did_not_ask_for_is_not_inert() {
        for line in [
            "index-url = https://example.invalid/simple",
            "extra-index-url = https://example.invalid/simple",
            "target = /tmp/elsewhere",
            "cache-dir = /tmp/elsewhere",
            "retries = 20",
        ] {
            assert!(!inert_line(line), "{line}");
        }
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

#[cfg(test)]
mod configuration_tests {
    use super::exported_configuration_inert;
    use std::ffi::OsStr;

    #[test]
    fn no_redirect_leaves_pips_file_where_the_check_reads_it() {
        assert!(exported_configuration_inert(None));
        assert!(exported_configuration_inert(Some(OsStr::new(""))));
    }

    #[test]
    fn a_redirect_the_check_cannot_follow_keeps_the_review() {
        assert!(!exported_configuration_inert(Some(OsStr::new(
            "relative/config"
        ))));
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            // A directory name this runtime cannot read as text still names a
            // `pip.conf` the command would read, so it is not proved inert.
            assert!(!exported_configuration_inert(Some(OsStr::from_bytes(
                b"/tmp/\xff"
            ))));
        }
    }
}
