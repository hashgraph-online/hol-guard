//! What a tool launcher already holds: `uv tool list`, `uv tool dir`,
//! `uv cache dir`, `uv python dir`, `pipx list` and `pipx environment`.
//!
//! Each of these prints a directory the launcher owns, or the tools it has
//! already installed into one. None resolves a version, contacts an index,
//! builds a distribution or runs an entry point, so none can reach the
//! network or execute a package. Agents run them to see what a machine holds
//! before they decide what to install, and a person adds nothing by
//! confirming a listing.
//!
//! Still reviewed:
//! - every installing verb, `uv tool install`, `uv tool run`, `pipx install`
//!   and `pipx run` among them, and `pipx runpip`, which hands the rest of
//!   the command to pip inside a managed environment.
//! - `pipx ensurepath`, which edits the shell profile, and `pipx uninstall`,
//!   `reinstall`, `inject` and `uninject`, which change what the listing
//!   above reports.
//! - `uv python list` and `uv python find`. uv discovers interpreters by
//!   running each candidate it finds on `PATH` and in its own directories,
//!   so these two execute a program the command never named. The listing
//!   verbs here read directory entries instead.
//! - every option outside the small sets below. Both launchers take options
//!   that move the directory a verb reads, choose an index, or name a
//!   configuration file, and an option this module does not know keeps the
//!   command in review rather than this proof guessing what it does.
//!
//! Neither launcher's configuration can turn one of these verbs into a
//! fetch: uv's `uv.toml` and `UV_` names, and pipx's `PIPX_` names, move the
//! directories a verb prints and nothing more, and printing a directory a
//! session chose is still a read. So, unlike [`super::pip_reads`], the proof
//! needs no configuration file of its own.

/// uv's global options that change nothing a listing reads. They may stand
/// before the verb, so skipping them finds the verb behind them.
const UV_GLOBAL_FLAGS: &[&str] = &[
    "--offline",
    "--no-cache",
    "--no-config",
    "--native-tls",
    "--no-progress",
    "--quiet",
    "-q",
    "--verbose",
    "-v",
];

/// pipx's global options of the same kind.
const PIPX_GLOBAL_FLAGS: &[&str] = &["--quiet", "-q", "--verbose", "-v"];

/// Options each admitted verb may carry. Every one changes only how the
/// listing prints or which of the launcher's own directories it names.
const UV_TOOL_LIST_FLAGS: &[&str] = &["--show-paths", "--show-version-specifiers", "--show-with"];
const UV_DIRECTORY_FLAGS: &[&str] = &["--bin"];
const PIPX_LIST_FLAGS: &[&str] = &["--short", "--json", "--include-injected"];

pub(super) fn safe_uv_segment(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
) -> bool {
    model.dialect == "posix" && segment.pipeline_index == 0 && safe_uv_arguments(&segment.arguments)
}

pub(super) fn safe_pipx_segment(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
) -> bool {
    model.dialect == "posix"
        && segment.pipeline_index == 0
        && safe_pipx_arguments(&segment.arguments)
}

fn safe_uv_arguments(arguments: &[String]) -> bool {
    let words: Vec<&str> = arguments.iter().map(String::as_str).collect();
    match after_global_flags(&words, UV_GLOBAL_FLAGS) {
        ["tool", "list", rest @ ..] => flags_only(rest, UV_TOOL_LIST_FLAGS),
        ["tool", "dir", rest @ ..] | ["python", "dir", rest @ ..] => {
            flags_only(rest, UV_DIRECTORY_FLAGS)
        }
        ["cache", "dir", rest @ ..] => rest.is_empty(),
        _ => false,
    }
}

fn safe_pipx_arguments(arguments: &[String]) -> bool {
    let words: Vec<&str> = arguments.iter().map(String::as_str).collect();
    match after_global_flags(&words, PIPX_GLOBAL_FLAGS) {
        ["list", rest @ ..] => flags_only(rest, PIPX_LIST_FLAGS),
        // `--value` picks one of the names the bare listing prints, so it
        // reads no further than the listing does.
        ["environment"] => true,
        ["environment", "--value", name] => environment_name(name),
        _ => false,
    }
}

/// The words a verb stands on, with the launcher's leading global flags
/// skipped. A word that is not one of them, flag or not, ends the skipping,
/// so an unknown option stays in the words the verb match above refuses.
fn after_global_flags<'a>(words: &'a [&'a str], global: &[&str]) -> &'a [&'a str] {
    let skipped = words
        .iter()
        .take_while(|word| global.contains(*word))
        .count();
    &words[skipped..]
}

fn flags_only(rest: &[&str], allowed: &[&str]) -> bool {
    rest.iter().all(|word| allowed.contains(word))
}

/// One of pipx's own `PIPX_` names: letters, digits and underscores, so the
/// value cannot carry a path or an option of its own.
fn environment_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
}

#[cfg(test)]
mod tests {
    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn listing_verbs_are_admitted() {
        for words in [
            vec!["tool", "list"],
            vec!["tool", "list", "--show-paths"],
            vec!["tool", "dir"],
            vec!["tool", "dir", "--bin"],
            vec!["cache", "dir"],
            vec!["python", "dir"],
            vec!["--offline", "tool", "list"],
            vec!["-q", "--no-config", "cache", "dir"],
        ] {
            assert!(super::safe_uv_arguments(&args(&words)), "uv {words:?}");
        }
        for words in [
            vec!["list"],
            vec!["list", "--short"],
            vec!["list", "--json", "--include-injected"],
            vec!["environment"],
            vec!["environment", "--value", "PIPX_HOME"],
            vec!["-q", "list"],
        ] {
            assert!(super::safe_pipx_arguments(&args(&words)), "pipx {words:?}");
        }
    }

    #[test]
    fn installing_and_executing_verbs_are_refused() {
        for words in [
            vec!["tool", "install", "ruff"],
            vec!["tool", "run", "ruff"],
            vec!["tool", "upgrade", "--all"],
            vec!["tool", "uninstall", "ruff"],
            // uv runs each candidate interpreter to answer these.
            vec!["python", "list"],
            vec!["python", "find"],
            vec!["python", "install", "3.12"],
            vec!["cache", "clean"],
            vec!["cache", "prune"],
            vec![],
        ] {
            assert!(!super::safe_uv_arguments(&args(&words)), "uv {words:?}");
        }
        for words in [
            vec!["run", "ruff"],
            vec!["install", "ruff"],
            vec!["runpip", "ruff", "list"],
            vec!["ensurepath"],
            vec!["inject", "ruff", "requests"],
            vec!["uninstall", "ruff"],
            vec![],
        ] {
            assert!(!super::safe_pipx_arguments(&args(&words)), "pipx {words:?}");
        }
    }

    #[test]
    fn options_outside_the_listing_sets_are_refused() {
        for words in [
            // Each of these moves a directory, chooses an index or names a
            // file the listing would otherwise never read.
            vec!["--directory", "/tmp", "tool", "list"],
            vec!["--config-file", "/tmp/uv.toml", "cache", "dir"],
            vec!["tool", "list", "--python", "/tmp/python"],
            vec!["tool", "dir", "--show-paths"],
            vec!["cache", "dir", "--bin"],
        ] {
            assert!(!super::safe_uv_arguments(&args(&words)), "uv {words:?}");
        }
        for words in [
            vec!["--global", "list"],
            vec!["list", "--verbose", "--pip-args", "-q"],
            vec!["environment", "--value", "PIPX_HOME", "extra"],
            vec!["environment", "--value", "../escape"],
            vec!["environment", "--value", ""],
        ] {
            assert!(!super::safe_pipx_arguments(&args(&words)), "pipx {words:?}");
        }
    }
}
