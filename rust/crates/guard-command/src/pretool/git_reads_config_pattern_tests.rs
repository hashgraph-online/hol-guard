use super::safe_git_arguments;
use crate::pretool::PathContext;

fn arguments(text: &str) -> Vec<String> {
    text.split_whitespace().map(str::to_owned).collect()
}

fn proven(text: &str) -> bool {
    safe_git_arguments(&arguments(text), true, PathContext::default())
}

/// `--get-regexp` matches its pattern against the keys in the configuration
/// file. Git never expands it over the files in the working directory, so the
/// path screen's question -- could this glob select a private file? -- has no
/// answer here, and asking it sent every pattern holding a `*` to review:
/// `remote.*url` is the spelling a read of the configured remotes uses.
///
/// The directory options are not exercised here: `PathContext::default()` has
/// no roots, so `-C <path>` is screened by the route that owns it and tested
/// beside that route.
#[test]
fn a_configuration_pattern_holding_a_star_is_not_a_glob_over_the_working_tree() {
    for text in [
        "config --get-regexp remote.*url",
        "config --get-regexp .*",
        "config --get-regexp remote*",
        "config --get-regexp remote\\..*\\.url",
        "config get --regexp remote.*url",
    ] {
        assert!(proven(text), "{text}");
    }
}

/// The spellings that already passed keep passing: the route still proves the
/// read form itself, not merely that the pattern is harmless.
#[test]
fn the_read_forms_a_configuration_name_takes_still_pass() {
    for text in [
        "config --get-regexp remote",
        "config --get-regexp ^remote\\.",
        "config --get remote.origin.url",
        "config --list",
        "config list",
        "config get user.name",
    ] {
        assert!(proven(text), "{text}");
    }
}

/// Only read forms reach the route. A write, an alternative configuration
/// source and the editor keep their own review.
#[test]
fn a_configuration_write_or_another_source_keeps_its_review() {
    for text in [
        "config --global user.name Someone",
        "config --unset remote.origin.url",
        "config --file /tmp/other/.gitconfig --list",
        "config --blob HEAD:.gitmodules --list",
        "config --edit",
        "config --get-regexp",
    ] {
        assert!(!proven(text), "{text}");
    }
}

/// Only a `--get-regexp` pattern is matched against configuration keys. Every
/// other argument is one the shell expands before Git sees it, so it keeps the
/// path screen: in a directory holding `user.name` and `value`, an unquoted
/// `git config *` reaches Git as the write `git config user.name value`, and a
/// `--default` operand can still name a private file.
#[test]
fn an_argument_the_shell_expands_keeps_the_path_screen() {
    for text in [
        "config *",
        "config get *",
        "config --get *",
        "config --get-all *",
        "config --list --default=.env",
        "config --get ~/.aws/*",
    ] {
        assert!(!proven(text), "{text}");
    }
}
