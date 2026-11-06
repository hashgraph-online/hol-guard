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
#[test]
fn a_configuration_pattern_holding_a_star_is_not_a_glob_over_the_working_tree() {
    for text in [
        "config --get-regexp remote.*url",
        "config --get-regexp .*",
        "config --get-regexp remote*",
        "config --get-regexp remote\\..*\\.url",
        "-C /tmp/checkout config --get-regexp remote.*url",
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
