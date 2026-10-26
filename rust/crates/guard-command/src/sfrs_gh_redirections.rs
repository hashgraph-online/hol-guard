//! Shell redirections attached to GitHub CLI commands
//! (`runtime/github_shell_redirections.py`).

// Consumed by the GitHub shell classifier slice.
#![allow(dead_code)]

use std::sync::LazyLock;

use regex::Regex;

static ATTACHED_SAFE_DISCARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\A[012]?(?:>>|>\||>|<)(/dev/(?:null|stdout|stderr)|nul)\z")
        .expect("constant pattern")
});

fn safe_discard_target(target: &str) -> bool {
    matches!(
        caseless::default_case_fold_str(target).as_str(),
        "/dev/null" | "/dev/stdout" | "/dev/stderr" | "nul"
    )
}

/// `github_shell_args_and_redirection`: GitHub argv plus whether a material
/// local redirection remains.
pub(crate) fn github_shell_args_and_redirection(
    segment: &[String],
    command_index: usize,
) -> (Vec<String>, bool) {
    let mut args = Vec::new();
    let mut has_redirection = false;
    let mut index = command_index + 1;
    while index < segment.len() {
        let token = segment[index].as_str();
        if token == "2>&1" || token == "1>&2" || ATTACHED_SAFE_DISCARD.is_match(token) {
            index += 1;
            continue;
        }
        if matches!(token, ">" | ">>" | ">|" | "<" | "<<" | "<<<") {
            let target = segment.get(index + 1).map_or("", String::as_str);
            let safe_discard =
                matches!(token, ">" | ">>" | ">|" | "<") && safe_discard_target(target);
            has_redirection = has_redirection || !safe_discard;
            index += 2;
            continue;
        }
        if token.contains(['>', '<']) {
            has_redirection = true;
            index += 1;
            continue;
        }
        args.push(token.to_owned());
        index += 1;
    }
    (args, has_redirection)
}
