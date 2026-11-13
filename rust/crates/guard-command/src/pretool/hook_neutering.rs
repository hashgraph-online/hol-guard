//! Commands that switch a repository's Git hooks off for good.
//!
//! A one-off `git commit --no-verify` skips the hooks for that commit only,
//! and stays allowed. Overwriting a hook with a script that does nothing, or
//! renaming a hook or the hooks directory out of the way, disables every
//! check the project's hooks run for every later commit and push, by anyone
//! working in the checkout. Writes into the hook directories are already
//! reviewed; this screen keeps those two shapes out of the sandbox route,
//! because the sandbox lets a command write anywhere in the workspace and
//! the hook would be switched off when the contained run finishes.

use std::sync::LazyLock;

use regex::Regex;

fn pattern(source: &str) -> Regex {
    Regex::new(source).expect("hook neutering pattern compiles")
}

macro_rules! patterns {
    ($($name:ident = $source:expr;)*) => {
        $(static $name: LazyLock<Regex> = LazyLock::new(|| pattern($source));)*
    };
}

const HOOK_DIRECTORY: &str = r"(?:\.githooks|\.husky|\.git/hooks)";
const HOOK_NAME: &str = r"(?:applypatch-msg|pre-applypatch|post-applypatch|pre-commit|pre-merge-commit|prepare-commit-msg|commit-msg|post-commit|pre-rebase|post-checkout|post-merge|pre-push|pre-receive|update|post-receive|post-update|push-to-checkout|pre-auto-gc|post-rewrite)";

patterns! {
    REDIRECT = r#"(?:>>?|\btee\s+(?:-a\s+)?)\s*["']?(?P<path>[^\s"'<>|;&()]+)"#;
    HOOK_FILE = &format!(r"(?:^|/){HOOK_DIRECTORY}/(?:_/)?{HOOK_NAME}$");
    HEREDOC = r#"<<-?\s*["']?(?P<tag>[A-Za-z_][A-Za-z0-9_]*)["']?"#;
    ECHOED = r#"^\s*(?:echo(?:\s+-[neE]+)*|printf)\s+(?P<body>.*?)\s*(?:>>?|\|\s*tee\b)"#;
    INERT_LINE = r"^\s*(?:#.*|exit(?:\s+0)?|true|:)?\s*;?\s*$";
    RENAMED = &format!(
        r#"(?:(?:\brename(?:Sync)?|\bos\.replace|\bshutil\.move)\s*\(?\s*(?:q\(|["'])?|(?:^|[;&|(\s])mv\s+(?:-[A-Za-z]+\s+)*["']?)(?:[^\s"'(),]*/)?{HOOK_DIRECTORY}(?:/{HOOK_NAME})?(?:["'),\s]|$)"#
    );
}

/// Whether a script body runs nothing: blank, comments, `exit 0`, `true`
/// or `:` lines only. Git runs an empty hook file through the shell, which
/// exits 0 as well.
fn inert(body: &str) -> bool {
    body.lines().all(|line| INERT_LINE.is_match(line))
}

/// The heredoc body that starts after `line_end`, ended by a line holding
/// only `tag`.
fn heredoc_body<'t>(text: &'t str, line_end: usize, tag: &str) -> Option<&'t str> {
    let rest = text.get(line_end..)?.strip_prefix('\n')?;
    let mut at = 0;
    for line in rest.split_inclusive('\n') {
        if line.trim() == tag {
            return Some(&rest[..at]);
        }
        at += line.len();
    }
    None
}

/// Whether one line writes a script that does nothing into a hook file.
fn overwrites_hook_with_nothing(text: &str, line_start: usize, line: &str) -> bool {
    REDIRECT.captures_iter(line).any(|found| {
        let path = found["path"].trim_end_matches(['"', '\'']);
        if !HOOK_FILE.is_match(path) {
            return false;
        }
        if let Some(tag) = HEREDOC.captures(line) {
            return heredoc_body(text, line_start + line.len(), &tag["tag"]).is_some_and(inert);
        }
        if let Some(echoed) = ECHOED.captures(line) {
            let body = echoed["body"]
                .trim_matches(['"', '\''])
                .replace("\\n", "\n");
            return inert(&body);
        }
        // `> .githooks/pre-commit` or `: > …` alone empties the hook.
        let before = line[..found.get(0).expect("match").start()].trim();
        before.is_empty() || before == ":" || before.ends_with("&&") || before.ends_with(';')
    })
}

/// Whether `text` overwrites a Git hook with a script that does nothing, or
/// renames a hook or a hooks directory out of the way.
pub(super) fn neuters_git_hooks(text: &str) -> bool {
    if RENAMED.is_match(text) {
        return true;
    }
    let mut line_start = 0;
    for line in text.split('\n') {
        if overwrites_hook_with_nothing(text, line_start, line) {
            return true;
        }
        line_start += line.len() + 1;
    }
    false
}

#[cfg(test)]
#[path = "hook_neutering_tests.rs"]
mod tests;
