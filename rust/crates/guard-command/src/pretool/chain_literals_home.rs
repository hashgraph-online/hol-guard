//! `find "$HOME/.nvm/versions/node" -maxdepth 1 -type d` is how agents most
//! often name a folder in the home directory, yet the same read written
//! `find ~/.nvm/versions/node ...` was proven while the `$HOME` spelling went
//! to review. Both expand from the shell's HOME, so once that HOME is the
//! declared home directory, `$HOME` and `${HOME}` outside single quotes and
//! escapes name exactly that directory until something in the list could set
//! it. Writing the path in their place lets each step be judged on the path
//! it really names. Anything this pass does not fully understand returns
//! `None`, so the expansion stays opaque.

use super::pwd::project_uses;

/// The command with each home-directory expansion replaced by `home`; `None`
/// when nothing is replaced, the directory is not a plain absolute literal,
/// or any step at or before a replaced use could set `HOME`.
pub(super) fn project(command: &str, home: &str) -> Option<String> {
    project_uses(command, home, "HOME", use_width, |_| false)
}

/// The length of a home-directory use at the start of `rest`, 0 when it
/// starts some other expansion, and `None` for a `$HOME` the shell would
/// subscript or modify (zsh's `$HOME[1]`, `$HOME:h`).
fn use_width(rest: &[char]) -> Option<usize> {
    let starts = |text: &str| {
        rest.len() >= text.len() && rest.iter().zip(text.chars()).all(|(a, b)| *a == b)
    };
    if starts("${HOME}") {
        return Some(7);
    }
    if starts("$HOME") {
        return match rest.get(5) {
            Some(c) if c.is_ascii_alphanumeric() || *c == '_' => Some(0),
            Some('[' | ':') => None,
            _ => Some(5),
        };
    }
    Some(0)
}

#[cfg(test)]
#[path = "chain_literals_home_tests.rs"]
mod tests;
