//! A leading `!` and a trailing `&` wrap a command list without changing
//! which commands it runs: `!` inverts the list's exit status and `&` runs
//! it in the background. Neither adds a program, a redirect or a word to any
//! command, so the wrapped list's commands are the unwrapped list's and the
//! ordinary proofs can decide them. Anything this recognizer does not fully
//! understand returns `None`, which keeps the existing review behavior.
//!
//! `!` is the one wrapper whose reach is narrower than the list: it negates
//! the first pipeline, so a `&&` or `||` successor runs on the opposite
//! outcome once it is gone. A negation is therefore only read as its list
//! when that list is a single pipeline.
//!
//! Guard's own launcher is left out. The invocations it is admitted for, such
//! as the contained test runner, are proved by their exact text because the
//! runtime behind them honours exactly what that text asks for; reading a
//! wrapped spelling as the bare one would hand a wrapper the answer the exact
//! text earned. The wrapped form stays reviewable instead.

use super::script_content::foreground_job;

const MAX_COMMAND_BYTES: usize = 8192;

/// The command list a `!`-negated or `&`-backgrounded command runs, or `None`
/// when the command carries neither wrapper or the text is not understood.
pub(crate) fn unwrapped(command: &str) -> Option<String> {
    let command = command.trim();
    if command.len() > MAX_COMMAND_BYTES
        || command.contains("<<")
        || command
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
    {
        return None;
    }
    let foreground = foreground_job(command).map_or(command, str::trim);
    let unnegated = unnegated(foreground).unwrap_or(foreground);
    if unnegated == command || super::guard_diagnostics::names_launcher(unnegated) {
        return None;
    }
    Some(unnegated.to_owned())
}

/// The list a leading `!` negates. `!` is a reserved word only as the first
/// word of the list, so it has to stand alone: the text after it is a list in
/// its own right, and a second `!` is not a list this recognizer models.
fn unnegated(command: &str) -> Option<&str> {
    let rest = command.strip_prefix('!')?;
    if !matches!(rest.chars().next(), Some(c) if c == ' ' || c == '\t') {
        return None;
    }
    let rest = rest.trim_start();
    // `! cd sub && touch ../x` runs `touch` when `cd` fails, because the `!`
    // negates `cd` alone. The bare list runs it when `cd` succeeds, so the
    // flow-sensitive proofs would read the successors in the wrong working
    // directory and could admit a write the real shell makes outside the
    // workspace. Only a list that is one pipeline reads alike both ways.
    if rest.contains("&&") || rest.contains("||") || rest.contains([';', '\n']) {
        return None;
    }
    (!rest.is_empty() && !rest.starts_with('!')).then_some(rest)
}

#[cfg(test)]
#[path = "list_wrapper_tests.rs"]
mod tests;
