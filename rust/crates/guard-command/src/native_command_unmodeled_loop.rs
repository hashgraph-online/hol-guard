//! Loops around a kept value that the unmodeled floor can still bound.
use super::substitution::LAUNCHERS;
use super::{command_words, named_words, unquoted_literal, INTERPRETERS};

/// Whether a text that fails `plain_sequence` only because of a `for`,
/// `while` or `until` loop names no program that runs text of its own.
///
/// `for f in a.js b.js; do actual=$(shasum -a 256 "$f" | awk '{print $1}');
/// test "$actual" = x; done` keeps a checksum in a value and compares it, and
/// every program the loop runs is named. It reached an evaluation failure, a
/// block with no approval left to give, because any loop around a kept value
/// was refused. The danger that refusal guards against is a kept value
/// reaching a program that runs it as code or as a program name, as in
/// `x=$(curl -s URL); for f in a; do node -e "$x" "$f"; done`, so a loop is
/// read here only when it closes with `done` and no word of the text names an
/// interpreter, a launcher, `eval`, `source` or `.`. Conditionals, case arms,
/// `select`, functions and coprocesses keep the refusal `plain_sequence`
/// gives them. The floor this opens never goes below review.
pub(super) fn launcher_free_loop(text: &str) -> bool {
    let literal = unquoted_literal(text);
    let mut closes = false;
    for word in command_words(&literal) {
        let keyword = word.split(['<', '>']).next().unwrap_or(word);
        match keyword {
            "done" => closes = true,
            "if" | "then" | "elif" | "else" | "fi" | "case" | "esac" | "select" | "function"
            | "coproc" | "." => return false,
            _ => {}
        }
    }
    closes
        && !named_words(text)
            .iter()
            .any(|name| INTERPRETERS.contains(&name.as_str()) || LAUNCHERS.contains(&name.as_str()))
}
