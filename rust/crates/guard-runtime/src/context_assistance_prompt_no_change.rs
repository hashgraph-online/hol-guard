//! Whether a prompt asks for an answer and no change to the code, as a
//! question does. Only a prohibition on the whole task counts: "don't edit
//! the tests" or "don't change anything else" limits a fix, which still
//! needs the tests near the code it changes.

/// Phrases that say not to change the code.
const NO_CHANGE: [&str; 11] = [
    "no code changes",
    "no code change",
    "no changes",
    "change nothing",
    "don't change anything",
    "do not change anything",
    "without changing anything",
    "don't modify anything",
    "do not modify anything",
    "don't edit",
    "do not edit",
];
/// Words after such a phrase that keep it about the whole task.
const STILL_WHOLE: [&str; 4] = ["just", "please", "yet", "i"];
/// Words after such a phrase that name everything, so the words after them
/// decide: "don't edit files, just answer" but "don't edit files in tests/".
const EVERYTHING: [&str; 5] = ["files", "code", "anything", "at", "all"];

/// True when the prompt says not to change anything at all.
pub(crate) fn asks_no_change(prompt: &str) -> bool {
    let lower = prompt.to_lowercase().replace('\u{2019}', "'");
    NO_CHANGE.iter().any(|phrase| {
        lower.match_indices(phrase).any(|(at, _)| {
            let before = lower[..at].chars().next_back();
            !before.is_some_and(char::is_alphanumeric) && whole(&lower[at + phrase.len()..])
        })
    })
}

/// True when the text after a no-change phrase does not narrow it to a part
/// of the project: it ends there, or goes on with a new clause.
fn whole(rest: &str) -> bool {
    let rest = rest.trim_start();
    let Some(first) = rest.chars().next() else {
        return true;
    };
    if !first.is_alphanumeric() {
        return true;
    }
    let word_end = rest
        .find(|c: char| !c.is_alphanumeric() && c != '\'')
        .unwrap_or(rest.len());
    let word = &rest[..word_end];
    if EVERYTHING.contains(&word) {
        return whole(&rest[word_end..]);
    }
    STILL_WHOLE.contains(&word)
}
