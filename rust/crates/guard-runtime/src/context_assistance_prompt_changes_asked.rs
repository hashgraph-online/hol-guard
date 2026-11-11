//! Whether a prompt asks about changes, and whether about someone else's
//! change or a failure, read from its plain words.

const WORDS: &str =
    "change changed changes pushed teammate review diff broke commit commits committed recently";
/// Words for a prompt about a change the agent did not make, or one that
/// broke something: then a commit's own diff is worth showing.
const OTHERS: [&str; 5] = ["teammate", "pushed", "broke", "broken", "failing"];

/// Words that, just before a change word, say there is none to look at.
const NOT: [&str; 5] = ["no", "not", "without", "don", "dont"];

/// Whether `prompt` asks about what changed.
pub(super) fn about_changes(prompt: &str) -> bool {
    let lower = prompt.to_lowercase();
    let words = words(&lower);
    // "no code changes" or "don't change anything" rules changes out.
    let denied = |at: usize| {
        words[at.saturating_sub(2)..at]
            .iter()
            .any(|word| NOT.contains(word))
    };
    (words.iter().enumerate()).any(|(at, word)| {
        (WORDS.split(' ').any(|known| known == *word) || word.starts_with("regress")) && !denied(at)
    }) || (words.windows(2)).any(|pair| pair == ["this", "session"] || last_push(pair))
}

/// Whether `prompt` is about someone else's change or a failure.
pub(super) fn about_others(prompt: &str) -> bool {
    let lower = prompt.to_lowercase();
    let words = words(&lower);
    (words.iter()).any(|word| {
        OTHERS.contains(word) || word.starts_with("fail") || word.starts_with("regress")
    }) || words.windows(2).any(last_push)
}

/// "since the last push" names what was pushed, as "pushed" does; a bare
/// "push" ("push this when it passes") names nothing that changed.
fn last_push(pair: &[&str]) -> bool {
    matches!(pair, ["last" | "latest" | "recent", "push"])
}

fn words(lower: &str) -> Vec<&str> {
    (lower.split(|c: char| !c.is_alphanumeric()))
        .filter(|word| !word.is_empty())
        .collect()
}

#[cfg(test)]
#[path = "context_assistance_prompt_changes_asked_tests.rs"]
mod tests;
