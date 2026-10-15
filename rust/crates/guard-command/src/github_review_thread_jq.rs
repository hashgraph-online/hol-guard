//! What a `gh api` jq filter may do: the one response projection a routine
//! review-thread mutation may carry, and no read of the environment.

/// A `--jq` filter that only walks down the mutation's own response,
/// `.data.resolveReviewThread.thread.isResolved` (or the
/// `unresolveReviewThread` field) or a prefix of it, and so cannot call
/// `env`, `input` or any other builtin or project other data.
pub(super) fn jq_is_plain_path(filter: &str) -> bool {
    let steps: Vec<&str> = filter.split('.').collect();
    steps.first() == Some(&"")
        && (2..=5).contains(&steps.len())
        && steps[1..]
            .iter()
            .zip([
                "data",
                "resolveReviewThread|unresolveReviewThread",
                "thread",
                "id|isResolved",
            ])
            .all(|(step, expected)| expected.split('|').any(|name| name == *step))
}

/// Whether a `gh api --jq` (`-q`) filter can read the process environment.
/// gh's jq exposes every variable, tokens included, through `$ENV` and `env`,
/// and prints the result, so such a filter is no static read. A `.env` field
/// access only walks the response.
pub(super) fn jq_env(option: &str, filter: &str) -> bool {
    let word = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    let bytes = filter.as_bytes();
    matches!(option, "--jq" | "-q")
        && (filter.contains("ENV")
            || filter.match_indices("env").any(|(at, _)| {
                let before = at.checked_sub(1).map(|index| bytes[index]);
                !before.is_some_and(|byte| word(byte) || byte == b'.')
                    && !bytes.get(at + 3).copied().is_some_and(word)
            }))
}
