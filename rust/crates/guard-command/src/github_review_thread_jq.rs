//! The one response projection a routine review-thread mutation may carry.

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
