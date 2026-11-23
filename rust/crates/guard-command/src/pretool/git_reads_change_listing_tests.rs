//! `git whatchanged` and `git range-diff` print committed history.

use super::safe_git_arguments;
use crate::pretool::PathContext;

fn arguments(text: &str) -> Vec<String> {
    text.split_whitespace().map(str::to_owned).collect()
}

fn proven(text: &str) -> bool {
    safe_git_arguments(&arguments(text), true, PathContext::default())
}

/// `whatchanged` is `log` with the diff of each commit attached, and
/// `range-diff` compares two ranges of commits that are already recorded.
/// Both print and neither writes, so a read of them asks the same question
/// `git log` asks and is answered the same way.
#[test]
fn the_change_listings_read_recorded_history() {
    for text in [
        "whatchanged",
        "whatchanged -3",
        "whatchanged --oneline",
        "whatchanged --since=yesterday",
        "range-diff main...HEAD",
        "range-diff main..topic main..other",
        "range-diff --creation-factor=80 main...HEAD",
        "range-diff --no-dual-color main...HEAD",
    ] {
        assert!(proven(text), "{text}");
    }
}

/// The options that make any other read of the diff machinery keep its
/// review do the same here: one names a program Git runs for a blob or a
/// file, the other names a file Git writes.
#[test]
fn a_helper_or_an_output_file_keeps_its_review() {
    for text in [
        "whatchanged --textconv",
        "whatchanged --ext-diff",
        "whatchanged --output=/tmp/changed.patch",
        "whatchanged -o /tmp/changed.patch",
        "range-diff --textconv main...HEAD",
        "range-diff --ext-diff main...HEAD",
        "range-diff --output=/tmp/range.patch main...HEAD",
    ] {
        assert!(!proven(text), "{text}");
    }
}

/// Without the configuration probe `whatchanged` stays unproven unless the
/// command turns both helpers off itself, exactly as `git log` does: a
/// configured `diff.external` or `diff.<driver>.textconv` would otherwise
/// start a program the command never named.
///
/// `range-diff` gets no such spelling. It reads each range through an inner
/// `git log -p` that it assembles itself, and it does not pass its own
/// `--no-ext-diff` or `--no-textconv` down to that child, so a configured
/// `diff.<driver>.textconv` still runs with both switches on the command
/// line. Only the configuration probe clears that read.
#[test]
fn an_unprobed_listing_needs_both_helpers_turned_off() {
    for text in [
        "whatchanged",
        "range-diff main...HEAD",
        "range-diff --no-ext-diff --no-textconv main...HEAD",
        "range-diff --no-ext-diff --no-textconv --no-dual-color main...HEAD",
    ] {
        assert!(
            !safe_git_arguments(&arguments(text), false, PathContext::default()),
            "{text}"
        );
    }
    for text in [
        "whatchanged --no-ext-diff --no-textconv",
        "whatchanged --no-ext-diff --no-textconv -3",
    ] {
        assert!(
            safe_git_arguments(&arguments(text), false, PathContext::default()),
            "{text}"
        );
    }
}
