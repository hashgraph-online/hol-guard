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

/// Without the configuration probe neither listing is proven, however it is
/// spelled. Both walk commits, so `log.showSignature`, a `%G` placeholder or
/// a `pretty.*` alias carrying one starts the configured verification
/// program, which `--no-ext-diff` and `--no-textconv` do not touch; and
/// `range-diff` reads each range through an inner `git log -p` that it
/// assembles itself and never gives those switches to, so a configured
/// `diff.<driver>.textconv` runs with both of them on the command line. The
/// probe screens all of that, and nothing else does.
///
/// A comparison between two trees keeps the spelling: an external driver and
/// a textconv filter are the whole of what it can start.
#[test]
fn an_unprobed_listing_needs_the_configuration_probe() {
    for text in [
        "whatchanged",
        "whatchanged --no-ext-diff --no-textconv",
        "whatchanged --no-ext-diff --no-textconv -3",
        "range-diff main...HEAD",
        "range-diff --no-ext-diff --no-textconv main...HEAD",
        "range-diff --no-ext-diff --no-textconv --no-dual-color main...HEAD",
        // The commit walks they are spellings of answer the same way.
        "log --no-ext-diff --no-textconv -3",
        "show --no-ext-diff --no-textconv HEAD",
    ] {
        assert!(
            !safe_git_arguments(&arguments(text), false, PathContext::default()),
            "{text}"
        );
    }
    for text in [
        "diff --no-ext-diff --no-textconv",
        "diff-tree --no-ext-diff --no-textconv -r HEAD",
    ] {
        assert!(
            safe_git_arguments(&arguments(text), false, PathContext::default()),
            "{text}"
        );
    }
}
