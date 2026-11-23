//! The read prefix before a `cd` admits every filter the segment proof reads.

use super::super::super::stdin_filters::text_filter_program;
use super::cwd_read_executable;

/// A command that reads, changes directory and then reads again is judged in
/// two parts, and the part before the `cd` has to pass this screen for the
/// rest to be measured against the new directory. Agents end those prefix
/// reads in a filter -- `echo scan | nl && cd DIR && git status` -- and each
/// of these programs already carries an argument proof that opens a file only
/// through the same read screen `cat` takes, so a name missing here refused
/// the whole command for the name alone.
#[test]
fn every_text_filter_may_read_before_a_verified_cd() {
    for name in [
        "sort", "uniq", "cut", "tr", "paste", "join", "column", "nl", "tac", "rev", "fold",
        "expand", "unexpand", "fmt", "comm", "strings", "hexdump", "xxd", "pr", "shuf", "iconv",
        "ul", "tsort", "zcat", "gzcat", "bzcat", "xzcat", "lzcat", "zstdcat",
    ] {
        assert!(text_filter_program(name), "{name}");
        assert!(cwd_read_executable(Some(name)), "{name}");
    }
}

/// `awk` and `numfmt` are screened beside the filters by their own proofs:
/// `awk` refuses `system`, `getline`, the environment arrays and every pipe
/// or redirect its program could spell, and `numfmt` rewrites the numbers it
/// is handed without opening a file at all.
#[test]
fn awk_and_numfmt_may_read_before_a_verified_cd() {
    for name in ["awk", "numfmt"] {
        assert!(cwd_read_executable(Some(name)), "{name}");
    }
}

/// Membership still narrows. A program that writes is refused by name before
/// its arguments are read at all.
#[test]
fn programs_that_write_stay_out_of_the_screen() {
    for name in [
        "tee", "cp", "mv", "rm", "install", "truncate", "dd", "python3",
    ] {
        assert!(!text_filter_program(name), "{name}");
        assert!(!cwd_read_executable(Some(name)), "{name}");
    }
}
