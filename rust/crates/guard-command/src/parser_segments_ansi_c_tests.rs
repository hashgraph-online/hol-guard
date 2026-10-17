//! `$'…'` spells a literal word, escapes and all.
use super::{shell_tokens, split_execution_segments};

/// The word runs nothing: it is single-quoted text whose escapes are written
/// out. Reading it is what keeps `grep -n $'\t' src/main.rs`, which an agent
/// writes whenever a tab is the separator, from an approval it has no reason
/// to need.
#[test]
fn an_ansi_c_word_reads_as_the_text_it_spells() {
    for (command, expected) in [
        (
            "grep -n $'\\t' src/main.rs",
            vec!["grep", "-n", "\t", "src/main.rs"],
        ),
        ("printf '%s' $'hello'", vec!["printf", "%s", "hello"]),
        ("echo $'line\\tsep'", vec!["echo", "line\tsep"]),
        ("echo pre$'\\x41'post", vec!["echo", "preApost"]),
        ("echo $'\\101'", vec!["echo", "A"]),
        ("echo $'it\\'s'", vec!["echo", "it's"]),
        (
            "sort -t $'\\t' -k2 data.tsv",
            vec!["sort", "-t", "\t", "-k2", "data.tsv"],
        ),
    ] {
        assert_eq!(shell_tokens(command, false).unwrap(), expected, "{command}");
    }
}

/// A word this reader cannot decode is a word it would spell differently than
/// the shell spells it, so the command stays uncertain rather than modelled
/// wrong. `$"…"` is the other non-POSIX quoting and is not read at all.
#[test]
fn an_escape_this_reader_does_not_decode_stays_uncertain() {
    for command in [
        "echo $'\\u0041'",
        "echo $'\\cA'",
        "echo $'\\x00'",
        "echo $'a\u{0}b'",
        "echo $'open",
    ] {
        assert!(
            split_execution_segments(command, false).is_err(),
            "{command}"
        );
        assert!(shell_tokens(command, false).is_err(), "{command}");
    }
    assert!(split_execution_segments("echo $\"hello\"", false).is_err());
}

/// A shell that keeps an unquoted backslash literal spells no ANSI-C word:
/// there `\$'x\'` is a literal `$` and then a plain single-quoted word, so
/// reading it as one word would swallow the separator behind it and model a
/// command the shell does not run.
#[test]
fn a_shell_that_keeps_a_backslash_literal_reads_no_ansi_c_word() {
    for command in [
        "echo \\$'x\\' ; docker ps ; $''",
        "grep -n $'\\t' src/main.rs",
        "echo $'hello'",
    ] {
        assert!(
            split_execution_segments(command, true).is_err(),
            "{command}"
        );
        assert!(shell_tokens(command, true).is_err(), "{command}");
    }
}
