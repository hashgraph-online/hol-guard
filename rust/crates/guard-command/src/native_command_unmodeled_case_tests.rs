use super::without_case_labels;

/// Every label goes, and the `)` that ended it becomes the separator that
/// keeps the clause body in command position.
#[test]
fn labels_become_separators() {
    assert_eq!(
        without_case_labels("case x in a) echo a;; *) echo b;; esac"),
        "case x in  ; echo a;;  ; echo b;; esac"
    );
    assert_eq!(
        without_case_labels("case \"$f\" in *.ts|*.tsx) tsc;; esac"),
        "case \"$f\" in           ; tsc;; esac"
    );
    assert_eq!(
        without_case_labels("case $MODE in a) $CMD;; *) echo b;; esac"),
        "case $MODE in  ; $CMD;;  ; echo b;; esac"
    );
}

/// The word the construct matches on is not a label and stays where it is, and
/// so does everything after `esac`.
#[test]
fn only_the_labels_go() {
    assert_eq!(
        without_case_labels("case $MODE in a) echo a;; esac; echo $MODE"),
        "case $MODE in  ; echo a;; esac; echo $MODE"
    );
}

/// A single `;` ends a command inside a clause body; it does not open the next
/// label list.
#[test]
fn a_single_separator_does_not_open_a_label() {
    assert_eq!(
        without_case_labels("case x in a) echo a; echo b;; esac"),
        "case x in  ; echo a; echo b;; esac"
    );
}

/// A label built at run time, a text whose `(` may open a subshell, a function
/// body or an extglob, and a text with no construct at all are left exactly as
/// they were.
#[test]
fn an_unreadable_construct_is_left_alone() {
    for text in [
        "case x in $PATTERN) echo a;; esac",
        "case x in `echo a`) echo a;; esac",
        "case x in (a) echo a;; esac",
        "greet() { echo hi; }; greet",
        "echo a; echo b",
    ] {
        assert_eq!(without_case_labels(text), text, "{text}");
    }
}

/// A `)` outside any construct is not a label either, and a nested construct
/// keeps its own labels and its outer one apart.
#[test]
fn a_nested_construct_keeps_its_own_labels() {
    assert_eq!(without_case_labels("echo a) b"), "echo a) b");
    assert_eq!(
        without_case_labels("case x in a) case y in b) echo b;; esac;; esac"),
        "case x in  ; case y in  ; echo b;; esac;; esac"
    );
}

/// A label spelled inside quotes is still a label, and a quoted `)` does not
/// end one.
#[test]
fn quoting_does_not_move_a_label() {
    assert_eq!(
        without_case_labels("case x in 'a)b') echo a;; esac"),
        "case x in      ; echo a;; esac"
    );
}

/// The construct's keywords have to be its own. `case` and `in` written as
/// arguments open nothing, and a `#` comment runs to the end of its line, so
/// neither the keywords nor a `)` a comment holds takes a label. Without
/// either rule the one word the shell builds at run time would have been
/// blanked away.
#[test]
fn words_outside_the_construct_open_no_label() {
    for text in [
        "echo case in; /usr/bin/pyth?n3 -c 'import os' # )",
        "echo case in /bin/b?sh -c id )",
        "ls # case in x)",
    ] {
        assert_eq!(without_case_labels(text), text, "{text}");
    }
}

/// A comment inside a real construct is still only a comment: the labels go
/// and the clause body keeps every word it had.
#[test]
fn a_comment_in_a_clause_keeps_the_body() {
    assert_eq!(
        without_case_labels("case $MODE in a) /usr/bin/pyth?n3 -c 'ok';; esac # )"),
        "case $MODE in  ; /usr/bin/pyth?n3 -c 'ok';; esac # )"
    );
}

/// A span holding a command separator is a run of commands rather than a
/// pattern, so the text keeps the refusal it had.
#[test]
fn a_span_holding_a_separator_is_not_a_label() {
    for text in [
        "case x in a; b) echo a;; esac",
        "case x in a && b) echo a;; esac",
    ] {
        assert_eq!(without_case_labels(text), text, "{text}");
    }
}

/// The keyword still opens a construct wherever the shell reads a command,
/// which is what the separator and the shell prefixes before it decide.
#[test]
fn a_construct_after_a_separator_still_opens() {
    assert_eq!(
        without_case_labels("pwd && case $MODE in a) echo a;; *) echo b;; esac"),
        "pwd && case $MODE in  ; echo a;;  ; echo b;; esac"
    );
    assert_eq!(
        without_case_labels("if true; then case $MODE in a) echo a;; esac; fi"),
        "if true; then case $MODE in  ; echo a;; esac; fi"
    );
}

/// `case` is a keyword only where the shell still reads one. After a program
/// that runs another it is an ordinary word, so `nohup case` opens nothing and
/// the label a fake construct would have started cannot blank away the command
/// standing between it and the real construct's own label.
#[test]
fn a_case_after_a_program_that_runs_another_opens_nothing() {
    assert_eq!(
        without_case_labels(
            "nohup case x | echo in | /bin/b?sh -c id | { case y in y) echo;; esac; }"
        ),
        "nohup case x | echo in | /bin/b?sh -c id | { case y in  ; echo;; esac; }"
    );
    for text in [
        "command case x in a) echo a;; esac",
        "builtin case x in a) echo a;; esac",
    ] {
        assert_eq!(without_case_labels(text), text, "{text}");
    }
}

/// A brace group is a reserved word of its own, so a construct written inside
/// one is still the construct it looks like.
#[test]
fn a_construct_inside_a_brace_group_still_opens() {
    assert_eq!(
        without_case_labels("{ case $MODE in a) echo a;; esac; }"),
        "{ case $MODE in  ; echo a;; esac; }"
    );
}

/// A label list is one pattern, or several with a `|` between them. A span
/// holding whitespace-separated words is a run of commands wearing a label's
/// shape, so the text keeps the refusal it had, while the blanks a real list
/// carries around its `|` are read as the list they belong to.
#[test]
fn only_a_pattern_list_is_taken_for_a_label() {
    for text in [
        "case x in a b) echo a;; esac",
        "case x in a |) echo a;; esac",
    ] {
        assert_eq!(without_case_labels(text), text, "{text}");
    }
    assert_eq!(
        without_case_labels("case \"$f\" in *.ts | *.tsx) echo ts;; esac"),
        "case \"$f\" in             ; echo ts;; esac"
    );
}
