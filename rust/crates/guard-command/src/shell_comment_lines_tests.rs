use super::mask_comment_lines;

fn masked(text: &str) -> Option<String> {
    let out = mask_comment_lines(text);
    if let Some(value) = &out {
        assert_eq!(value.chars().count(), text.chars().count(), "{text:?}");
    }
    out
}

#[test]
fn a_whole_line_comment_is_blanked_in_place() {
    assert_eq!(
        masked("# check it; list it\ngh pr list").as_deref(),
        Some("                    gh pr list")
    );
    assert_eq!(
        masked("gh pr list\n  # then the threads\ngh api user").as_deref(),
        Some("gh pr list\n                     gh api user")
    );
    assert_eq!(
        masked("for n in 1 2; do\n# each one\ngh pr view $n; done").as_deref(),
        Some("for n in 1 2; do\n           gh pr view $n; done")
    );
}

#[test]
fn text_without_a_whole_line_comment_is_left_alone() {
    for text in [
        "gh pr list",
        "git status # a; b",
        "echo a#b",
        "echo ${#x}",
        "echo $#",
    ] {
        assert_eq!(masked(text), None, "{text:?}");
    }
}

#[test]
fn a_hash_line_inside_a_quote_or_expansion_is_data() {
    for text in [
        "echo 'a\n# b'",
        "echo \"a\n# b\"",
        "echo $'it\\'s\n# b'",
        "echo ${x:-\n# b}",
        "echo \"$(echo \"a\n# b\")\"",
        "echo `a\n# b`",
    ] {
        assert_eq!(masked(text), None, "{text:?}");
    }
}

#[test]
fn a_hash_line_inside_parentheses_is_left_alone() {
    // Inside `((...))` the `#` is arithmetic text and `$(...)` still expands.
    for text in [
        "((\n# $(touch x)\n1))",
        "(\n# note\ntrue)",
        "x=$(\n# note\ntrue)",
    ] {
        assert_eq!(masked(text), None, "{text:?}");
    }
}

#[test]
fn heredocs_continuations_and_open_quotes_are_not_read() {
    for text in [
        "cat <<EOF\n# not a comment\nEOF",
        "echo a \\\n# joined",
        "echo 'never closed\n# b",
        "# note\necho 'never closed",
        "x=$(case a in a) true;; esac)\n# note",
    ] {
        assert_eq!(masked(text), None, "{text:?}");
    }
}
