use super::leaves_quote_open;

#[test]
fn a_stray_quote_after_the_last_argument_is_open() {
    for command in [
        "gh api graphql -f query='mutation { a }' -f t=PRRT_x'}",
        "echo \"unfinished",
        "git commit -m 'fix",
        "echo \"a \\\" b",
        // A `#` inside quotes or a word is text, not a comment.
        "git commit -m \"fix #12",
        "echo 'issue #4 and more",
        "echo a#b 'open",
    ] {
        assert!(leaves_quote_open(command), "{command}");
    }
}

#[test]
fn balanced_or_unclear_quoting_is_not_claimed_open() {
    for command in [
        "gh api graphql -f query='mutation { a }' -f t=PRRT_x",
        "echo \"it's fine\"",
        "echo 'say \"hi\"'",
        "echo it\\'s",
        "echo \"a \\\" b\"",
        // The shell reads these quotes differently from the plain rules.
        "echo \"$(echo \"'\")\"",
        "echo `echo \"'\"`",
        "echo $'it\\'s'",
        "echo hi # don't",
        "echo hi;# don't",
        "echo \"#\" # don't",
        "cat <<EOF\ndon't\nEOF",
    ] {
        assert!(!leaves_quote_open(command), "{command}");
    }
}
