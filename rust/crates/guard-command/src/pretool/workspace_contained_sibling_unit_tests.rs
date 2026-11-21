//! Unit tests for the sibling route's word readings.

#[test]
fn only_a_bounded_numeric_heap_size_is_peeled() {
    for word in ["--max-old-space-size=16", "--max-old-space-size=4096"] {
        assert!(super::node_heap_size(word), "{word}");
    }
    for word in [
        "--max-old-space-size=",
        "--max-old-space-size=8",
        "--max-old-space-size=999999",
        "--max-old-space-size=4096k",
        "--max-old-space-size=+4096",
        "--require=./hook.js",
        "-r",
    ] {
        assert!(!super::node_heap_size(word), "{word}");
    }
}

#[test]
fn only_operators_outside_quotes_keep_the_review() {
    for text in [
        "sed -i '' 's|1.0.0|1.1.0|' /tmp/wt/catalog.json",
        "perl -pi -e \"s/a|b/c/\" /tmp/wt/notes.md",
        "sed -i 's/a\\|b/c/' notes.md",
        "printf 'a;b&c<d>e'",
    ] {
        assert!(!super::unquoted_operator(text), "{text}");
    }
    for text in [
        "sed -i '' 's/a/b/' notes.md > out",
        "perl -pi -e 's/a/b/' notes.md 2>/dev/null",
        "echo \"`id`\"",
        "echo 'open",
        "printf 'a\\' > out '",
        "cat notes.md | sh",
    ] {
        assert!(super::unquoted_operator(text), "{text}");
    }
}
