use super::*;

fn vector(words: &[&str]) -> Vec<String> {
    words.iter().map(|word| (*word).to_owned()).collect()
}

fn read(words: &[&str]) -> Option<(String, Vec<String>)> {
    read_only_invocation(&vector(words))
}

#[test]
fn the_diff_family_carries_both_helper_screens() {
    for verb in ["diff", "log", "show"] {
        assert_eq!(
            read(&["git", verb, "--stat"]),
            Some((
                verb.to_owned(),
                vector(&["--no-ext-diff", "--no-textconv", "--stat"])
            )),
            "{verb}"
        );
    }
}

#[test]
fn a_verb_that_reads_its_own_blobs_screens_only_the_filter_it_knows() {
    assert_eq!(
        read(&["git", "blame", "src/main.rs"]),
        Some((
            "blame".to_owned(),
            vector(&["--no-textconv", "src/main.rs"])
        ))
    );
    assert_eq!(
        read(&["git", "grep", "-n", "todo"]),
        Some(("grep".to_owned(), vector(&["--no-textconv", "-n", "todo"])))
    );
}

#[test]
fn a_verb_that_names_no_helper_option_is_passed_through() {
    assert_eq!(
        read(&["git", "rev-list", "--count", "HEAD"]),
        Some(("rev-list".to_owned(), vector(&["--count", "HEAD"])))
    );
}

#[test]
fn an_everyday_read_authority_contains_is_planned_here_too() {
    for verb in [
        "cat-file",
        "check-attr",
        "check-ignore",
        "count-objects",
        "describe",
        "for-each-ref",
        "ls-tree",
        "merge-base",
        "shortlog",
        "show-ref",
    ] {
        assert!(read(&["git", verb]).is_some(), "{verb}");
    }
}

#[test]
fn a_mixed_verb_is_read_only_in_the_forms_that_are_named() {
    assert!(read(&["git", "stash", "list"]).is_some());
    assert!(read(&["git", "stash", "show", "-p"]).is_some());
    assert!(read(&["git", "stash", "push"]).is_none());
    assert!(read(&["git", "stash"]).is_none());
    assert!(read(&["git", "bisect", "log"]).is_some());
    assert!(read(&["git", "bisect", "reset"]).is_none());
    assert!(read(&["git", "reflog"]).is_some());
    assert!(read(&["git", "reflog", "show", "HEAD"]).is_some());
    assert!(read(&["git", "reflog", "expire"]).is_none());
    assert!(read(&["git", "notes"]).is_some());
    assert!(read(&["git", "notes", "list"]).is_some());
    assert!(read(&["git", "notes", "show"]).is_none());
    assert!(read(&["git", "notes", "add"]).is_none());
    assert!(read(&["git", "sparse-checkout", "list"]).is_some());
    assert!(read(&["git", "sparse-checkout", "set", "src"]).is_none());
}

#[test]
fn a_mutating_verb_is_never_a_read() {
    for verb in ["commit", "push", "reset", "clean", "apply", "submodule"] {
        assert!(read(&["git", verb]).is_none(), "{verb}");
    }
}

#[test]
fn an_option_that_selects_a_helper_or_moves_the_output_is_refused() {
    for option in [
        "--ext-diff",
        "--textconv",
        "--output",
        "--output=out.txt",
        "-o",
        "--exec-path=/tmp/evil",
        "-Oorderfile",
        "--open-files-in-pager=sh",
    ] {
        assert!(read(&["git", "log", option]).is_none(), "{option}");
    }
}

#[test]
fn a_word_that_spells_shell_syntax_is_refused() {
    for operator in [";", "&&", "||", "|", "&"] {
        assert!(
            read(&["git", "diff", operator, "rm"]).is_none(),
            "{operator}"
        );
    }
}

#[test]
fn only_git_itself_is_read_this_way() {
    assert!(read(&["/usr/bin/git", "diff"]).is_some());
    assert!(read(&["git.exe", "diff"]).is_some());
    assert!(read(&["gitk", "diff"]).is_none());
    assert!(read(&["git"]).is_none());
    assert!(read(&[]).is_none());
}
