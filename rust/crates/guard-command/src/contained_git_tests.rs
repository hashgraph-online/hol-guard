use super::*;

fn vector(words: &[&str]) -> Vec<String> {
    words.iter().map(|word| (*word).to_owned()).collect()
}

fn read(words: &[&str]) -> Option<(String, Vec<String>)> {
    read_only_invocation(&vector(words)).map(|reading| (reading.operation, reading.arguments))
}

fn routed(words: &[&str]) -> Option<(String, Vec<String>, Vec<String>)> {
    read_only_invocation(&vector(words))
        .map(|reading| (reading.operation, reading.arguments, reading.directories))
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
fn a_subcommand_that_prints_a_diff_is_screened_after_its_own_word() {
    assert_eq!(
        read(&["git", "stash", "show", "-p"]),
        Some((
            "stash".to_owned(),
            vector(&["show", "--no-ext-diff", "--no-textconv", "-p"])
        ))
    );
}

#[test]
fn a_log_walk_under_another_name_is_screened_and_refused_as_the_log_family_is() {
    // `git reflog show` and `git stash list` hand their words to the log walk,
    // so `-p` prints a patch and the helpers run unless they are screened.
    assert_eq!(
        read(&["git", "stash", "list", "-p"]),
        Some((
            "stash".to_owned(),
            vector(&["list", "--no-ext-diff", "--no-textconv", "-p"])
        ))
    );
    assert_eq!(
        read(&["git", "reflog", "show", "-p"]),
        Some((
            "reflog".to_owned(),
            vector(&["show", "--no-ext-diff", "--no-textconv", "-p"])
        ))
    );
    assert_eq!(
        read(&["git", "reflog"]),
        Some((
            "reflog".to_owned(),
            vector(&["--no-ext-diff", "--no-textconv"])
        ))
    );
    for words in [
        &["git", "reflog", "show", "-p", "--ext-diff"][..],
        &["git", "reflog", "show", "--textconv"][..],
        &["git", "reflog", "show", "--output=/tmp/out"][..],
        &["git", "stash", "list", "-p", "--textconv"][..],
        &["git", "stash", "list", "--ext-diff"][..],
        &["git", "stash", "list", "--output=/tmp/out"][..],
    ] {
        assert!(read(words).is_none(), "{words:?}");
    }
    // A pickaxe value that spells a refused letter is the value, as it is for
    // the verbs this one is an alias of.
    assert!(read(&["git", "reflog", "show", "-Sorigin"]).is_some());
    // `reflog exists` answers about a ref and takes no log option, so it is
    // left as it was written.
    assert_eq!(
        read(&["git", "reflog", "exists", "HEAD"]),
        Some(("reflog".to_owned(), vector(&["exists", "HEAD"])))
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
    ] {
        assert!(read(&["git", "log", option]).is_none(), "{option}");
    }
    assert!(read(&["git", "grep", "--open-files-in-pager=sh"]).is_none());
}

#[test]
fn a_refused_option_is_refused_in_every_spelling_git_resolves() {
    // Git accepts any unambiguous prefix of a long option its verb defines.
    for option in ["--open", "--open-files", "--textc", "--tex"] {
        assert!(
            read(&["git", "grep", option, "needle"]).is_none(),
            "{option}"
        );
    }
    for option in ["--ext", "--ext-di", "--outp"] {
        assert!(read(&["git", "diff", option]).is_none(), "{option}");
    }
    // A cluster carries its letters one by one, whatever their order.
    for cluster in ["-nO", "-iOsh", "-O"] {
        assert!(
            read(&["git", "grep", cluster, "needle"]).is_none(),
            "{cluster}"
        );
    }
    // `cat-file` runs the repository's smudge filter for `--filters`, and
    // spells neither `--filter` nor `--text`, so both abbreviate a refusal.
    for option in ["--filters", "--filter", "--text"] {
        assert!(
            read(&["git", "cat-file", option, "HEAD:x"]).is_none(),
            "{option}"
        );
    }
}

#[test]
fn an_option_a_verb_spells_in_full_keeps_its_own_meaning() {
    // `--text` is the diff family's own "treat the file as text", and the
    // letters after a short option that takes a value are that value.
    assert!(read(&["git", "diff", "--text"]).is_some());
    assert!(read(&["git", "grep", "--text", "needle"]).is_some());
    assert!(read(&["git", "grep", "-eFOO"]).is_some());
    assert!(read(&["git", "log", "-SFOO"]).is_some());
    assert!(read(&["git", "log", "--oneline", "--format=%H"]).is_some());
    // `git grep -o` prints only the matching text; nothing is opened by it.
    assert_eq!(
        read(&["git", "grep", "-o", "needle"]),
        Some((
            "grep".to_owned(),
            vector(&["--no-textconv", "-o", "needle"])
        ))
    );
}

#[test]
fn a_leading_directory_is_reported_rather_than_executed() {
    assert_eq!(
        routed(&["git", "-C", "subdir", "grep", "needle"]),
        Some((
            "grep".to_owned(),
            vector(&["--no-textconv", "needle"]),
            vector(&["subdir"])
        ))
    );
    assert_eq!(
        routed(&["git", "-Csubdir", "-C", "nested", "log", "-1"]),
        Some((
            "log".to_owned(),
            vector(&["--no-ext-diff", "--no-textconv", "-1"]),
            vector(&["subdir", "nested"])
        ))
    );
    assert_eq!(
        routed(&["git", "--no-pager", "diff"]),
        Some((
            "diff".to_owned(),
            vector(&["--no-ext-diff", "--no-textconv"]),
            Vec::new()
        ))
    );
}

#[test]
fn a_global_option_that_configures_git_is_not_a_read() {
    // `-c` names a setting such as the pager, and `--git-dir` moves the
    // repository out from under the roots the plan grants.
    assert!(read(&["git", "-c", "core.pager=sh", "log"]).is_none());
    assert!(read(&["git", "--git-dir=/tmp/evil", "log"]).is_none());
    assert!(read(&["git", "--exec-path=/tmp/evil", "log"]).is_none());
    assert!(read(&["git", "-C"]).is_none());
    assert!(read(&["git", "-C", "-x", "log"]).is_none());
    assert!(read(&["git", "-C", ";", "log"]).is_none());
    assert!(read(&["git", "-C", "subdir"]).is_none());
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
