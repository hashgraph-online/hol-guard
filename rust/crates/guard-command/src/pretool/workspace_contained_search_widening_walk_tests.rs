//! The hidden-entry walk skips the directories ripgrep skips, and keeps
//! review wherever it cannot tell what ripgrep would bring back.
use super::segment_widens;
use std::path::Path;

fn widens(command: &[&str], cwd: &Path) -> bool {
    let arguments: Vec<String> = command.iter().map(|word| (*word).to_owned()).collect();
    segment_widens(&arguments, cwd, false)
}

fn write(root: &Path, file: &str, text: &str) {
    let path = root.join(file);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// A checkout with ignored dependency and build trees, each holding a hidden file.
fn tree(git: bool) -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    if git {
        std::fs::create_dir_all(root.path().join(".git")).unwrap();
    }
    write(root.path(), ".gitignore", "node_modules/\n/build\n");
    write(root.path(), "src/app.ts", "export const KEY = 1;\n");
    for directory in ["node_modules/pkg", "build"] {
        write(
            root.path(),
            &format!("{directory}/.env.local.ts"),
            "KEY=SYNTHETIC_MARKER_ONLY\n",
        );
    }
    root
}

#[test]
fn an_ignored_dependency_tree_is_not_walked_inside_a_repository() {
    let root = tree(true);
    assert!(!widens(&["-n", "KEY", "-g", "*.ts"], root.path()));
    // A glob naming the ignored directory reopens it.
    assert!(widens(&["-n", "KEY", "-g", "node_modules/**"], root.path()));
}

#[test]
fn ignore_files_outside_a_repository_do_not_prune_the_walk() {
    // ripgrep reads `.gitignore` only inside a git repository.
    let root = tree(false);
    assert!(widens(&["-n", "KEY", "-g", "*.ts"], root.path()));
}

#[test]
fn plain_searches_and_exclusions_do_not_widen() {
    let root = tree(true);
    assert!(!widens(&["-n", "KEY"], root.path()));
    assert!(!widens(&["--files", "-g", "!build"], root.path()));
    assert!(widens(&["-n", "--hidden", "KEY"], root.path()));
}

#[test]
fn a_glob_that_brings_back_a_gitignored_file_widens() {
    // An inclusion glob overrides ignore rules for the files it names.
    let root = tree(true);
    write(root.path(), "config/secrets.json", "{}\n");
    write(root.path(), "config/app.json", "{}\n");
    write(
        root.path(),
        ".gitignore",
        "node_modules/\n/build\nconfig/secrets.json\n*.pem\n!public.pem\n",
    );
    assert!(widens(&["-n", "KEY", "-g", "*.json"], root.path()));
    assert!(!widens(&["-n", "KEY", "-g", "app.json"], root.path()));
    write(root.path(), "server.pem", "x\n");
    assert!(widens(&["--files", "-g", "*.pem"], root.path()));
}

#[test]
fn a_rule_another_rule_puts_back_still_counts() {
    // ripgrep ranks `.ignore` over a deeper `.gitignore`; the walk does not
    // rank rules at all, so any rule excluding a file keeps review.
    let root = tree(true);
    write(root.path(), ".ignore", "*.key\n");
    write(root.path(), "sub/.gitignore", "!*.key\n");
    write(root.path(), "sub/a.key", "x\n");
    assert!(widens(&["-n", "KEY", "-g", "*.key"], root.path()));
}

#[test]
fn an_ignore_file_the_walk_cannot_read_in_full_keeps_review() {
    let root = tree(true);
    assert!(!widens(&["-n", "KEY", "-g", "*.ts"], root.path()));
    write(root.path(), "src/.gitignore", &"# note\n".repeat(2_000));
    assert!(widens(&["-n", "KEY", "-g", "*.ts"], root.path()));
}

#[test]
fn a_dotfile_a_glob_names_counts_as_hidden() {
    let root = tree(true);
    assert!(widens(&["--files", "-g", "*"], root.path()));
}

#[test]
fn a_pattern_that_names_a_directory_is_not_taken_for_the_search_root() {
    let root = tempfile::tempdir().unwrap();
    write(root.path(), "src/app.ts", "src\n");
    write(root.path(), ".env", "KEY=SYNTHETIC_MARKER_ONLY\n");
    // ripgrep searches `cwd` for the pattern `src`, and `*` brings back `.env`.
    assert!(widens(&["src", "-g", "*"], root.path()));
    assert!(widens(&["-t", "ts", "src", "-g", "*"], root.path()));
    // With the pattern given by a flag, or no pattern, `src` is the root.
    assert!(!widens(&["-e", "KEY", "src", "-g", "*"], root.path()));
    assert!(!widens(&["--files", "src", "-g", "*"], root.path()));
    assert!(!widens(&["KEY", "src", "-g", "*"], root.path()));
}

#[test]
fn a_standalone_double_dash_ends_the_options() {
    let root = tempfile::tempdir().unwrap();
    write(root.path(), "README.md", "--hidden\n");
    assert!(!widens(
        &["-g", "*.md", "--", "--hidden", "README.md"],
        root.path()
    ));
    // Taken as a flag's value, `--` ends nothing.
    assert!(widens(
        &["--context-separator", "--", "--hidden"],
        root.path()
    ));
}

#[test]
fn glob_case_insensitive_folds_every_glob() {
    let root = tempfile::tempdir().unwrap();
    write(root.path(), ".local.env", "KEY=SYNTHETIC_MARKER_ONLY\n");
    assert!(!widens(&["-n", "KEY", "-g", "*.ENV"], root.path()));
    assert!(widens(
        &["-n", "KEY", "--glob-case-insensitive", "-g", "*.ENV"],
        root.path()
    ));
}

#[test]
fn a_search_after_a_directory_change_keeps_review() {
    let root = tempfile::tempdir().unwrap();
    write(root.path(), "README.md", "# KEY\n");
    let arguments = ["-n", "KEY", "-g", "*.md"].map(str::to_owned);
    assert!(!segment_widens(&arguments, root.path(), false));
    assert!(segment_widens(&arguments, root.path(), true));
}

#[test]
fn a_literal_ignore_rule_is_read_without_the_glob_matcher() {
    // A walk asks every rule about every entry it meets. Over a large
    // checkout whose `.gitignore` names dozens of directories outright, the
    // glob matcher made the walk outlast the hook's deadline.
    let root = tree(true);
    let mut rules = String::from("node_modules/\n/build\n*.log\n");
    for index in 0..40 {
        rules.push_str(&format!("generated-{index}/\n/fixtures/output-{index}\n"));
    }
    write(root.path(), ".gitignore", &rules);
    for index in 0..30 {
        write(
            root.path(),
            &format!("src/module_{index}.ts"),
            "export {};\n",
        );
    }
    super::GLOB_RULE_READS.with(|reads| reads.set(0));
    assert!(!widens(&["-n", "KEY", "-g", "*.ts*"], root.path()));
    let reads = super::GLOB_RULE_READS.with(std::cell::Cell::get);
    // Only `*.log` goes to the glob matcher: once for each of the ~35
    // entries the walk meets, not 83 times.
    assert!(reads > 0, "the wildcard rule was never read");
    assert!(
        reads <= 40,
        "literal rules went to the glob matcher: {reads}"
    );
}

#[test]
fn a_literal_rule_matches_exactly_what_the_glob_matcher_matches() {
    use crate::pretool::search_scope_glob::{glob_matches, is_literal};
    let patterns = [
        "node_modules",
        "dist",
        "app/generated",
        ".env",
        "a b",
        "*.log",
        "build?",
        "[ab]c",
        "\\#notes",
        "out/**",
    ];
    let subjects = [
        "node_modules",
        "node_modules2",
        "Node_modules",
        "dist",
        "dist/x",
        "app/generated",
        "app/generated/x",
        "x/app/generated",
        ".env",
        ".envrc",
        "a b",
        "build1",
        "ac",
        "#notes",
        "",
    ];
    for pattern in patterns {
        assert_eq!(
            is_literal(pattern),
            !pattern.contains(['*', '?', '[', '\\']),
            "{pattern}"
        );
        if !is_literal(pattern) {
            continue;
        }
        for subject in subjects {
            assert_eq!(
                glob_matches(pattern, subject),
                Ok(pattern == subject),
                "{pattern} against {subject}"
            );
        }
    }
    // A pattern too long for the glob matcher is not literal, so it still
    // reads as unreadable instead of as a plain comparison.
    let long = "x".repeat(257);
    assert!(!is_literal(&long));
    assert!(glob_matches(&long, &long).is_err());
}
