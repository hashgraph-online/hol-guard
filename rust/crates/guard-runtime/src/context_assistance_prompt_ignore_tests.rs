use super::*;
use std::fs;

/// A temp folder by its real path, since ignore files are read link-free.
fn folder() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = crate::context_assistance_prompt_files::plain(fs::canonicalize(dir.path()).unwrap());
    (dir, path)
}

fn rules(text: &str) -> Chain {
    let (_dir, root) = folder();
    let file = root.join(".gitignore");
    fs::write(&file, text).unwrap();
    extend(None, &file, "").unwrap()
}

#[test]
fn names_and_extensions_match_at_any_depth() {
    let chain = rules("*.log\nsecrets\n# comment\n\n");
    assert!(ignored(&chain, "debug.log", false));
    assert!(ignored(&chain, "src/deep/debug.log", false));
    assert!(ignored(&chain, "src/secrets", true));
    assert!(!ignored(&chain, "src/log.ts", false));
    assert!(!ignored(&chain, "# comment", false));
}

#[test]
fn a_pattern_with_a_slash_is_anchored_to_its_folder() {
    let chain = rules("src/private/\n/build.ts\ndocs/*.md\n");
    assert!(ignored(&chain, "src/private", true));
    assert!(!ignored(&chain, "src/private", false));
    assert!(!ignored(&chain, "app/src/private", true));
    assert!(ignored(&chain, "build.ts", false));
    assert!(!ignored(&chain, "src/build.ts", false));
    assert!(ignored(&chain, "docs/notes.md", false));
    assert!(!ignored(&chain, "docs/deep/notes.md", false));
}

#[test]
fn double_stars_cross_folders() {
    let chain = rules("**/drafts\nlogs/**\na/**/z.txt\n");
    assert!(ignored(&chain, "drafts", true));
    assert!(ignored(&chain, "x/y/drafts", true));
    assert!(ignored(&chain, "logs/today/run.txt", false));
    assert!(!ignored(&chain, "logs", true));
    assert!(ignored(&chain, "a/z.txt", false));
    assert!(ignored(&chain, "a/b/c/z.txt", false));
}

#[test]
fn the_last_matching_line_wins_and_negation_reincludes() {
    let chain = rules("*.md\n!README.md\n");
    assert!(ignored(&chain, "notes.md", false));
    assert!(!ignored(&chain, "README.md", false));
}

#[test]
fn classes_question_marks_and_escapes_follow_git() {
    let chain = rules("file[0-9].txt\nname?.rs\n[!a]x.css\n\\#hash\n\\!bang\nspace\\ \n");
    assert!(ignored(&chain, "file3.txt", false));
    assert!(!ignored(&chain, "filex.txt", false));
    assert!(ignored(&chain, "name1.rs", false));
    assert!(!ignored(&chain, "name12.rs", false));
    assert!(ignored(&chain, "bx.css", false));
    assert!(!ignored(&chain, "ax.css", false));
    assert!(ignored(&chain, "#hash", false));
    assert!(ignored(&chain, "!bang", false));
    assert!(ignored(&chain, "space ", false));
}

#[test]
fn a_nested_file_applies_below_its_folder_and_overrides_the_top() {
    let (_dir, root) = folder();
    let root = root.as_path();
    fs::create_dir_all(root.join("pkg")).unwrap();
    fs::write(root.join(".gitignore"), "*.md\n").unwrap();
    fs::write(root.join("pkg/.gitignore"), "!keep.md\nlocal/\n").unwrap();
    let top = root_chain(root).unwrap();
    let nested = extend(top.clone(), &root.join("pkg/.gitignore"), "pkg").unwrap();
    assert!(ignored(&nested, "pkg/other.md", false));
    assert!(!ignored(&nested, "pkg/keep.md", false));
    assert!(ignored(&nested, "pkg/local", true));
    assert!(!ignored(&top, "local", true));
    assert!(!ignored(&nested, "local", true));
}

#[test]
fn git_info_exclude_counts_and_an_unreadable_file_is_an_error() {
    let (_dir, root) = folder();
    let root = root.as_path();
    fs::create_dir_all(root.join(".git/info")).unwrap();
    fs::write(root.join(".git/info/exclude"), "scratch/\n").unwrap();
    let chain = root_chain(root).unwrap();
    assert!(ignored(&chain, "scratch", true));
    fs::write(root.join(".gitignore"), "x\n".repeat(MAX_IGNORE_BYTES)).unwrap();
    assert!(root_chain(root).is_err());
}

#[test]
fn rules_it_cannot_fully_honour_keep_the_folder_out() {
    let (_dir, root) = folder();
    let file = root.join(".gitignore");
    let many: String = (0..=MAX_RULES)
        .map(|index| format!("file{index}\n"))
        .collect();
    fs::write(&file, many).unwrap();
    assert!(extend(None, &file, "").is_err(), "too many rules");
    let at_limit: String = (0..MAX_RULES)
        .map(|index| format!("file{index}\n"))
        .collect();
    fs::write(&file, at_limit).unwrap();
    assert!(extend(None, &file, "").is_ok());
    assert!(
        parse(&format!("{}x", "a?".repeat(200_000))).is_err(),
        "too large to compile"
    );
}
