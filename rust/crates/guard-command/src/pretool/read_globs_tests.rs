use super::{literal_pattern, wildcard_matches};

#[test]
fn matcher_covers_every_name_a_shell_could_expand() {
    for (pattern, name) in [
        ("*.json", "commands.json"),
        ("*.json", "COMMANDS.JSON"),
        ("*.json", ".hidden.json"),
        ("*.json", "*.json"),
        ("v?.md", "v1.md"),
        ("*", "anything"),
        ("a*b*c", "abc"),
    ] {
        assert!(
            wildcard_matches(pattern.as_bytes(), name.as_bytes()),
            "{pattern} {name}"
        );
    }
    for (pattern, name) in [
        ("*.json", "commands.jsonl"),
        ("v?.md", "v10.md"),
        ("a*b*c", "acb"),
    ] {
        assert!(
            !wildcard_matches(pattern.as_bytes(), name.as_bytes()),
            "{pattern} {name}"
        );
    }
}

#[test]
fn only_plain_last_component_patterns_are_modelled() {
    for pattern in ["*.json", "*.rs", "schema-?.json", "v1.*", "*"] {
        assert!(literal_pattern(pattern), "{pattern}");
    }
    for pattern in [
        "",
        "commands.json",
        "**",
        "**.json",
        ".*",
        ".env*",
        "[a-z]*.json",
        "{a,b}.json",
        "*.json~",
        "*(x)",
        "!(*.json)",
        "^*.json",
        "*#",
        "*\\.json",
        "* .json",
        "*$HOME",
        "*`id`",
    ] {
        assert!(!literal_pattern(pattern), "{pattern}");
    }
}

/// The body of an unrolled `for` loop reads its variable unquoted, so a name
/// holding whitespace would reach the program as two arguments rather than as
/// the path this proof read.
#[test]
fn a_match_that_would_split_into_two_words_is_refused() {
    let root =
        std::path::Path::new("/tmp").join(format!("guard-glob-split-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let home = root.join("home");
    let workspace = home.join("project");
    let source = workspace.join("src");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::create_dir_all(workspace.join(".git")).unwrap();
    std::fs::write(source.join("one.ts"), "export {};\n").unwrap();
    let home = std::fs::canonicalize(&home).unwrap();
    let workspace = std::fs::canonicalize(&workspace).unwrap();
    let context = super::super::super::PathContext {
        home_dir: home.to_str(),
        cwd: workspace.to_str(),
        ..Default::default()
    };

    assert_eq!(
        super::glob_file_matches("src/*.ts", context),
        Some(vec!["src/one.ts".to_owned()])
    );
    std::fs::write(source.join("two words.ts"), "export {};\n").unwrap();
    assert_eq!(super::glob_file_matches("src/*.ts", context), None);

    let _ = std::fs::remove_dir_all(&root);
}

/// That same unquoted read expands its word a second time, so a name holding
/// a glob character names files this proof never read: `src/x[.]pem` clears
/// the secret-extension check, then `cat $f` reads `src/x.pem`.
#[test]
fn a_match_that_would_expand_again_is_refused() {
    let root =
        std::path::Path::new("/tmp").join(format!("guard-glob-reglob-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let home = root.join("home");
    let workspace = home.join("project");
    let source = workspace.join("src");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::create_dir_all(workspace.join(".git")).unwrap();
    std::fs::write(source.join("notes.md"), "notes\n").unwrap();
    let home = std::fs::canonicalize(&home).unwrap();
    let workspace = std::fs::canonicalize(&workspace).unwrap();
    let context = super::super::super::PathContext {
        home_dir: home.to_str(),
        cwd: workspace.to_str(),
        ..Default::default()
    };

    assert_eq!(
        super::glob_file_matches("src/*.md", context),
        Some(vec!["src/notes.md".to_owned()])
    );
    std::fs::write(source.join("x.pem"), "secret\n").unwrap();
    std::fs::write(source.join("x[.]pem"), "decoy\n").unwrap();
    assert_eq!(super::glob_file_matches("src/x?.?pem", context), None);

    let _ = std::fs::remove_dir_all(&root);
}

/// `cat *.md` names no directory at all. The shell expands it against the
/// working directory and passes the bare names on, so the proof reads the
/// same files and returns the same words.
#[test]
fn a_pattern_without_a_directory_expands_in_the_working_directory() {
    let root = std::path::Path::new("/tmp").join(format!("guard-glob-bare-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let home = root.join("home");
    let workspace = home.join("project");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(workspace.join(".git")).unwrap();
    std::fs::write(workspace.join("notes.md"), "notes\n").unwrap();
    let home = std::fs::canonicalize(&home).unwrap();
    let workspace = std::fs::canonicalize(&workspace).unwrap();
    let context = super::super::super::PathContext {
        home_dir: home.to_str(),
        cwd: workspace.to_str(),
        ..Default::default()
    };

    assert_eq!(
        super::glob_file_matches("*.md", context),
        Some(vec!["notes.md".to_owned()])
    );
    assert_eq!(
        super::glob_file_matches("./*.md", context),
        Some(vec!["./notes.md".to_owned()])
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// Without a directory prefix the expanded word is the name itself, so a name
/// the program would read as an option or as a variable assignment, a secret
/// extension and a hidden entry all keep their review.
#[test]
fn a_bare_pattern_still_refuses_an_option_or_a_secret() {
    let root = std::path::Path::new("/tmp").join(format!("guard-glob-dash-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let home = root.join("home");
    let workspace = home.join("project");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(workspace.join(".git")).unwrap();
    std::fs::write(workspace.join("report.txt"), "report\n").unwrap();
    let home = std::fs::canonicalize(&home).unwrap();
    let workspace = std::fs::canonicalize(&workspace).unwrap();
    let context = super::super::super::PathContext {
        home_dir: home.to_str(),
        cwd: workspace.to_str(),
        ..Default::default()
    };

    assert_eq!(
        super::glob_file_matches("*.txt", context),
        Some(vec!["report.txt".to_owned()])
    );
    std::fs::write(workspace.join("-n.txt"), "option\n").unwrap();
    assert_eq!(super::glob_file_matches("*.txt", context), None);
    std::fs::remove_file(workspace.join("-n.txt")).unwrap();

    // `awk '{print}' *.txt` hands every match on as an operand, and an
    // operand spelled `name=value` sets a variable instead of naming a file.
    // The proof would stand for a read the command never performs, so the
    // match keeps its review.
    std::fs::write(workspace.join("FS=x.txt"), "assignment\n").unwrap();
    assert_eq!(super::glob_file_matches("*.txt", context), None);
    std::fs::remove_file(workspace.join("FS=x.txt")).unwrap();

    assert_eq!(
        super::glob_file_matches("report.*", context),
        Some(vec!["report.txt".to_owned()])
    );
    std::fs::write(workspace.join("report.key"), "secret\n").unwrap();
    assert_eq!(super::glob_file_matches("report.*", context), None);

    let _ = std::fs::remove_dir_all(&root);
}
