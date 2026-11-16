//! A search pattern whose glob characters are all quoted is matching text
//! the shell hands over as written. Only an unquoted one can still expand
//! into a credential file name beside it.
use crate::pretool::listing_reads::literal_words;

fn parsed(command: &str) -> crate::CanonicalCommandV1 {
    crate::parse_command(&crate::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })
    .unwrap()
}

#[test]
fn quoted_words_are_read_as_written() {
    assert_eq!(
        literal_words(r#"grep -o "FAILED tests/[^ ]*" notes.md"#),
        ["grep", "-o", "FAILED tests/[^ ]*", "notes.md"]
    );
    assert_eq!(literal_words("rg 's[a-z]*' src"), ["rg", "s[a-z]*", "src"]);
    assert_eq!(
        literal_words("grep .env{,.local} notes.md"),
        ["grep", "notes.md"]
    );
    // The same text unquoted elsewhere in the command could be either one.
    assert!(!literal_words(r#"grep "a*" a* notes.md"#).contains(&"a*".to_owned()));
    // The shell rewrites these before the program sees them.
    for text in [
        r#"grep "$P*" notes.md"#,
        "grep $P'*' notes.md",
        "grep `p`'*' notes.md",
        r"grep a\* notes.md",
        "grep 'a* notes.md",
        "grep 'a*' <<EOF\nauth\nEOF",
    ] {
        assert!(literal_words(text).is_empty(), "{text}");
    }
}

#[test]
fn a_quoted_pattern_is_not_a_file_name_but_an_unquoted_one_is() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/grep-quoted-pattern")
        .join(std::process::id().to_string());
    let repo = root.join("work/app");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(repo.join("notes.md"), "FAILED tests/a.py\n").unwrap();
    std::fs::write(repo.join("auth.json"), "{}\n").unwrap();
    let repo = crate::runtime_read_paths::canonicalize_text(&repo).unwrap();
    let context = crate::pretool::PathContext {
        cwd: repo.to_str(),
        ripgrep_config_absent: true,
        ..Default::default()
    };
    for (command, allowed) in [
        (r#"grep "a*" notes.md"#, true),
        ("grep 'a*' notes.md", true),
        (r#"grep -o "FAILED tests/[^ ]*" notes.md"#, true),
        (r#"grep -e "s[a-z]*" notes.md"#, true),
        (r#"rg "s[a-z]*" notes.md"#, true),
        ("grep a* notes.md", false),
        (r#"grep "a"* notes.md"#, false),
        (r#"grep "a*" a* notes.md"#, false),
        ("grep -e s[a-z]* notes.md", false),
        ("rg s[a-z]* notes.md", false),
        // The option reader hands over only the part after an attached option.
        (r#"grep -e"s[a-z]*" notes.md"#, true),
        (r#"grep --regexp="s[a-z]*" notes.md"#, true),
        (r#"rg --regexp="s[a-z]*" notes.md"#, true),
        ("grep -es[a-z]* notes.md", false),
        // Bash expands a brace list into separate words, the second one a file.
        ("grep .env{,.local} notes.md", false),
        ("rg .env{,.local} notes.md", false),
        ("grep --regexp=\".env*\" -e .env* notes.md", false),
    ] {
        let model = parsed(command);
        let segment = &model.segments[0];
        let proven = if command.starts_with("rg") {
            super::super::super::safe_rg_segment(&model, segment, context)
        } else {
            super::super::safe_grep_segment(&model, segment, context)
        };
        assert_eq!(proven, allowed, "{command}");
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_quoted_pattern_filters_piped_text() {
    for (command, allowed) in [
        (r#"cat notes.md | grep "a*""#, true),
        (r#"cat notes.md | grep -o "FAILED tests/[^ ]*""#, true),
        ("cat notes.md | grep a*", false),
        ("cat notes.md | grep .env{,.local}", false),
        ("cat notes.md | grep --regexp=\".env*\" -e .env*", false),
        ("cat notes.md | grep -e .env* -e \".env*\"", false),
    ] {
        let model = parsed(command);
        let segment = &model.segments[1];
        assert_eq!(
            super::super::safe_stdin_arguments(&segment.arguments, &literal_words(&segment.text)),
            allowed,
            "{command}"
        );
        assert_eq!(
            super::super::super::safe_rg_stdin_arguments(
                &segment.arguments,
                &literal_words(&segment.text.replacen("grep", "rg", 1)),
            ),
            allowed,
            "{command}"
        );
    }
}
