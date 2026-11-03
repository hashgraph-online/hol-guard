use super::*;

fn app(root: &Path) -> PathBuf {
    let project = root.join("todo-app");
    fs::create_dir_all(project.join(".git")).unwrap();
    fs::create_dir_all(project.join("src/components")).unwrap();
    fs::create_dir_all(project.join("node_modules/lib")).unwrap();
    fs::create_dir_all(project.join("dist")).unwrap();
    fs::write(
        project.join("src/components/Header.tsx"),
        "export function Header() {\n  return <header className=\"bar\">Todos</header>;\n}\n",
    )
    .unwrap();
    fs::write(
        project.join("src/theme.css"),
        ".bar { color: #222; background-color: white; }\n",
    )
    .unwrap();
    fs::write(
        project.join("src/api.ts"),
        "export const load = () => fetch('/x');\n",
    )
    .unwrap();
    fs::write(project.join("node_modules/lib/header.js"), "header\n").unwrap();
    fs::write(project.join("dist/header.js"), "header\n").unwrap();
    fs::write(project.join("package-lock.json"), "{\"header\":1}\n").unwrap();
    fs::write(project.join("secrets.env"), "HEADER=1\n").unwrap();
    fs::write(project.join("generated.log"), "header\n").unwrap();
    fs::write(project.join(".gitignore"), "*.log\ncoverage/\n").unwrap();
    project
}

fn canonical() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = plain(fs::canonicalize(dir.path()).unwrap());
    (dir, path)
}

#[test]
fn prompt_words_skip_filler_and_keep_names() {
    assert_eq!(
        terms("Please add a color to the header"),
        ["color", "header"]
    );
    assert_eq!(terms("build a to-do app"), ["todo", "app"]);
    assert_eq!(
        terms("fix the user_profiles page"),
        ["userprofile", "user", "profile", "page"]
    );
    assert!(terms("make it so").is_empty());
}

#[test]
fn a_test_request_late_in_a_long_prompt_still_counts() {
    let long = "change header color background spacing border radius font size weight \
                alignment padding margin shadow and update the tests";
    let found = terms(long);
    assert_eq!(found.len(), MAX_TERMS);
    assert!(asks_for_tests(&found), "{found:?}");
    assert!(!asks_for_tests(&terms(
        "change header color background spacing"
    )));
}

#[test]
fn dotted_test_names_are_tests() {
    assert!(test_file("src/header.color_test.go"));
    assert!(test_file("src/Header.test.tsx"));
    assert!(test_file("tests/header.py"));
    assert!(!test_file("src/header.color.ts"));
    assert!(!test_file("src/contest.ts"));
}

#[test]
fn a_color_change_finds_the_header_and_its_styles_only() {
    let (_dir, root) = canonical();
    let project = app(&root);
    let found = candidates(
        &project,
        &terms("add a color to the header"),
        &[],
        WALK_BUDGET,
    );
    assert_eq!(found[0], "src/components/Header.tsx", "{found:?}");
    assert!(found.contains(&"src/theme.css".to_owned()), "{found:?}");
    for skipped in [
        "src/api.ts",
        "node_modules/lib/header.js",
        "dist/header.js",
        "package-lock.json",
        "generated.log",
    ] {
        assert!(
            !found.contains(&skipped.to_owned()),
            "{skipped} in {found:?}"
        );
    }
}

#[test]
fn tests_that_quote_the_request_give_way_to_the_source() {
    let (_dir, root) = canonical();
    let project = app(&root);
    fs::create_dir_all(project.join("src/components/__tests__")).unwrap();
    fs::create_dir_all(project.join("tests")).unwrap();
    let quoted = "header color header color header color\n";
    for test in [
        "src/components/Header.test.tsx",
        "src/components/__tests__/header.tsx",
        "tests/header_color.py",
        "src/header_color_test.go",
        "src/header_tests.rs",
    ] {
        fs::write(project.join(test), quoted).unwrap();
    }
    let found = candidates(
        &project,
        &terms("add a color to the header"),
        &[],
        WALK_BUDGET,
    );
    assert_eq!(
        found,
        ["src/components/Header.tsx", "src/theme.css"],
        "no test files when the source matched"
    );
    let asked = candidates(
        &project,
        &terms("fix the header color tests"),
        &[],
        WALK_BUDGET,
    );
    assert!(
        asked.contains(&"src/components/Header.test.tsx".to_owned()),
        "{asked:?}"
    );
    fs::remove_file(project.join("src/components/Header.tsx")).unwrap();
    fs::remove_file(project.join("src/theme.css")).unwrap();
    let only_tests = candidates(
        &project,
        &terms("add a color to the header"),
        &[],
        WALK_BUDGET,
    );
    assert!(
        only_tests.contains(&"tests/header_color.py".to_owned()),
        "tests remain when nothing else matched: {only_tests:?}"
    );
}

#[test]
fn no_time_left_means_no_walk() {
    let (_dir, root) = canonical();
    let project = app(&root);
    assert!(candidates(
        &project,
        &terms("add a color to the header"),
        &[],
        Duration::ZERO
    )
    .is_empty());
}

#[test]
fn an_empty_folder_or_unrelated_prompt_adds_nothing() {
    let (_dir, root) = canonical();
    let empty = root.join("fresh");
    fs::create_dir(&empty).unwrap();
    assert!(candidates(&empty, &terms("build a to-do app"), &[], WALK_BUDGET).is_empty());
    let project = app(&root);
    assert!(candidates(
        &project,
        &terms("write a haiku about winter"),
        &[],
        WALK_BUDGET
    )
    .is_empty());
}

#[test]
fn files_git_ignores_never_become_candidates() {
    let (_dir, root) = canonical();
    let project = app(&root);
    fs::create_dir_all(project.join("src/private")).unwrap();
    fs::create_dir_all(project.join("src/notes/local")).unwrap();
    fs::write(project.join("src/private/header-notes.md"), "header\n").unwrap();
    fs::write(project.join("src/notes/header.md"), "header\n").unwrap();
    fs::write(project.join("src/notes/local/header.md"), "header\n").unwrap();
    fs::write(project.join("src/notes/.gitignore"), "local/\n").unwrap();
    fs::write(project.join(".gitignore"), "*.log\nsrc/private/\n").unwrap();
    let found = candidates(&project, &terms("the header"), &[], WALK_BUDGET);
    assert!(
        found.contains(&"src/notes/header.md".to_owned()),
        "{found:?}"
    );
    for kept_out in ["src/private/header-notes.md", "src/notes/local/header.md"] {
        assert!(
            !found.contains(&kept_out.to_owned()),
            "{kept_out} in {found:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn a_linked_folder_is_never_walked() {
    let (_dir, root) = canonical();
    let project = app(&root);
    let outside = root.join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("header.ts"), "header\n").unwrap();
    std::os::unix::fs::symlink(&outside, project.join("linked")).unwrap();
    let found = candidates(&project, &terms("the header"), &[], WALK_BUDGET);
    assert!(
        found.iter().all(|path| !path.starts_with("linked")),
        "{found:?}"
    );
}

#[test]
fn the_project_is_the_enclosing_repository_never_home_or_guard() {
    let (_dir, root) = canonical();
    let home = root.join("home");
    let project = app(&home);
    let guard = home.join(".hol-guard");
    fs::create_dir_all(&guard).unwrap();
    let nested = project.join("src/components");
    assert_eq!(project_root(&nested, &home, &guard), Some(project.clone()));
    let loose = home.join("notes/ideas");
    fs::create_dir_all(&loose).unwrap();
    assert_eq!(project_root(&loose, &home, &guard), Some(loose));
    assert_eq!(
        project_root(&home, &home, &guard),
        None,
        "never the home folder"
    );
    assert_eq!(
        project_root(&guard, &home, &guard),
        None,
        "never Guard's own files"
    );
    assert_eq!(project_root(&root, &home, &guard), None, "never above home");
}

#[test]
fn quoted_text_is_kept_as_a_phrase() {
    assert_eq!(
        phrases(
            "The confirm dialog's cancel button should say \"Never mind\" instead of \"Cancel\"."
        ),
        ["never mind", "cancel"]
    );
    assert_eq!(
        phrases("rename \u{201c}Try again\u{201d} to `Reload` and 'Retry now'"),
        ["try again", "reload", "retry now"]
    );
    assert!(phrases("don't change the user's \"ok\" label").is_empty());
}

/// A big settings file that says the request's everyday words many times
/// must not outrank the small file the request names. The settings file
/// never says "never mind" as one phrase, so only the words repeat.
#[test]
fn rare_words_and_quoted_text_outrank_common_words_repeated() {
    let (_dir, root) = canonical();
    let project = root.join("dash");
    fs::create_dir_all(project.join(".git")).unwrap();
    fs::create_dir_all(project.join("src")).unwrap();
    for n in 0..20 {
        fs::write(
            project.join(format!("src/panel-{n}.tsx")),
            "// Never say instead; mind the default button.\nexport const Panel = () => <button />;\n",
        )
        .unwrap();
    }
    fs::write(
        project.join("src/settings-workspace.tsx"),
        "default button: say mind, never instead, cancel dialog\n".repeat(8),
    )
    .unwrap();
    fs::write(
        project.join("src/confirm-dialog.tsx"),
        "export function ConfirmDialog({ cancelLabel = \"Cancel\" }) {\n  return <button>{cancelLabel}</button>;\n}\n",
    )
    .unwrap();
    let prompt = "The confirm dialog's default cancel button should say \"Never mind\" instead of \"Cancel\".";
    let found = candidates(&project, &terms(prompt), &phrases(prompt), WALK_BUDGET);
    assert_eq!(
        found.first().map(String::as_str),
        Some("src/confirm-dialog.tsx"),
        "{found:?}"
    );
}

#[test]
fn a_file_with_only_the_quoted_text_still_counts() {
    let (_dir, root) = canonical();
    let project = root.join("quoted");
    fs::create_dir_all(project.join("src")).unwrap();
    fs::write(
        project.join("src/strings.ts"),
        "export const LABEL = 'zq';\n// Ok, got it\n",
    )
    .unwrap();
    let found = candidates(&project, &[], &["ok, got it".to_owned()], WALK_BUDGET);
    assert_eq!(found, ["src/strings.ts"]);
}

#[test]
fn unmatched_quotes_are_scanned_in_one_pass() {
    let prompt = " \u{201c}".repeat(50_000);
    let started = Instant::now();
    assert!(phrases(&prompt).is_empty());
    assert!(started.elapsed() < Duration::from_secs(1));
    let far = format!("\"{}\" and \"keep this\"", "x".repeat(200));
    assert_eq!(phrases(&far), ["keep this"]);
}
