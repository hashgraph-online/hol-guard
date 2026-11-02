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
fn a_color_change_finds_the_header_and_its_styles_only() {
    let (_dir, root) = canonical();
    let project = app(&root);
    let found = candidates(&project, &terms("add a color to the header"));
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
fn an_empty_folder_or_unrelated_prompt_adds_nothing() {
    let (_dir, root) = canonical();
    let empty = root.join("fresh");
    fs::create_dir(&empty).unwrap();
    assert!(candidates(&empty, &terms("build a to-do app")).is_empty());
    let project = app(&root);
    assert!(candidates(&project, &terms("write a haiku about winter")).is_empty());
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
    let found = candidates(&project, &terms("the header"));
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
    let found = candidates(&project, &terms("the header"));
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
