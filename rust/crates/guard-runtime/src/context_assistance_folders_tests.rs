use super::*;
use std::path::Path;

fn tree(root: &Path) -> PathBuf {
    let project = root.join("my-app");
    fs::create_dir_all(project.join(".git")).unwrap();
    fs::create_dir(project.join("docs")).unwrap();
    fs::create_dir(project.join("node_modules")).unwrap();
    fs::create_dir(project.join("secrets")).unwrap();
    fs::create_dir(project.join("auth-service")).unwrap();
    fs::write(project.join("README.md"), "# My app\n").unwrap();
    fs::write(project.join("AGENTS.md"), "Rules\n").unwrap();
    fs::write(project.join("docs/design.md"), "Design\n").unwrap();
    fs::write(project.join(".env"), "KEY=1\n").unwrap();
    fs::write(project.join("logo.png"), b"\x89PNG").unwrap();
    fs::write(
        project.join("big.md"),
        "x".repeat(MAX_FILE_BYTES as usize + 1),
    )
    .unwrap();
    fs::write(project.join("server.pem"), "k\n").unwrap();
    fs::write(project.join("tokenizer.py"), "print(1)\n").unwrap();
    fs::create_dir(root.join("notes")).unwrap();
    fs::create_dir(root.join(".hidden")).unwrap();
    fs::create_dir(root.join(".ssh")).unwrap();
    fs::create_dir(root.join("prod-secrets")).unwrap();
    project
}

fn root() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let canonical = plain(fs::canonicalize(dir.path()).unwrap());
    (dir, canonical)
}

fn code(result: Result<Value, String>) -> String {
    result.unwrap_err()
}

fn names(listing: &Value, key: &str, field: &str) -> Vec<String> {
    listing[key]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row[field].as_str().unwrap().to_owned())
        .collect()
}

#[cfg(unix)]
fn link(target: &Path, at: &Path) {
    std::os::unix::fs::symlink(target, at).unwrap();
}

#[test]
fn folders_lists_only_plain_subfolders_and_marks_projects() {
    let (_dir, root) = root();
    tree(&root);
    let listing = browse(&json!({"path": root})).unwrap();
    assert_eq!(listing["schema"], SCHEMA);
    assert_eq!(listing["path"], json!(root));
    let projects: Vec<(String, bool)> = listing["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                row["name"].as_str().unwrap().into(),
                row["project"].as_bool().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        projects,
        [("my-app".into(), true), ("notes".into(), false)],
        "hidden folders and credential stores are left out"
    );
    let shown = browse(&json!({"path": root, "hidden": true})).unwrap();
    assert_eq!(
        names(&shown, "entries", "name"),
        [".hidden", "my-app", "notes"]
    );
    assert_eq!(listing["places"][0]["kind"], "home");
    assert!(!listing["roots"].as_array().unwrap().is_empty());
}

#[test]
fn folders_rejects_invalid_input() {
    for (input, expected) in [
        (json!({"path": "relative/dir"}), "not_absolute"),
        (json!({"path": 7}), "input_invalid"),
        (json!({"mode": "other"}), "input_invalid"),
        (json!({"mode": "files"}), "input_invalid"),
        (json!({"path": "/", "extra": true}), "input_invalid"),
        (json!([]), "input_invalid"),
    ] {
        assert_eq!(code(browse(&input)), fail(expected), "{input}");
    }
}

#[test]
fn folders_reports_missing_and_file_paths() {
    let (_dir, root) = root();
    assert_eq!(
        code(browse(&json!({"path": root.join("nope")}))),
        fail("not_found")
    );
    fs::write(root.join("file.txt"), "x").unwrap();
    assert_eq!(
        code(browse(&json!({"path": root.join("file.txt")}))),
        fail("not_directory")
    );
}

#[test]
fn files_offer_only_what_a_source_grant_accepts() {
    let (_dir, root) = root();
    let project = tree(&root);
    let listing = browse(&json!({"mode": "files", "workspace": project})).unwrap();
    assert_eq!(listing["workspace"], json!(project));
    assert_eq!(
        names(&listing, "entries", "relative"),
        ["auth-service", "docs"],
        "a credential store is hidden, a feature folder named like one is not"
    );
    let rows: Vec<(String, bool, Value)> = listing["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                row["relative"].as_str().unwrap().into(),
                row["available"].as_bool().unwrap(),
                row["reason"].clone(),
            )
        })
        .collect();
    // `.env`, `server.pem` and `logo.png` are refused by the grant's read
    // screen, so they are not offered at all.
    assert_eq!(
        rows,
        [
            ("AGENTS.md".into(), true, Value::Null),
            ("big.md".into(), false, json!("too_large")),
            ("README.md".into(), true, Value::Null),
            ("tokenizer.py".into(), true, Value::Null),
        ]
    );
    assert_eq!(
        names(&listing, "suggested", "relative"),
        ["README.md", "AGENTS.md", "docs/design.md"]
    );
    let nested = browse(&json!({"mode": "files", "workspace": project, "path": "docs"})).unwrap();
    assert_eq!(names(&nested, "files", "relative"), ["docs/design.md"]);
    assert_eq!(nested["suggested"], json!([]));
}

#[test]
fn files_stay_inside_the_workspace() {
    let (_dir, root) = root();
    let project = tree(&root);
    for path in ["../outside", "docs/../..", "C:\\x", "a/./b", "docs//x"] {
        let result = browse(&json!({"mode": "files", "workspace": project, "path": path}));
        assert_eq!(code(result), fail("input_invalid"), "{path}");
    }
    let missing = browse(&json!({"mode": "files", "workspace": project, "path": "nope"}));
    assert_eq!(code(missing), fail("not_found"));
}

#[cfg(unix)]
#[test]
fn a_linked_folder_inside_the_project_is_never_followed() {
    let (_dir, root) = root();
    let project = tree(&root);
    let outside = root.join("outside");
    fs::create_dir_all(outside.join("deep")).unwrap();
    fs::write(outside.join("deep/notes.md"), "x\n").unwrap();
    link(&outside, &project.join("linked"));
    let top = browse(&json!({"mode": "files", "workspace": project})).unwrap();
    assert!(!names(&top, "entries", "relative").contains(&"linked".to_owned()));
    for path in ["linked", "linked/deep"] {
        let result = browse(&json!({"mode": "files", "workspace": project, "path": path}));
        assert_eq!(code(result), fail("not_found"), "{path}");
    }
}

#[cfg(unix)]
#[test]
fn linked_docs_and_notes_are_not_suggested() {
    let (_dir, root) = root();
    let project = root.join("app");
    fs::create_dir(&project).unwrap();
    let elsewhere = root.join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    fs::write(elsewhere.join("README.md"), "x\n").unwrap();
    fs::write(elsewhere.join("plan.md"), "x\n").unwrap();
    link(&elsewhere, &project.join("docs"));
    link(&elsewhere.join("README.md"), &project.join("README.md"));
    let listing = browse(&json!({"mode": "files", "workspace": project})).unwrap();
    assert_eq!(listing["suggested"], json!([]));
    assert!(listing["files"].as_array().unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn folders_resolve_a_linked_start_and_hide_linked_children() {
    let (_dir, root) = root();
    fs::create_dir(root.join("real")).unwrap();
    link(&root.join("real"), &root.join("link"));
    let through = browse(&json!({"path": root.join("link")})).unwrap();
    assert_eq!(through["path"], json!(root.join("real")));
    let listing = browse(&json!({"path": root})).unwrap();
    assert_eq!(names(&listing, "entries", "name"), ["real"]);
}

#[test]
fn a_huge_folder_is_listed_in_part() {
    let (_dir, root) = root();
    for index in 0..MAX_ENTRIES + 5 {
        fs::create_dir(root.join(format!("d{index:04}"))).unwrap();
    }
    let listing = browse(&json!({"path": root})).unwrap();
    assert_eq!(listing["entries"].as_array().unwrap().len(), MAX_ENTRIES);
    assert_eq!(listing["truncated"], true);
}

#[cfg(windows)]
#[test]
fn windows_paths_are_shown_without_the_verbatim_prefix() {
    assert_eq!(
        plain(PathBuf::from(r"\\?\C:\Users\me")),
        PathBuf::from(r"C:\Users\me")
    );
    assert_eq!(
        plain(PathBuf::from(r"\\?\UNC\server\share\x")),
        PathBuf::from(r"\\server\share\x")
    );
    let (_dir, root) = root();
    let listing = browse(&json!({"path": root})).unwrap();
    assert!(!listing["path"].as_str().unwrap().starts_with(r"\\?\"));
    assert!(listing["roots"][0]["path"]
        .as_str()
        .unwrap()
        .ends_with(":\\"));
}
