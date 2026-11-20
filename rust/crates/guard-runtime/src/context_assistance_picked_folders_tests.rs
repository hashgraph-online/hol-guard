use super::*;

fn home() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("guard-home");
    fs::create_dir(&home).unwrap();
    (dir, home)
}

fn folder(name: &str) -> Folder {
    Folder {
        workspace: PathBuf::from(format!("/work/{name}")),
        sources: vec!["README.md".into(), "src/app.ts".into()],
        notes_read: true,
        notes_propose: false,
    }
}

#[test]
fn nothing_picked_yet_reads_as_an_empty_list() {
    let (_dir, home) = home();
    assert_eq!(load(&home).unwrap(), Vec::<Folder>::new());
    assert!(
        !home.join("context-assistance").exists(),
        "a read creates nothing"
    );
}

#[test]
fn picked_folders_come_back_after_a_restart() {
    let (_dir, home) = home();
    let folders = vec![folder("todo-app"), folder("shop")];
    save(&home, &folders).unwrap();
    assert_eq!(load(&home).unwrap(), folders);
    save(&home, &[]).unwrap();
    assert_eq!(load(&home).unwrap(), Vec::<Folder>::new());
}

#[test]
fn the_record_holds_paths_only() {
    let (_dir, home) = home();
    save(&home, &[folder("todo-app")]).unwrap();
    let text = fs::read_to_string(home.join("context-assistance").join(FILE)).unwrap();
    let value: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        value,
        json!({"schema": SCHEMA, "folders": [{"workspace": "/work/todo-app",
            "sources": ["README.md", "src/app.ts"], "notes_read": true, "notes_propose": false}]})
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(home.join("context-assistance").join(FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "private to the user");
    }
}

#[test]
fn a_bad_or_oversized_record_is_refused() {
    let (_dir, home) = home();
    let mut relative = folder("todo-app");
    relative.workspace = PathBuf::from("todo-app");
    assert!(save(&home, &[relative]).is_err());
    let many: Vec<Folder> = (0..=MAX_FOLDERS)
        .map(|index| folder(&index.to_string()))
        .collect();
    assert!(save(&home, &many).is_err());
    save(&home, &[folder("todo-app")]).unwrap();
    let path = home.join("context-assistance").join(FILE);
    let text = fs::read_to_string(&path)
        .unwrap()
        .replace(SCHEMA, "other.v1");
    persist_private_bytes(&path, text.as_bytes(), LIMIT, "cigar_picked_folders", &home).unwrap();
    assert!(load(&home).is_err());
}
