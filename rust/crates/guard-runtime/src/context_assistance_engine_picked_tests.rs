use super::*;
use std::path::Path;

fn folder(workspace: &Path, sources: &[&str]) -> Folder {
    Folder {
        workspace: workspace.to_path_buf(),
        sources: sources.iter().map(|source| (*source).to_owned()).collect(),
        notes_read: false,
        notes_propose: false,
    }
}

#[test]
fn a_gone_folder_ends_its_pick_and_a_gone_file_leaves_it() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("todo-app");
    std::fs::create_dir_all(project.join("src")).unwrap();
    std::fs::write(project.join("README.md"), "todo\n").unwrap();
    std::fs::write(project.join("src/app.ts"), "app\n").unwrap();
    let gone = dir.path().join("deleted-project");
    let restored = restorable(vec![
        folder(&project, &["README.md", "src/app.ts", "src/removed.ts"]),
        folder(&gone, &["README.md"]),
    ]);
    assert_eq!(restored.len(), 1, "{restored:?}");
    assert_eq!(
        restored[&project].sources,
        ["README.md", "src/app.ts"],
        "the folder comes back without the file that is gone"
    );
}

#[test]
fn a_folder_picked_without_files_still_comes_back() {
    let dir = tempfile::tempdir().unwrap();
    let restored = restorable(vec![folder(dir.path(), &[])]);
    assert!(restored[dir.path()].sources.is_empty());
}

#[cfg(unix)]
#[test]
fn a_folder_that_cannot_be_checked_keeps_its_pick() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let locked = dir.path().join("locked");
    let project = locked.join("todo-app");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    let readable = std::fs::metadata(&project).is_ok();
    let restored = restorable(vec![folder(&project, &["README.md"])]);
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
    if readable {
        return; // permissions do not apply to this user
    }
    assert_eq!(restored[&project].sources, ["README.md"]);
}

#[test]
fn a_new_pick_replaces_a_saved_folder_that_did_not_come_back() {
    let mut picks: Picks = (0..picked::MAX_FOLDERS)
        .map(|index| {
            let path = PathBuf::from(format!("/work/{index}"));
            (path.clone(), folder(&path, &[]))
        })
        .collect();
    let idle = Path::new("/work/3");
    let fresh = Path::new("/work/new");
    assert!(make_room(&mut picks, fresh, |path| path != idle));
    assert_eq!(picks.len(), picked::MAX_FOLDERS - 1);
    assert!(!picks.contains_key(idle));
    let mut full = picks.clone();
    full.insert(fresh.to_path_buf(), folder(fresh, &[]));
    assert!(
        !make_room(&mut full, Path::new("/work/other"), |_| true),
        "never drops a folder that is in use"
    );
    assert!(
        make_room(&mut full, Path::new("/work/0"), |_| true),
        "a pick already saved is updated in place"
    );
    assert_eq!(full.len(), picked::MAX_FOLDERS);
}
