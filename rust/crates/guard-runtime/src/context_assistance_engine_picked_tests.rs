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
