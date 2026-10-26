use super::omp_bash_cwd::{resolve, BashCwd};
use serde_json::json;
use std::path::{Path, PathBuf};

fn cwd(session: &Path, target: &Path) -> BashCwd {
    resolve(
        &json!({"tool_input": {"command": "git status", "cwd": target.to_str().unwrap()}}),
        None,
        session.to_str(),
    )
}

/// A session directory holding a primary checkout, with one linked worktree
/// registered outside it.
fn layout(name: &str) -> (PathBuf, PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!("guard-omp-cwd-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let (session, tree) = (root.join("org"), root.join("tree"));
    let admin = session.join("app/.git/worktrees/tree");
    std::fs::create_dir_all(&admin).unwrap();
    std::fs::create_dir_all(&tree).unwrap();
    let (session, tree) = (
        session.canonicalize().unwrap(),
        tree.canonicalize().unwrap(),
    );
    let admin = admin.canonicalize().unwrap();
    std::fs::write(admin.join("commondir"), "../..\n").unwrap();
    std::fs::write(
        admin.join("gitdir"),
        format!("{}\n", tree.join(".git").display()),
    )
    .unwrap();
    std::fs::write(tree.join(".git"), format!("gitdir: {}\n", admin.display())).unwrap();
    (root, session, tree)
}

#[test]
fn a_linked_worktree_of_a_session_repository_is_judged_where_it_runs() {
    let (root, session, tree) = layout("linked");
    assert!(
        matches!(cwd(&session, &tree), BashCwd::Within(directory) if Path::new(&directory) == tree)
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_copied_worktree_git_file_is_judged_as_a_leading_cd() {
    let (root, session, tree) = layout("forged");
    // The copy names the same registry entry, whose `gitdir` backlink still
    // names the real worktree.
    let forged = root.join("forged");
    std::fs::create_dir_all(&forged).unwrap();
    std::fs::copy(tree.join(".git"), forged.join(".git")).unwrap();
    let forged = forged.canonicalize().unwrap();
    assert!(
        matches!(cwd(&session, &forged), BashCwd::Outside(directory) if Path::new(&directory) == forged)
    );
    let _ = std::fs::remove_dir_all(&root);
}
