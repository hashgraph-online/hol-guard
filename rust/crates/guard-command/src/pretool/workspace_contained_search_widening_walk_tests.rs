//! The hidden-entry walk skips the directories ripgrep skips.
use super::segment_widens;
use std::path::Path;

fn widens(command: &[&str], cwd: &Path) -> bool {
    let arguments: Vec<String> = command.iter().map(|word| (*word).to_owned()).collect();
    segment_widens(&arguments, cwd)
}

fn tree(name: &str, git: bool) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("hg-widening-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("src")).unwrap();
    if git {
        std::fs::create_dir_all(root.join(".git")).unwrap();
    }
    std::fs::write(root.join(".gitignore"), "node_modules/\n/build\n").unwrap();
    std::fs::write(root.join("src/app.ts"), "export const KEY = 1;\n").unwrap();
    for directory in ["node_modules/pkg", "build"] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
        std::fs::write(
            root.join(directory).join(".env.local.ts"),
            "KEY=SYNTHETIC_MARKER_ONLY\n",
        )
        .unwrap();
    }
    root
}

#[test]
fn an_ignored_dependency_tree_is_not_walked_inside_a_repository() {
    let root = tree("repo", true);
    assert!(!widens(&["-n", "KEY", "-g", "*.ts"], &root));
    // A glob naming the ignored directory reopens it.
    assert!(widens(&["-n", "KEY", "-g", "node_modules/**"], &root));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn ignore_files_outside_a_repository_do_not_prune_the_walk() {
    // ripgrep reads `.gitignore` only inside a git repository.
    let root = tree("plain", false);
    assert!(widens(&["-n", "KEY", "-g", "*.ts"], &root));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn plain_searches_and_exclusions_do_not_widen() {
    let root = tree("plain-search", true);
    assert!(!widens(&["-n", "KEY"], &root));
    assert!(!widens(&["--files", "-g", "!build"], &root));
    assert!(widens(&["-n", "--hidden", "KEY"], &root));
    let _ = std::fs::remove_dir_all(&root);
}
