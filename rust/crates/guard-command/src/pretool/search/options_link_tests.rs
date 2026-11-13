//! The glob walk follows links to directories inside the checkout, as the
//! shell's glob does.

use super::glob_meets_unsafe_link;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

fn scratch(label: &str) -> PathBuf {
    let root = std::fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!("hg-glob-links-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("outside")).unwrap();
    std::fs::create_dir_all(root.join("repo/deep/nested")).unwrap();
    std::fs::write(root.join("outside/secret.txt"), "TOKEN=fixture\n").unwrap();
    std::fs::write(root.join("repo/deep/nested/real.ts"), "export {};\n").unwrap();
    symlink("deep/nested", root.join("repo/lib")).unwrap();
    symlink(".", root.join("repo/deep/self")).unwrap();
    root
}

#[test]
fn a_glob_walks_through_a_directory_link_to_an_escaping_link() {
    let root = scratch("escape");
    let repo = root.join("repo");
    assert!(!glob_meets_unsafe_link("l*/*.ts", &repo));
    assert!(!glob_meets_unsafe_link("**/*.ts", &repo));
    symlink(
        root.join("outside/secret.txt"),
        repo.join("deep/nested/evil.ts"),
    )
    .unwrap();
    assert!(glob_meets_unsafe_link("l*/*.ts", &repo));
    assert!(glob_meets_unsafe_link("**/*.ts", &repo));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_directory_link_into_the_walk_does_not_loop_it() {
    let root = scratch("cycle");
    let repo = root.join("repo");
    symlink("..", repo.join("deep/nested/up")).unwrap();
    assert!(!glob_meets_unsafe_link("deep/**/*.ts", &repo));
    let _ = std::fs::remove_dir_all(&root);
}
