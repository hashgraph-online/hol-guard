use super::super::walk_exact;
use std::fs;
use std::path::Path;
use std::time::Duration;

fn write(root: &Path, relative: &str, text: &str) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn owned(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

/// A walk out of time still reads the files Git's search found, once.
#[test]
fn files_git_found_are_read_after_the_walk_stops() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(root, "deep/a/b/limits.py", "MERGE_LIMIT = 3\n");
    write(root, "other.py", "value = 1\n");
    let (terms, exact) = (owned(&["limit"]), owned(&["MERGE_LIMIT"]));
    let first = owned(&["deep/a/b/limits.py"]);
    let stopped = walk_exact(root, &terms, &[], &[], (&exact, &Vec::new), Duration::ZERO);
    assert!(stopped.files.is_empty());
    let read = walk_exact(
        root,
        &terms,
        &[],
        &[],
        (&exact, &|| first.clone()),
        Duration::ZERO,
    );
    assert_eq!(read.files, first);
    assert!(!read.complete);
    // With time, the walk passes over it instead of reading it again.
    let whole = walk_exact(
        root,
        &terms,
        &[],
        &[],
        (&exact, &|| first.clone()),
        Duration::from_secs(5),
    );
    assert_eq!(whole.files, first);
    assert_eq!(whole.checked, 2);
    assert_eq!(whole.exact, vec![("MERGE_LIMIT".to_owned(), 1)]);
}

/// A path from Git's search is read only if the walk would have read it.
#[test]
fn files_git_found_pass_the_walks_own_checks() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let text = "LIMIT = 3\n";
    let deep = "a/b/c/d/e/f/g/h/i/j/k/limit.py";
    for relative in [
        ".hidden/limit.py",
        "node_modules/limit.py",
        "skipped/limit.py",
        "inner/x/limit.py",
        "config/private_key_jwt.toml",
        "image.png",
        deep,
        "kept/limit.py",
    ] {
        write(root, relative, text);
    }
    write(root, ".gitignore", "skipped/\n");
    write(root, "inner/.gitignore", "x/\n");
    let mut first = owned(&[
        ".hidden/limit.py",
        "node_modules/limit.py",
        "skipped/limit.py",
        "inner/x/limit.py",
        "config/private_key_jwt.toml",
        "image.png",
        deep,
        "../limit.py",
        "/kept/limit.py",
        "kept//limit.py",
        "kept\\limit.py",
        "missing.py",
    ]);
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(root.join("kept/limit.py"), root.join("link.py")).unwrap();
        std::os::unix::fs::symlink(root.join("kept"), root.join("linked")).unwrap();
        first.extend(owned(&["link.py", "linked/limit.py"]));
    }
    let terms = owned(&["limit"]);
    let refused = walk_exact(
        root,
        &terms,
        &[],
        &[],
        (&[], &|| first.clone()),
        Duration::ZERO,
    );
    assert!(refused.files.is_empty(), "{:?}", refused.files);
    assert_eq!(refused.checked, 0);
    first.push("kept/limit.py".to_owned());
    let kept = walk_exact(
        root,
        &terms,
        &[],
        &[],
        (&[], &|| first.clone()),
        Duration::ZERO,
    );
    assert_eq!(kept.files, owned(&["kept/limit.py"]));
}
