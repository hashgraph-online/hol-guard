use super::{filters_unset_in, populated_gitlink, unused, GitQuery};
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Answers `check-attr -z filter` for each queried path, reporting `lfs` for
/// the paths in `filtered` and `unspecified` for the rest.
fn attribute_answers<'a>(
    filtered: &'static [&'static [u8]],
    batches: &'a Mutex<Vec<Vec<u8>>>,
) -> Box<GitQuery<'a>> {
    Box::new(
        move |arguments: &[&str], input: Option<Vec<u8>>, _root: Option<&Path>| {
            assert_eq!(arguments, ["check-attr", "-z", "--stdin", "filter"]);
            let input = input?;
            let mut output = Vec::new();
            for path in input
                .split(|byte| *byte == 0)
                .filter(|path| !path.is_empty())
            {
                output.extend_from_slice(path);
                output.extend_from_slice(b"\0filter\0");
                output.extend_from_slice(if filtered.contains(&path) {
                    b"lfs"
                } else {
                    b"unspecified"
                });
                output.push(0);
            }
            batches.lock().unwrap().push(input);
            Some(output)
        },
    )
}

fn soon() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

#[test]
fn a_filter_on_a_path_in_a_later_batch_is_found() {
    let batches = Mutex::new(Vec::new());
    let query = attribute_answers(&[b"bb"], &batches);
    // Each two-byte path costs 22 bytes, so a 30-byte batch holds one path.
    let paths = b"aa\0bb\0cc\0";
    assert_eq!(
        filters_unset_in(&*query, paths, Path::new("/"), soon(), 30),
        Some(false)
    );
    assert_eq!(
        batches.lock().unwrap().clone(),
        vec![b"aa\0".to_vec(), b"bb\0".to_vec()]
    );
}

#[test]
fn every_batch_is_inspected_when_no_path_has_a_filter() {
    let batches = Mutex::new(Vec::new());
    let query = attribute_answers(&[], &batches);
    let paths = b"aa\0bb\0cc\0";
    assert_eq!(
        filters_unset_in(&*query, paths, Path::new("/"), soon(), 30),
        Some(true)
    );
    assert_eq!(batches.lock().unwrap().clone().len(), 3);
}

#[test]
fn a_directory_with_its_own_git_entry_is_a_populated_gitlink() {
    let root = std::env::temp_dir().join(format!("guard-filter-gitlink-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("module/.git")).unwrap();
    std::fs::create_dir_all(root.join("plain")).unwrap();
    std::fs::write(root.join("file.txt"), "text\n").unwrap();
    let unpopulated = [
        root.join("plain"),
        root.join("file.txt"),
        root.join("missing"),
    ];
    assert_eq!(populated_gitlink(&unpopulated, soon()), Some(false));
    let populated = [root.join("file.txt"), root.join("module")];
    assert_eq!(populated_gitlink(&populated, soon()), Some(true));
    assert_eq!(populated_gitlink(&populated, Instant::now()), None);
    std::fs::remove_dir_all(&root).unwrap();
}

fn git_binary() -> std::path::PathBuf {
    std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|directory| directory.join(if cfg!(windows) { "git.exe" } else { "git" }))
        .find(|candidate| candidate.is_file())
        .unwrap()
}

#[test]
fn a_checked_out_gitlink_keeps_status_unproven_when_no_path_has_a_filter() {
    let root = std::env::temp_dir().join(format!("guard-filter-unused-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let (home, repository) = (root.join("home"), root.join("repository"));
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&repository).unwrap();
    let git = git_binary();
    let run = |arguments: &[&str]| {
        assert!(std::process::Command::new(&git)
            .env_remove("GIT_DIR")
            .env_remove("GIT_INDEX_FILE")
            .env("HOME", &home)
            .arg("-C")
            .arg(&repository)
            .args(arguments)
            .status()
            .unwrap()
            .success());
    };
    run(&["init", "--quiet"]);
    std::fs::write(repository.join("README.md"), "fixture\n").unwrap();
    run(&["add", "README.md"]);
    run(&[
        "update-index",
        "--add",
        "--cacheinfo",
        "160000,1111111111111111111111111111111111111111,module",
    ]);
    let inspect = || {
        unused(
            &git,
            &[],
            &repository,
            &home,
            None,
            soon(),
            &[],
            false,
            true,
        )
    };
    // The gitlink is recorded but not checked out: nothing has a filter.
    assert_eq!(inspect(), Some(true));
    // Checked out in place, status would open it under its own configuration.
    std::fs::create_dir_all(repository.join("module/.git")).unwrap();
    assert_eq!(inspect(), Some(false));
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn only_a_cached_index_comparison_leaves_the_working_tree_alone() {
    let words = |values: &[&str]| {
        values
            .iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
    };
    for operation in ["diff", "diff-index"] {
        assert!(!super::reads_working_tree(operation, &words(&["--cached"])));
        assert!(!super::reads_working_tree(
            operation,
            &words(&["--staged", "--stat"])
        ));
        assert!(super::reads_working_tree(operation, &words(&["--stat"])));
        assert!(!super::reads_working_tree(
            operation,
            &words(&["--stat", "-p", "--cached"])
        ));
        assert!(!super::reads_working_tree(
            operation,
            &words(&["-S", "needle", "--cached"])
        ));
        // An option that takes the next word turns `--cached` into its value.
        for consumer in ["-S", "-G", "-O", "-pS", "--output", "--diff-filter", "-U"] {
            assert!(
                super::reads_working_tree(operation, &words(&[consumer, "--cached"])),
                "{consumer} --cached"
            );
        }
        // After `--` the word is a path, not the option.
        assert!(super::reads_working_tree(
            operation,
            &words(&["--", "--cached"])
        ));
    }
    // `--no-index` compares two files on disk whatever else is spelled.
    assert!(super::reads_working_tree(
        "diff",
        &words(&["--no-index", "--cached"])
    ));
}
