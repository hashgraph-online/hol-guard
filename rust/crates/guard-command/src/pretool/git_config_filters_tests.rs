use super::{filters_unset_in, populated_gitlink, GitQuery};
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
