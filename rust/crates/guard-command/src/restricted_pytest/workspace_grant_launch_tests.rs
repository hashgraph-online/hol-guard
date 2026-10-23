use super::*;
use std::os::unix::fs::symlink;

fn directory(tag: &str) -> PathBuf {
    let nonce = crate::unique_nanos::unique_nanos();
    let root =
        std::env::temp_dir().join(format!("guard-launch-{tag}-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    root.canonicalize().unwrap()
}

#[test]
fn links_come_in_the_order_they_are_followed() {
    let root = directory("order");
    std::fs::create_dir_all(root.join("real")).unwrap();
    std::fs::create_dir_all(root.join("via")).unwrap();
    std::fs::write(root.join("real/tool"), "data").unwrap();
    symlink("../real", root.join("via/dir")).unwrap();
    symlink("dir/tool", root.join("via/entry")).unwrap();
    // `via/entry` leads to `via/dir/tool`, and `via/dir` leads to a directory.
    assert_eq!(
        links(&root.join("via/entry")),
        Some(vec![
            (root.join("via/entry"), false),
            (root.join("via/dir"), true)
        ])
    );
    assert_eq!(
        links(&root.join("via/dir/tool")),
        Some(vec![(root.join("via/dir"), true)])
    );
    assert_eq!(links(&root.join("real/tool")), Some(vec![]));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_loop_of_links_or_a_relative_path_is_not_resolved() {
    let root = directory("loop");
    symlink("second", root.join("first")).unwrap();
    symlink("first", root.join("second")).unwrap();
    assert_eq!(links(&root.join("first")), None);
    assert_eq!(links(Path::new("relative/tool")), None);
    assert_eq!(links(&root.join("missing")), None);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_parent_step_through_a_link_leaves_the_directory_it_leads_to() {
    let root = directory("parent");
    std::fs::create_dir_all(root.join("real/deep")).unwrap();
    std::fs::write(root.join("real/tool"), "data").unwrap();
    symlink("real/deep", root.join("entry")).unwrap();
    // `entry/../tool` is `real/tool`: the parent of what `entry` leads to.
    assert_eq!(
        links(&root.join("entry/../tool")),
        Some(vec![(root.join("entry"), true)])
    );
    let _ = std::fs::remove_dir_all(&root);
}
