use std::fs;
use std::path::{Path, PathBuf};

use serde_json::json;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use super::{
    classify_path_class, inspect_aibom_source_path, source_of_truth_metadata_from_inspection,
};

fn write(path: &Path, body: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("parent directory");
    }
    fs::write(path, body).expect("write");
}

fn hex_digest(body: &str) -> String {
    hex::encode(Sha256::digest(body.as_bytes()))
}

fn roots(home: &Path) -> Vec<PathBuf> {
    vec![home.to_path_buf()]
}

#[test]
fn a_plain_file_inside_the_safe_roots_is_a_valid_copy() {
    let home = TempDir::new().expect("home");
    let file = home.path().join("notes.md");
    write(&file, "alpha");

    let inspection =
        inspect_aibom_source_path(&file, &roots(home.path()), home.path(), None, false);

    assert_eq!(inspection.link_kind, "copy");
    assert_eq!(inspection.validation_state, "valid");
    assert_eq!(
        inspection.target_content_hash.as_deref(),
        Some(hex_digest("alpha").as_str())
    );
    assert!(inspection.hop_fingerprints.is_empty());
}

#[test]
fn a_path_that_is_neither_a_file_nor_a_link_is_missing() {
    let home = TempDir::new().expect("home");
    let missing = home.path().join("gone.md");

    let inspection =
        inspect_aibom_source_path(&missing, &roots(home.path()), home.path(), None, false);

    assert_eq!(inspection.validation_state, "missing");
    assert_eq!(inspection.link_kind, "copy");
    assert!(inspection.target_content_hash.is_none());
}

#[test]
fn a_file_outside_the_safe_roots_is_escape_blocked() {
    let home = TempDir::new().expect("home");
    let elsewhere = TempDir::new().expect("elsewhere");
    let file = elsewhere.path().join("notes.md");
    write(&file, "alpha");

    let inspection =
        inspect_aibom_source_path(&file, &roots(home.path()), home.path(), None, false);

    assert_eq!(inspection.validation_state, "escape_blocked");
    assert!(inspection.target_content_hash.is_none());
}

#[test]
fn a_path_under_a_harness_config_directory_is_a_config_root() {
    let home = TempDir::new().expect("home");
    let elsewhere = TempDir::new().expect("elsewhere");
    let file = elsewhere.path().join(".codex/hooks/run.sh");
    write(&file, "echo");

    assert_eq!(classify_path_class(&file, home.path(), None), "config_root");
}

#[test]
fn a_workspace_path_outranks_the_home_directory() {
    let home = TempDir::new().expect("home");
    let workspace = home.path().join("code/app");
    let file = workspace.join("AGENTS.md");
    write(&file, "alpha");

    assert_eq!(
        classify_path_class(&file, home.path(), Some(&workspace)),
        "workspace_relative"
    );
    assert_eq!(
        classify_path_class(&file, home.path(), None),
        "home_relative"
    );
}

#[test]
fn a_path_under_no_known_root_is_unknown() {
    let home = TempDir::new().expect("home");

    assert_eq!(
        classify_path_class(Path::new("/zz-no-such-root/app.md"), home.path(), None),
        "unknown"
    );
}

#[test]
fn the_metadata_carries_the_fingerprints_and_never_a_raw_path() {
    let home = TempDir::new().expect("home");
    let file = home.path().join("notes.md");
    write(&file, "alpha");

    let inspection =
        inspect_aibom_source_path(&file, &roots(home.path()), home.path(), None, false);
    let metadata = source_of_truth_metadata_from_inspection(&inspection, "codex:skill:abc");

    assert_eq!(metadata["sourceLinkId"], json!("codex:skill:abc"));
    assert_eq!(metadata["linkKind"], json!("copy"));
    assert_eq!(metadata["validationState"], json!("valid"));
    assert_eq!(
        metadata["redactionSummary"]["rawPathsIncluded"],
        json!(false)
    );
    assert_eq!(
        metadata["redactionSummary"]["pathFingerprint"],
        json!(inspection.path_fingerprint)
    );
    assert_eq!(
        metadata["metadata"]["targetContentHash"],
        json!(inspection.target_content_hash)
    );
    let rendered = metadata.to_string();
    assert!(!rendered.contains("notes.md"), "{rendered}");
}

#[cfg(unix)]
mod links {
    use super::*;
    use guard_command::inventory_fingerprints::fingerprint_mapping;

    fn link(target: &Path, at: &Path) {
        if let Some(parent) = at.parent() {
            fs::create_dir_all(parent).expect("parent directory");
        }
        std::os::unix::fs::symlink(target, at).expect("symlink");
    }

    #[test]
    fn a_symlink_to_a_file_inside_the_safe_roots_is_valid() {
        let home = TempDir::new().expect("home");
        let target = home.path().join("real.md");
        write(&target, "alpha");
        let source = home.path().join("link.md");
        link(&target, &source);

        let inspection =
            inspect_aibom_source_path(&source, &roots(home.path()), home.path(), None, false);

        assert_eq!(inspection.link_kind, "symlink");
        assert_eq!(inspection.validation_state, "valid");
        assert_eq!(
            inspection.target_content_hash.as_deref(),
            Some(hex_digest("alpha").as_str())
        );
        assert_eq!(inspection.hop_fingerprints.len(), 2);
    }

    #[test]
    fn a_symlink_with_no_target_is_broken() {
        let home = TempDir::new().expect("home");
        let source = home.path().join("link.md");
        link(&home.path().join("gone.md"), &source);

        let inspection =
            inspect_aibom_source_path(&source, &roots(home.path()), home.path(), None, false);

        assert_eq!(inspection.link_kind, "symlink");
        assert_eq!(inspection.validation_state, "broken");
        assert!(inspection.target_content_hash.is_none());
    }

    #[test]
    fn a_symlink_leaving_the_safe_roots_is_escape_blocked_until_it_is_followed() {
        let home = TempDir::new().expect("home");
        let elsewhere = TempDir::new().expect("elsewhere");
        let target = elsewhere.path().join("real.md");
        write(&target, "alpha");
        let source = home.path().join("link.md");
        link(&target, &source);

        let blocked =
            inspect_aibom_source_path(&source, &roots(home.path()), home.path(), None, false);
        assert_eq!(blocked.validation_state, "escape_blocked");
        assert!(blocked.target_content_hash.is_none());

        let followed =
            inspect_aibom_source_path(&source, &roots(home.path()), home.path(), None, true);
        assert_eq!(followed.validation_state, "valid");
        assert_eq!(
            followed.target_content_hash.as_deref(),
            Some(hex_digest("alpha").as_str())
        );
    }

    #[test]
    fn a_cycle_is_reported_as_a_loop() {
        let home = TempDir::new().expect("home");
        let first = home.path().join("a.md");
        let second = home.path().join("b.md");
        link(&second, &first);
        link(&first, &second);

        let inspection =
            inspect_aibom_source_path(&first, &roots(home.path()), home.path(), None, false);

        assert_eq!(inspection.validation_state, "loop");
        assert!(inspection.target_content_hash.is_none());
    }

    fn chain_of_links(home: &Path, length: usize) -> PathBuf {
        let target = home.join("real.md");
        write(&target, "alpha");
        let mut previous = target;
        for index in 0..length {
            let next = home.join(format!("hop-{index}.md"));
            link(&previous, &next);
            previous = next;
        }
        previous
    }

    #[test]
    fn a_chain_collapses_in_one_hop_because_the_target_is_resolved_whole() {
        let home = TempDir::new().expect("home");
        let source = chain_of_links(home.path(), 8);

        let inspection =
            inspect_aibom_source_path(&source, &roots(home.path()), home.path(), None, false);

        assert_eq!(inspection.validation_state, "valid");
        // The first hop's target resolves through the rest of the chain, as
        // `Path.resolve()` does, so the recorded hops are the link and its end.
        assert_eq!(inspection.hop_fingerprints.len(), 2);
    }

    #[test]
    fn a_chain_the_system_refuses_to_resolve_is_a_loop() {
        let home = TempDir::new().expect("home");
        let source = chain_of_links(home.path(), 64);

        let inspection =
            inspect_aibom_source_path(&source, &roots(home.path()), home.path(), None, false);

        assert_eq!(inspection.validation_state, "loop");
        assert!(inspection.target_content_hash.is_none());
    }

    #[test]
    fn a_directory_target_is_fingerprinted_as_a_tree_without_ignored_members() {
        let home = TempDir::new().expect("home");
        let tree = home.path().join("tree");
        write(&tree.join("a.txt"), "alpha");
        write(&tree.join("sub/b.txt"), "beta");
        write(&tree.join(".env"), "SECRET=1");
        write(&tree.join(".git/c.txt"), "gamma");
        let source = home.path().join("link");
        link(&tree, &source);

        let inspection =
            inspect_aibom_source_path(&source, &roots(home.path()), home.path(), None, false);

        let expected = fingerprint_mapping(&json!([
            {"path": "{home}/tree/a.txt", "sha256": hex_digest("alpha")},
            {"path": "{home}/tree/sub/b.txt", "sha256": hex_digest("beta")},
        ]));
        assert_eq!(inspection.validation_state, "valid");
        assert_eq!(
            inspection.target_content_hash.as_deref(),
            Some(expected.as_str())
        );
    }

    #[test]
    fn a_nested_member_precedes_the_sibling_its_directory_is_named_after() {
        // Python sorted the collected paths as `Path` objects, which compare
        // component by component, so `foo/bar.md` comes before `foo.md`.
        // Comparing whole path strings reverses that pair, because `.` sorts
        // below `/`, and the fingerprint of an untouched tree would move.
        let home = TempDir::new().expect("home");
        let tree = home.path().join("tree");
        write(&tree.join("foo.md"), "alpha");
        write(&tree.join("foo/bar.md"), "beta");
        let source = home.path().join("link");
        link(&tree, &source);

        let inspection =
            inspect_aibom_source_path(&source, &roots(home.path()), home.path(), None, false);

        let expected = fingerprint_mapping(&json!([
            {"path": "{home}/tree/foo/bar.md", "sha256": hex_digest("beta")},
            {"path": "{home}/tree/foo.md", "sha256": hex_digest("alpha")},
        ]));
        assert_eq!(
            inspection.target_content_hash.as_deref(),
            Some(expected.as_str())
        );
    }

    #[test]
    fn a_relative_link_target_resolves_against_the_parent_when_a_workspace_is_in_play() {
        let home = TempDir::new().expect("home");
        let workspace = home.path().join("code");
        let target = workspace.join("real.md");
        write(&target, "alpha");
        let source = workspace.join("link.md");
        link(Path::new("real.md"), &source);

        assert_eq!(
            classify_path_class(&source, home.path(), Some(&workspace)),
            "workspace_relative"
        );
        // Without a workspace the same relative target is read against the home
        // directory, which is where it does not exist.
        assert_eq!(
            classify_path_class(&source, home.path(), None),
            "home_relative"
        );
    }

    #[test]
    fn two_links_to_the_same_file_share_a_source_fingerprint() {
        let home = TempDir::new().expect("home");
        let target = home.path().join("real.md");
        write(&target, "alpha");
        let source = home.path().join("link.md");
        link(&target, &source);

        let first =
            inspect_aibom_source_path(&source, &roots(home.path()), home.path(), None, false);
        let second =
            inspect_aibom_source_path(&source, &roots(home.path()), home.path(), None, false);

        assert_eq!(first.source_fingerprint, second.source_fingerprint);
        assert_ne!(first.source_fingerprint, String::new());
    }
}
