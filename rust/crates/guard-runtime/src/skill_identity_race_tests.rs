//! Concurrent-change detection: the tree is mutated at the exact points the
//! inspector re-validates, and the result must be a typed non-reusable one.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use guard_contracts::{SkillDirectoryIdentityV1, SkillDirectoryLimitsV1};

use super::test_hooks::{COLLECT, HASHED};
use super::*;

struct Scenario {
    base: PathBuf,
    scope: PathBuf,
    skill: PathBuf,
}

impl Scenario {
    fn new(tag: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "hol-guard-skill-race-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&base);
        let scope = base.join("scope");
        let root = scope.join("skills").join("example");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("SKILL.md"), "# skill\n").unwrap();
        let base = fs::canonicalize(base).unwrap();
        Self {
            scope: base.join("scope"),
            skill: base.join("scope/skills/example/SKILL.md"),
            base,
        }
    }

    fn root(&self) -> &Path {
        self.skill.parent().unwrap()
    }

    fn inspect(&self) -> SkillDirectoryIdentityV1 {
        let limits = SkillDirectoryLimitsV1 {
            max_depth: 32,
            max_entries: 4096,
            max_file_bytes: 1024 * 1024,
            max_total_bytes: 4 * 1024 * 1024,
        };
        inspect_skill_directory(&self.skill, &self.scope, &limits)
    }
}

impl Drop for Scenario {
    fn drop(&mut self) {
        COLLECT.with(|hook| *hook.borrow_mut() = None);
        HASHED.with(|hook| *hook.borrow_mut() = None);
        let _ = fs::remove_dir_all(&self.base);
    }
}

fn assert_tree_changed(identity: &SkillDirectoryIdentityV1) {
    assert_eq!(identity.status, "incomplete");
    assert_eq!(identity.directory_hash, None);
    assert_eq!(
        identity.failure_reason,
        Some(Failure::TreeChangedDuringHash)
    );
}

#[test]
fn unmutated_tree_is_complete() {
    let scenario = Scenario::new("stable");
    assert_eq!(scenario.inspect().status, "complete");
}

#[test]
fn structure_added_between_collection_passes_is_detected() {
    let scenario = Scenario::new("added");
    let root = scenario.root().to_path_buf();
    COLLECT.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move |pass, after| {
            if pass == 2 && !after {
                fs::write(root.join("late-addition.txt"), "late").unwrap();
            }
        }));
    });
    assert_tree_changed(&scenario.inspect());
}

#[test]
fn root_replaced_after_final_collection_is_detected() {
    let scenario = Scenario::new("replaced");
    let root = scenario.root().to_path_buf();
    COLLECT.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move |pass, after| {
            if pass == 2 && after {
                fs::rename(&root, root.with_file_name("example-original")).unwrap();
                fs::create_dir(&root).unwrap();
                fs::write(root.join("SKILL.md"), "replacement\n").unwrap();
            }
        }));
    });
    assert_tree_changed(&scenario.inspect());
}

#[test]
fn symlink_retargeted_while_target_is_hashed_is_detected() {
    let scenario = Scenario::new("retargeted");
    let root = scenario.root().to_path_buf();
    fs::write(root.join("first.txt"), "first").unwrap();
    fs::write(root.join("second.txt"), "second").unwrap();
    symlink("first.txt", root.join("alias.txt")).unwrap();
    let mut retargeted = false;
    HASHED.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move |path| {
            if path.ends_with("first.txt") && !retargeted {
                retargeted = true;
                let alias = root.join("alias.txt");
                fs::remove_file(&alias).unwrap();
                symlink("second.txt", &alias).unwrap();
            }
        }));
    });
    assert_tree_changed(&scenario.inspect());
}
