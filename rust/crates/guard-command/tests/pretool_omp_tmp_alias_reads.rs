#![cfg(unix)]

//! Oh My Pi `read` names a directory or file through the `/tmp` alias (on
//! macOS a symlink to `/private/tmp`). The alias is resolved before the
//! symlink check wherever the target lives, so an ordinary listing of a
//! sibling worktree under the temporary root is not reviewed only for how
//! it was spelled. Symlinks below the alias and sensitive targets stay
//! reviewable.

use crate::git_helper_fixture::evaluate_pre_tool_envelope_with_context;
use crate::pretool_git_session_ops::default_controls;
use guard_contracts::PreToolResultV1;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    project: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// `None` where `/tmp` is not an alias, so there is nothing to prove.
fn fixture(name: &str) -> Option<Fixture> {
    let tmp = Path::new("/tmp");
    if std::fs::canonicalize(tmp).ok().as_deref() == Some(tmp) {
        return None;
    }
    let root = tmp.join(format!("guard-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let home = root.join("home");
    let project = home.join("project");
    std::fs::create_dir_all(&project).unwrap();
    let fixture = Fixture {
        home: std::fs::canonicalize(&home).unwrap(),
        project: std::fs::canonicalize(&project).unwrap(),
        root,
    };
    Some(fixture)
}

fn evaluate(fixture: &Fixture, tool: &str, input: Value) -> PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name": tool, "tool_input": input}),
        Some(&default_controls()),
        None,
        fixture.home.to_str(),
        fixture.project.to_str(),
    )
}

fn read(fixture: &Fixture, target: &Path) -> PreToolResultV1 {
    evaluate(fixture, "read", json!({"path": target.to_str().unwrap()}))
}

fn eval_read(fixture: &Fixture, target: &Path) -> PreToolResultV1 {
    let code = format!(
        "const r = await tool.read({{path:{}}}); display(r);",
        serde_json::to_string(target.to_str().unwrap()).unwrap(),
    );
    evaluate(
        fixture,
        "eval",
        json!({"language": "js", "code": code, "title": "List", "timeout": null, "reset": false}),
    )
}

#[test]
fn omp_reads_through_the_tmp_alias_outside_the_session_roots() {
    let Some(fixture) = fixture("omp-tmp-alias-sibling") else {
        return;
    };
    let sibling = fixture.root.join("sibling");
    std::fs::create_dir_all(sibling.join("src")).unwrap();
    std::fs::write(sibling.join("src").join("main.rs"), "fn main() {}\n").unwrap();
    let canonical = std::fs::canonicalize(&sibling).unwrap();

    for target in [sibling.as_path(), canonical.as_path()] {
        let direct = read(&fixture, target);
        assert_eq!(direct.minimum_action, "allow", "{}", target.display());
        assert_eq!(direct.reason_code, "native_exact_safe_directory_read");
        let bridged = eval_read(&fixture, target);
        assert_eq!(
            bridged.minimum_action,
            "allow",
            "{}: {}",
            target.display(),
            bridged.reason_code
        );
    }
}

#[test]
fn omp_tmp_alias_reads_keep_symlinks_and_secrets_reviewable() {
    let Some(fixture) = fixture("omp-tmp-alias-review") else {
        return;
    };
    let sibling = fixture.root.join("sibling");
    std::fs::create_dir_all(&sibling).unwrap();
    std::fs::write(sibling.join(".env"), "TOKEN=fixture\n").unwrap();
    let ssh = fixture.root.join("other-home").join(".ssh");
    std::fs::create_dir_all(&ssh).unwrap();
    std::fs::write(ssh.join("id_rsa"), "fixture\n").unwrap();
    let link = fixture.root.join("linked");
    std::os::unix::fs::symlink(&ssh, &link).unwrap();

    for target in [sibling.join(".env"), ssh.clone(), ssh.join("id_rsa"), link] {
        let direct = read(&fixture, &target);
        assert_ne!(
            direct.minimum_action,
            "allow",
            "{}: {}",
            target.display(),
            direct.reason_code
        );
        let bridged = eval_read(&fixture, &target);
        assert_ne!(
            bridged.minimum_action,
            "allow",
            "{}: {}",
            target.display(),
            bridged.reason_code
        );
    }
}
