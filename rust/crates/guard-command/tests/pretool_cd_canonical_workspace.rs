#![cfg(unix)]
//! A `cd` into the workspace spelled through a link only root or the user can
//! retarget names the workspace, so the writes after it keep their proof.
//!
//! macOS reports a session under `/tmp` while the shell may print the
//! canonical `/private/tmp` spelling, and `$TMPDIR` lives under the `/var`
//! alias. A link kept in a directory other users can write proves nothing:
//! they can point it elsewhere before the shell follows it.
use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn unique(prefix: &str) -> String {
    format!(
        "{prefix}-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    )
}

/// A canonical home holding one project below the target directory.
fn home() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-cd-canonical-workspace")
        .join(unique("home"));
    let home = root.join("home");
    std::fs::create_dir_all(home.join("project/src")).unwrap();
    std::fs::canonicalize(home).unwrap()
}

/// A directory with `mode` beside the home holding a link to the project.
fn link_in(home: &Path, name: &str, mode: u32) -> String {
    let directory = home.parent().unwrap().join(name);
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(mode)).unwrap();
    let link = directory.join("project");
    std::os::unix::fs::symlink(home.join("project"), &link).unwrap();
    link.to_str().unwrap().to_owned()
}

/// Restores a writable mode so the target directory can be cleaned.
fn release(home: &Path, name: &str) {
    let directory = home.parent().unwrap().join(name);
    let _ = std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700));
}

/// The decision both shell harnesses reach for `command` in a session whose
/// home and working directory are spelled as given, or "mixed".
fn shell(home: &str, cwd: &str, command: &str) -> String {
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: vec!["GIT_CONFIG_NOSYSTEM".to_owned()],
        environment_digest: "0".repeat(64),
        home: Some(home.to_owned()),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: true,
        library_search_paths: Default::default(),
    };
    let [omp, zcode] = ["omp", "zcode"].map(|harness| {
        evaluate_pre_tool_envelope_with_execution_context(
            harness,
            "PreToolUse",
            &json!({"tool_name": "bash", "tool_input": {"command": command}}),
            None,
            None,
            PathContext {
                home_dir: Some(home),
                cwd: Some(cwd),
                ..PathContext::default()
            },
            Some(&environment),
        )
        .minimum_action
    });
    if omp == zcode {
        omp
    } else {
        format!("mixed: omp {omp}, zcode {zcode}")
    }
}

#[test]
fn cd_through_a_private_user_link_creates_inside_the_workspace() {
    let home = home();
    let link = link_in(&home, "links", 0o700);
    let (home_text, cwd) = (
        home.to_str().unwrap(),
        home.join("project").to_str().unwrap().to_owned(),
    );
    assert_eq!(
        shell(home_text, &cwd, &format!("cd {link} && mkdir -p a/b")),
        "allow"
    );
    std::fs::create_dir_all(home.join("project/a/b")).unwrap();
    assert_eq!(
        shell(
            home_text,
            &cwd,
            &format!("cd {link} && touch a/b/created.ts")
        ),
        "allow"
    );
    let _ = std::fs::remove_dir_all(home.parent().unwrap());
}

#[test]
fn cd_through_a_link_others_can_swap_stays_unproven() {
    let home = home();
    let (home_text, cwd) = (
        home.to_str().unwrap(),
        home.join("project").to_str().unwrap().to_owned(),
    );
    for (name, mode) in [("open", 0o777), ("sticky", 0o1777)] {
        let link = link_in(&home, name, mode);
        let decision = shell(home_text, &cwd, &format!("cd {link} && mkdir -p a/b"));
        release(&home, name);
        assert_ne!(decision, "allow", "{name} link {link}");
    }
    let _ = std::fs::remove_dir_all(home.parent().unwrap());
}

/// The live macOS shape: the session reports `/tmp`, the command spells the
/// canonical `/private/tmp`, and both name the same workspace.
#[cfg(target_os = "macos")]
#[test]
fn cd_to_private_tmp_matches_a_tmp_workspace() {
    let root = Path::new("/tmp").join(unique("hol-guard-cd-canonical"));
    let home = root.join("home");
    std::fs::create_dir_all(home.join("project/output/generated/nested")).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let canonical = std::fs::canonicalize(home.join("project")).unwrap();
    assert!(canonical.starts_with("/private/tmp"), "{canonical:?}");
    let (home_text, cwd) = (
        home.to_str().unwrap(),
        home.join("project").to_str().unwrap().to_owned(),
    );
    for spelling in [canonical.to_str().unwrap(), cwd.as_str()] {
        assert_eq!(
            shell(
                home_text,
                &cwd,
                &format!("cd {spelling} && mkdir -p output/generated/nested")
            ),
            "allow",
            "{spelling}"
        );
        assert_eq!(
            shell(
                home_text,
                &cwd,
                &format!("cd {spelling} && touch output/generated/nested/created.ts")
            ),
            "allow",
            "{spelling}"
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}
