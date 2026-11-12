//! The check asks the kernel about the sandbox it runs in, so the macOS
//! cases start this test binary again under `sandbox-exec` with a profile
//! shaped like one of Codex's and read the check's answer from its exit
//! status.

use super::*;

fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_owned()).collect()
}

#[test]
fn a_malformed_call_is_refused() {
    let workspace = tempfile::tempdir().unwrap();
    let workspace = workspace.path().to_str().unwrap();
    for args in [
        strings(&[]),
        strings(&["--profile", WORKSPACE_PROFILE]),
        strings(&["--workspace", workspace, "--profile", WORKSPACE_PROFILE]),
        strings(&[
            "--profile",
            WORKSPACE_PROFILE,
            "--workspace",
            workspace,
            "x",
        ]),
    ] {
        assert_eq!(run(&args), REFUSED, "{args:?}");
    }
}

#[test]
fn a_process_outside_any_sandbox_is_refused() {
    let workspace = tempfile::tempdir().unwrap();
    let workspace = workspace.path().to_str().unwrap();
    for profile in [WORKSPACE_PROFILE, PYTEST_PROFILE, SHARED_TMP_CHECK] {
        assert!(!confined(profile, workspace), "{profile}");
        let args = strings(&["--profile", profile, "--workspace", workspace]);
        assert_eq!(run(&args), REFUSED, "{profile}");
    }
    assert!(!confined(WORKSPACE_PROFILE, "/no/such/workspace"));
}

#[cfg(unix)]
#[test]
fn the_directories_outside_the_workspace_include_its_parent_and_tmp() {
    let workspace = tempfile::tempdir().unwrap();
    let workspace = std::fs::canonicalize(workspace.path()).unwrap();
    let outside = outside_paths(&workspace).unwrap();
    assert_eq!(outside[0], workspace.parent().unwrap());
    assert!(outside.contains(&std::fs::canonicalize("/tmp").unwrap()));
    assert!(outside_paths(std::path::Path::new("/")).is_none());
}

#[cfg(target_os = "macos")]
const CHILD: &str = "codex_sandbox_check::tests::sandboxed_child";
#[cfg(target_os = "macos")]
const PROFILE_ENV: &str = "HOL_GUARD_SANDBOX_CHECK_PROFILE";
#[cfg(target_os = "macos")]
const WORKSPACE_ENV: &str = "HOL_GUARD_SANDBOX_CHECK_WORKSPACE";

/// The check, run in the process `check_under` started in a sandbox.
#[cfg(target_os = "macos")]
#[test]
fn sandboxed_child() {
    let (Ok(profile), Ok(workspace)) = (std::env::var(PROFILE_ENV), std::env::var(WORKSPACE_ENV))
    else {
        return;
    };
    let status = if confined(&profile, &workspace) {
        0
    } else {
        REFUSED
    };
    std::process::exit(status);
}

/// The check's exit status for `profile` in a process confined by `sbpl`.
#[cfg(target_os = "macos")]
fn check_under(sbpl: &str, profile: &str, workspace: &std::path::Path) -> i32 {
    let status = std::process::Command::new("/usr/bin/sandbox-exec")
        .arg("-p")
        .arg(sbpl)
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", CHILD, "--nocapture"])
        .env(PROFILE_ENV, profile)
        .env(WORKSPACE_ENV, workspace)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    status.code().unwrap()
}

/// A profile that denies the network unless `network`, and writes outside
/// `writable`.
#[cfg(target_os = "macos")]
fn sbpl(network: bool, writable: &[&std::path::Path]) -> String {
    let mut profile = String::from("(version 1)(allow default)(deny file-write*)");
    if !network {
        profile.push_str("(deny network*)");
    }
    for directory in writable {
        profile.push_str(&format!(
            "(allow file-write* (subpath {:?}))",
            directory.to_str().unwrap()
        ));
    }
    profile
}

#[cfg(target_os = "macos")]
#[test]
fn codex_workspace_write_sandbox_holds_only_the_workspace_profile() {
    let workspace = tempfile::tempdir().unwrap();
    let workspace = std::fs::canonicalize(workspace.path()).unwrap();
    let codex = sbpl(false, &[&workspace]);
    assert_eq!(check_under(&codex, WORKSPACE_PROFILE, &workspace), 0);
    assert_eq!(
        check_under(&codex, "pytest-readonly-v2", &workspace),
        REFUSED,
        "a read-only profile must not write the workspace"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn codex_read_only_sandbox_holds_every_profile() {
    let workspace = tempfile::tempdir().unwrap();
    let workspace = std::fs::canonicalize(workspace.path()).unwrap();
    let read_only = sbpl(false, &[]);
    for profile in [WORKSPACE_PROFILE, "pytest-readonly-v2"] {
        assert_eq!(check_under(&read_only, profile, &workspace), 0, "{profile}");
    }
}

#[cfg(target_os = "macos")]
#[test]
fn a_wider_sandbox_is_refused() {
    let workspace = tempfile::tempdir().unwrap();
    let workspace = std::fs::canonicalize(workspace.path()).unwrap();
    let tmp = std::fs::canonicalize("/tmp").unwrap();
    let parent = workspace.parent().unwrap().to_path_buf();
    let wider = [
        ("no sandbox rules", "(version 1)(allow default)".to_owned()),
        ("network", sbpl(true, &[&workspace])),
        ("/tmp", sbpl(false, &[&workspace, &tmp])),
        ("the workspace's parent", sbpl(false, &[&parent])),
    ];
    for (name, profile) in wider {
        assert_eq!(
            check_under(&profile, WORKSPACE_PROFILE, &workspace),
            REFUSED,
            "{name}"
        );
    }
}

/// Codex's default sandbox: no network, writes to the workspace, `/tmp` and
/// `$TMPDIR`.
#[cfg(target_os = "macos")]
#[test]
fn codex_default_sandbox_holds_only_the_shared_tmp_check() {
    let workspace = tempfile::tempdir().unwrap();
    let workspace = std::fs::canonicalize(workspace.path()).unwrap();
    let shared = temp_paths();
    let mut writable: Vec<&std::path::Path> = vec![&workspace];
    writable.extend(shared.iter().map(std::path::PathBuf::as_path));
    let codex = sbpl(false, &writable);
    assert_eq!(check_under(&codex, SHARED_TMP_CHECK, &workspace), 0);
    for profile in [WORKSPACE_PROFILE, PYTEST_PROFILE] {
        assert_eq!(
            check_under(&codex, profile, &workspace),
            REFUSED,
            "{profile}"
        );
    }
    let home = std::fs::canonicalize(std::env::var_os("HOME").unwrap()).unwrap();
    let wider = [
        ("network", sbpl(true, &writable)),
        (
            "home",
            sbpl(false, &[writable.as_slice(), &[home.as_path()]].concat()),
        ),
        ("no sandbox rules", "(version 1)(allow default)".to_owned()),
    ];
    for (name, profile) in wider {
        assert_eq!(
            check_under(&profile, SHARED_TMP_CHECK, &workspace),
            REFUSED,
            "{name}"
        );
    }
}

/// A workspace outside the temporary directories keeps its parent denied.
#[cfg(target_os = "macos")]
#[test]
fn the_shared_tmp_check_still_denies_the_workspace_parent() {
    let deps = std::env::current_exe().unwrap();
    let workspace = tempfile::tempdir_in(deps.parent().unwrap()).unwrap();
    let workspace = std::fs::canonicalize(workspace.path()).unwrap();
    let parent = workspace.parent().unwrap().to_path_buf();
    let shared = temp_paths();
    let mut writable: Vec<&std::path::Path> = vec![&workspace];
    writable.extend(shared.iter().map(std::path::PathBuf::as_path));
    assert_eq!(
        check_under(&sbpl(false, &writable), SHARED_TMP_CHECK, &workspace),
        0
    );
    writable.push(&parent);
    assert_eq!(
        check_under(&sbpl(false, &writable), SHARED_TMP_CHECK, &workspace),
        REFUSED
    );
}
