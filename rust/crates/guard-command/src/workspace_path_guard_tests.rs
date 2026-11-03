//! Containment for workspace-relative manifest and lockfile paths.
//!
//! Every manifest a package request reads is named by a relative path that came
//! from the command line, so the resolver is what keeps `-r ../outside/
//! requirements.txt` from turning into a read outside the workspace. The two
//! readers in `package_authority_op` are four-line wrappers that call this
//! resolver and then open the path it returned, so pinning the resolver pins
//! what they are allowed to open.

use std::fs;
use std::path::{Path, PathBuf};

use crate::package_intent_common::{
    existing_paths_within_workspace, resolve_path_within_workspace,
};

struct Fixture {
    _root: tempfile::TempDir,
    workspace: PathBuf,
    outside: PathBuf,
}

fn fixture() -> Fixture {
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let workspace = root.path().join("workspace");
    let outside = root.path().join("outside");
    fs::create_dir(&workspace).unwrap();
    fs::create_dir(&outside).unwrap();
    Fixture {
        _root: root,
        workspace,
        outside,
    }
}

fn symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_file(target, link)
    }
}

#[test]
fn parent_traversal_resolves_to_nothing() {
    let fixture = fixture();
    fs::write(fixture.outside.join("requirements.txt"), "leakpkg==1.0.0\n").unwrap();

    assert_eq!(
        resolve_path_within_workspace(&fixture.workspace, "../outside/requirements.txt"),
        None
    );
    assert!(existing_paths_within_workspace(
        Some(&fixture.workspace),
        &["../outside/requirements.txt".to_string()],
    )
    .is_empty());
}

#[test]
fn absolute_and_empty_operands_resolve_to_nothing() {
    let fixture = fixture();
    let absolute = fixture.outside.join("requirements.txt");
    fs::write(&absolute, "leakpkg==1.0.0\n").unwrap();

    assert_eq!(
        resolve_path_within_workspace(&fixture.workspace, absolute.to_str().unwrap()),
        None
    );
    assert_eq!(resolve_path_within_workspace(&fixture.workspace, ""), None);
    assert!(existing_paths_within_workspace(
        Some(&fixture.workspace),
        &[absolute.to_string_lossy().into_owned(), String::new()],
    )
    .is_empty());
}

#[test]
fn a_symlink_out_of_the_workspace_resolves_to_nothing() {
    let fixture = fixture();
    let secret = fixture.outside.join("secret.env");
    fs::write(&secret, "AWS_SECRET_ACCESS_KEY=super-secret\n").unwrap();
    // Windows needs developer mode or an elevated process to create a symlink.
    // Skip only when the host refuses to make one, so the case still runs
    // wherever it can instead of being compiled out on a whole platform.
    if symlink(&secret, &fixture.workspace.join("requirements.txt")).is_err() {
        return;
    }

    assert_eq!(
        resolve_path_within_workspace(&fixture.workspace, "requirements.txt"),
        None
    );
    assert!(existing_paths_within_workspace(
        Some(&fixture.workspace),
        &["requirements.txt".to_string()],
    )
    .is_empty());
}

#[test]
fn a_file_inside_the_workspace_resolves_and_is_reported_once() {
    let fixture = fixture();
    fs::create_dir(fixture.workspace.join("deps")).unwrap();
    fs::write(
        fixture.workspace.join("deps/requirements.txt"),
        "left-pad==1.3.0\n",
    )
    .unwrap();

    let resolved =
        resolve_path_within_workspace(&fixture.workspace, "deps/requirements.txt").unwrap();
    assert_eq!(fs::read_to_string(&resolved).unwrap(), "left-pad==1.3.0\n");
    assert_eq!(
        existing_paths_within_workspace(
            Some(&fixture.workspace),
            &[
                "deps/requirements.txt".to_string(),
                "deps/requirements.txt".to_string(),
                "deps/missing.txt".to_string(),
            ],
        ),
        vec!["deps/requirements.txt".to_string()]
    );
}

#[test]
fn no_workspace_reports_no_paths() {
    assert!(existing_paths_within_workspace(None, &["requirements.txt".to_string()]).is_empty());
}
