use super::{base_outside_install_roots, wrapped_base_outside_install_roots};
use std::path::{Path, PathBuf};

fn parsed(command: &str) -> crate::CanonicalCommandV1 {
    crate::parse_command(&crate::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })
    .unwrap()
}

struct Fixture {
    root: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A workspace with a `.venv` built from a base Python installed under
/// `installs/<install>`, beside an all-users root and a per-user root.
fn fixture(name: &str, install: &str) -> Fixture {
    let root = std::env::temp_dir().join(format!(
        "guard-windows-pytest-base-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    for directory in [
        "all-users/Python312",
        "per-user/Python312",
        "workspace/.venv/bin",
    ] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
        std::fs::write(root.join(directory).join("python.exe"), b"MZ").unwrap();
    }
    std::fs::write(root.join("workspace/.venv/bin/pytest"), b"#!python\n").unwrap();
    let home = root.join(install).join("Python312");
    std::fs::write(
        root.join("workspace/.venv/pyvenv.cfg"),
        format!("home = {}\nversion_info = 3.12.10\n", home.display()),
    )
    .unwrap();
    Fixture { root }
}

fn outside(fixture: &Fixture, command: &str) -> bool {
    let workspace = fixture.root.join("workspace");
    base_outside_install_roots(
        &parsed(command),
        workspace.to_str(),
        &[fixture.root.join("all-users")],
    )
}

/// A virtual environment of a per-user Python cannot run inside the
/// AppContainer, so the activated `pytest` keeps its review instead of
/// being handed to a contained run that can only exit 126.
#[test]
fn a_per_user_base_python_keeps_the_review() {
    let fixture = fixture("per-user", "per-user");
    assert!(outside(&fixture, ".venv/bin/pytest -q"));
    assert!(outside(&fixture, ".venv/bin/python -m pytest -q"));
}

#[test]
fn an_all_users_base_python_stays_contained() {
    let fixture = fixture("all-users", "all-users");
    assert!(!outside(&fixture, ".venv/bin/pytest -q"));
}

/// A `home` that names no interpreter is refused by the planner too.
#[test]
fn a_base_that_does_not_resolve_keeps_the_review() {
    let fixture = fixture("missing", "nowhere");
    assert!(outside(&fixture, ".venv/bin/pytest -q"));
}

/// A bare name is found on the shell's `PATH`, which the hook does not see;
/// it is left to the planner.
#[test]
fn a_bare_pytest_is_left_to_the_planner() {
    let fixture = fixture("bare", "per-user");
    assert!(!outside(&fixture, "pytest -q"));
    assert!(!base_outside_install_roots(
        &parsed(".venv/bin/pytest -q"),
        None,
        &[Path::new("/").to_path_buf()],
    ));
}

/// A launcher outside a marked environment is not read as one.
#[test]
fn an_unmarked_directory_is_left_to_the_planner() {
    let fixture = fixture("unmarked", "per-user");
    std::fs::remove_file(fixture.root.join("workspace/.venv/pyvenv.cfg")).unwrap();
    assert!(!outside(&fixture, ".venv/bin/pytest -q"));
}

fn wrapped_outside(fixture: &Fixture, command: &str) -> bool {
    let home = fixture.root.canonicalize().unwrap();
    let workspace = home.join("workspace");
    std::fs::create_dir_all(workspace.join(".git")).unwrap();
    std::fs::write(workspace.join(".git/config"), "[core]\n\tbare = false\n").unwrap();
    wrapped_base_outside_install_roots(
        &parsed(command),
        crate::pretool::PathContext {
            home_dir: home.to_str(),
            cwd: workspace.to_str(),
            cdpath_unset: true,
            ..Default::default()
        },
        &[fixture.root.join("all-users")],
    )
}

/// The containment route reads pytest inside a piped run or after a `cd`, so
/// the base Python is read from that same core and directory.
#[test]
fn a_wrapped_run_reads_the_base_of_its_core() {
    let per_user = fixture("wrapped", "per-user");
    let workspace = per_user.root.join("workspace");
    std::fs::create_dir_all(workspace.join("api/.venv/bin")).unwrap();
    for file in [
        ".venv/bin/python.exe",
        ".venv/bin/pytest",
        ".venv/pyvenv.cfg",
    ] {
        std::fs::copy(workspace.join(file), workspace.join("api").join(file)).unwrap();
    }
    assert!(wrapped_outside(&per_user, ".venv/bin/pytest -q"));
    assert!(wrapped_outside(&per_user, ".venv/bin/pytest -q | head -40"));
    // An absolute `cd` is peeled on every host; Windows also peels a relative
    // one inside the workspace.
    let api = crate::runtime_read_paths::strip_verbatim_prefix(
        workspace.join("api").canonicalize().unwrap(),
    );
    assert!(wrapped_outside(
        &per_user,
        &format!("cd {} && .venv/bin/pytest -q", api.display())
    ));
    let all_users = fixture("wrapped-all-users", "all-users");
    assert!(!wrapped_outside(
        &all_users,
        ".venv/bin/pytest -q | head -40"
    ));
}
