//! Unit tests for the Windows read-only pytest planner.
//!
//! The module these cover is `#[cfg(windows)]`, so the file compiles only
//! where the behaviour it describes exists. `ci/platform_arms.json` records
//! that arm and the Unix behaviour it mirrors.
use super::*;
use crate::windows_readonly::canonical;
use serde_json::json;

#[test]
fn reads_an_environment_interpreter_back_from_a_plan() {
    let (environment, interpreter) =
        staged_interpreter(Path::new(".venv/Scripts/python.exe")).expect("a staged interpreter");
    assert_eq!(environment, Path::new(".venv"));
    assert_eq!(interpreter, Path::new(".venv/Scripts/python.exe"));
}

#[test]
fn reads_a_backslash_spelling_and_a_nested_environment() {
    let (environment, interpreter) =
        staged_interpreter(Path::new(r"services\api\.venv\bin\python3.12.exe"))
            .expect("a staged interpreter");
    assert_eq!(environment, Path::new("services/api/.venv"));
    assert_eq!(
        interpreter,
        Path::new("services/api/.venv/bin/python3.12.exe")
    );
}

#[test]
fn refuses_an_interpreter_outside_the_snapshot() {
    for spelling in [
        r"C:\Python312\python.exe",
        "../.venv/Scripts/python.exe",
        ".venv/Scripts/pytest.exe",
        ".venv/lib/python.exe",
        "Scripts/python.exe",
        ".venv/Scripts/../python.exe",
    ] {
        assert!(
            staged_interpreter(Path::new(spelling)).is_none(),
            "{spelling} should not name a staged interpreter"
        );
    }
}

#[test]
fn names_the_environment_binaries_from_the_run_directory() {
    assert_eq!(
        relative_from(Path::new(""), Path::new(".venv/Scripts")),
        Path::new(".venv/Scripts")
    );
    assert_eq!(
        relative_from(Path::new("services/api"), Path::new(".venv/Scripts")),
        Path::new("../../.venv/Scripts")
    );
}

/// The planner reads argv through `guard-command`'s own validator, so this
/// covers the shapes that decide whether the run is pytest at all.
#[test]
fn reads_only_a_module_run_of_pytest() {
    let targets = |items: &[&str]| {
        guard_command::pytest_argv::python_args_target_pytest(
            &items
                .iter()
                .map(|item| (*item).to_owned())
                .collect::<Vec<_>>(),
        )
    };
    assert!(targets(&["-m", "pytest", "-q"]));
    assert!(targets(&["-X", "utf8", "-mpytest"]));
    assert!(targets(&["-W", "ignore", "-m", "pytest"]));
    assert!(!targets(&["-c", "import os"]));
    assert!(!targets(&["-m", "pip", "install", "x"]));
    assert!(!targets(&["--", "-m", "pytest"]));
    assert!(!targets(&["-q"]));
    // The script ends the options, so the `-m` after it is the script's own.
    assert!(!targets(&["evil.py", "-m", "pytest"]));
    assert!(!targets(&["-", "-m", "pytest"]));
    // A value-taking short option swallows the rest of its cluster.
    assert!(!targets(&["-Ic", "import os", "-m", "pytest"]));
    assert!(!targets(&["-Icimport os", "-m", "pytest"]));
    assert!(!targets(&["--command=import os", "-m", "pytest"]));
    // A `-X` value must not be read as the start of the module run.
    assert!(!targets(&["-X", "-m", "pytest"]));
}

#[test]
fn refuses_shell_operators_in_argv() {
    let arguments = vec!["-q".to_owned(), "&&".to_owned(), "curl".to_owned()];
    assert_eq!(
        screened(&arguments).expect_err("a refusal").reason_code,
        INVALID
    );
}

#[test]
fn reads_the_interpreter_names_an_environment_creates() {
    for name in ["python.exe", "python3.exe", "pythonw.exe", "python3.12.exe"] {
        assert!(interpreter_named(name), "{name} should be an interpreter");
    }
    for name in ["pytest.exe", "node.exe", "python3x.exe", "python3..exe"] {
        assert!(!interpreter_named(name), "{name} should not be one");
    }
}

#[test]
fn refuses_a_directory_that_is_not_an_environment() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let root = directory.path().to_path_buf();
    let failure = base_interpreter(&root).expect_err("no pyvenv.cfg");
    assert_eq!(failure.reason_code, UNAVAILABLE);
    std::fs::write(
        root.join("pyvenv.cfg"),
        "include-system-site-packages = false\n",
    )
    .expect("a configuration without a home");
    assert_eq!(
        base_interpreter(&root).expect_err("no home").reason_code,
        UNAVAILABLE
    );
}

#[test]
fn refuses_an_environment_with_no_interpreter_of_its_own() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let root = directory.path().to_path_buf();
    std::fs::create_dir_all(root.join("bin")).expect("a binaries directory");
    std::fs::write(root.join("bin/pytest"), "#!/bin/sh\n").expect("a POSIX launcher");
    let failure = environment_interpreter(&root).expect_err("no interpreter");
    assert_eq!(failure.reason_code, UNAVAILABLE);
    std::fs::write(root.join("bin/python.exe"), b"MZ").expect("an interpreter");
    assert_eq!(
        environment_interpreter(&root).expect("an interpreter"),
        Path::new("bin/python.exe")
    );
}

/// An editable install or a `.pth` line holds the path it was written with,
/// which the snapshot does not hold a copy of.
#[test]
fn refuses_an_environment_that_imports_through_a_path_outside_itself() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let root = directory.path().to_path_buf();
    let packages = root.join("Lib/site-packages");
    std::fs::create_dir_all(&packages).expect("a site-packages");
    assert!(!imports_outside_itself(&root));

    std::fs::write(packages.join("_virtualenv.pth"), "import _virtualenv\n")
        .expect("a startup entry");
    std::fs::write(packages.join("relative.pth"), "../src\n").expect("a relative entry");
    assert!(!imports_outside_itself(&root));

    std::fs::write(packages.join("project.pth"), r"C:\work\project\src")
        .expect("an absolute entry");
    assert!(imports_outside_itself(&root));

    std::fs::remove_file(packages.join("project.pth")).expect("a removed entry");
    std::fs::write(
        packages.join("__editable___demo_finder.py"),
        "MAPPING = {}\n",
    )
    .expect("an editable finder");
    assert!(imports_outside_itself(&root));
    std::fs::remove_file(packages.join("__editable___demo_finder.py")).expect("a removed finder");

    // `site` joins a rooted or drive-relative line onto the drive, not onto
    // the site directory, so it names a directory outside the environment
    // although Rust does not call it absolute.
    for line in [r"\work\project\src", "/work/project/src", r"C:src"] {
        std::fs::write(packages.join("rooted.pth"), line).expect("a rooted entry");
        assert!(imports_outside_itself(&root), "{line} should be outside");
    }
    std::fs::remove_file(packages.join("rooted.pth")).expect("a removed entry");
    assert!(!imports_outside_itself(&root));
}

/// Reading stops at a bound, and a directory larger than it is one this read
/// never reached the end of, so it settles nothing and keeps its review.
#[test]
fn refuses_a_site_packages_too_large_to_read_through() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let root = directory.path().to_path_buf();
    let packages = root.join("Lib/site-packages");
    std::fs::create_dir_all(&packages).expect("a site-packages");
    for index in 0..SITE_ENTRIES_MAX {
        std::fs::write(packages.join(format!("package_{index}")), "").expect("an entry");
    }
    assert!(!imports_outside_itself(&root));
    std::fs::write(packages.join("package_over"), "").expect("one entry too many");
    assert!(imports_outside_itself(&root));
}

/// `uv` installs packages by hardlinking them out of its cache, and the
/// snapshot leaves out any file with a second directory entry.
#[test]
fn refuses_an_environment_built_from_hardlinked_files() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let root = directory.path().join("env");
    let binaries = root.join("Scripts");
    let packages = root.join("Lib/site-packages/demo");
    std::fs::create_dir_all(&binaries).expect("a binaries directory");
    std::fs::create_dir_all(&packages).expect("a package directory");
    std::fs::write(binaries.join("python.exe"), b"MZ").expect("an interpreter");
    std::fs::write(packages.join("__init__.py"), "").expect("a module");
    let interpreter = Path::new("Scripts/python.exe");
    assert!(!stages_incompletely(&root, interpreter));

    let cached = directory.path().join("cached.py");
    std::fs::write(&cached, "").expect("a cached module");
    std::fs::remove_file(packages.join("__init__.py")).expect("a removed module");
    std::fs::hard_link(&cached, packages.join("__init__.py")).expect("a hardlinked module");
    assert!(stages_incompletely(&root, interpreter));

    std::fs::remove_file(packages.join("__init__.py")).expect("a removed module");
    std::fs::write(packages.join("__init__.py"), "").expect("a module");
    assert!(!stages_incompletely(&root, interpreter));
    std::fs::remove_file(binaries.join("python.exe")).expect("a removed interpreter");
    std::fs::hard_link(&cached, binaries.join("python.exe")).expect("a hardlinked interpreter");
    assert!(stages_incompletely(&root, interpreter));
    // An interpreter the environment does not have is not one to stage.
    assert!(stages_incompletely(&root, Path::new("Scripts/missing.exe")));
}

/// The command's first word may be a bare name an activated environment put
/// on `PATH`, with or without the extension the launcher was written under.
#[test]
fn resolves_a_launcher_named_without_a_path() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let root = canonical(directory.path()).expect("a canonical directory");
    let binaries = root.join(".venv/Scripts");
    std::fs::create_dir_all(&binaries).expect("a binaries directory");
    std::fs::write(binaries.join("pytest.exe"), b"MZ").expect("a launcher");
    std::fs::write(binaries.join("pytest"), "#!/bin/sh\n").expect("a shim");
    let search_path = binaries.to_string_lossy().into_owned();

    assert_eq!(
        resolved("pytest", &root, &search_path).expect("a resolved launcher"),
        canonical(&binaries.join("pytest")).expect("a canonical launcher")
    );
    assert_eq!(
        resolved("pytest.exe", &root, &search_path).expect("a resolved launcher"),
        canonical(&binaries.join("pytest.exe")).expect("a canonical launcher")
    );
    assert!(resolved("pytest", &root, "").is_none());
    assert!(resolved("missing", &root, &search_path).is_none());
    // A spelling that carries a path is read from the working directory, not
    // from the search path.
    assert!(resolved(r".venv\Scripts\pytest.exe", &root, "").is_some());
    assert!(resolved("pytest.exe", &root, "relative\\directory").is_none());
}

#[test]
fn reads_the_environment_a_launcher_belongs_to() {
    assert_eq!(
        environment_root(Path::new(r"C:\repo\.venv\Scripts\pytest.exe")),
        Some(PathBuf::from(r"C:\repo\.venv"))
    );
    assert_eq!(
        environment_root(Path::new(r"C:\repo\tools\pytest.exe")),
        None
    );
}

#[test]
fn refuses_a_writable_run() {
    let result = plan(&json!({"command": ["pytest"], "workspace": ".", "cwd": "."}))
        .expect_err("a read-only profile only");
    assert_eq!(result.reason_code, UNAVAILABLE);
}

#[test]
fn reports_a_refusal_as_a_resident_reason_code() {
    let value = prepare(&json!({"command": ["pytest"], "workspace": ".", "cwd": "."}));
    assert_eq!(value["reason_code"], json!(UNAVAILABLE));
    assert!(value.get("value").is_none());
}
