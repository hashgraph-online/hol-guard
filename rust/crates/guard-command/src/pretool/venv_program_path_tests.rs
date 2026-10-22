use super::environment_program;
use crate::pretool::PathContext;
use std::path::Path;

/// The fixture's own root, removed when the test ends. It reads as a path, so
/// the helpers below take the `&Path` they would take for any other place.
struct Fixture(tempfile::TempDir);

impl std::ops::Deref for Fixture {
    type Target = Path;

    fn deref(&self) -> &Path {
        self.0.path()
    }
}

/// macOS keeps the per-user temporary directory under `/private/var`, a
/// system root the location screen refuses for an interpreter outside the
/// working directory. A fixture there would have its base interpreter refused
/// for where the test put it rather than for what it is, so POSIX fixtures
/// live under `/tmp` on every platform.
#[cfg(unix)]
fn fixture_parent() -> std::path::PathBuf {
    std::path::PathBuf::from("/tmp")
}

#[cfg(not(unix))]
fn fixture_parent() -> std::path::PathBuf {
    std::env::temp_dir()
}

fn root(name: &str) -> Fixture {
    let holder = tempfile::Builder::new()
        .prefix(&format!("venv-program-{name}-"))
        .tempdir_in(fixture_parent())
        .unwrap();
    let root = holder.path();
    std::fs::create_dir_all(root.join("project/.venv/bin")).unwrap();
    std::fs::create_dir_all(root.join("base")).unwrap();
    Fixture(holder)
}

fn mark(root: &Path) {
    std::fs::write(
        root.join("project/.venv/pyvenv.cfg"),
        format!("home = {}\nversion = 3.12.0\n", root.join("base").display()),
    )
    .unwrap();
}

/// A file written straight into the environment's `bin`, the way a session
/// that plants one does.
fn program(root: &Path, marked: bool, name: &str) {
    if marked {
        mark(root);
    }
    std::fs::write(
        root.join("project/.venv/bin").join(name),
        "#!/bin/sh\nexit 0\n",
    )
    .unwrap();
}

/// The environment's own entry: a link to the base interpreter it was built
/// from, which is what `venv`, `virtualenv` and `uv` write.
#[cfg(unix)]
fn linked(root: &Path, marked: bool, name: &str, base: &Path) {
    if marked {
        mark(root);
    }
    if let Some(parent) = base.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(base, "#!/bin/sh\nexit 0\n").unwrap();
    std::os::unix::fs::symlink(base, root.join("project/.venv/bin").join(name)).unwrap();
}

fn proven(root: &Path, executable: &str) -> bool {
    proven_from(root, &root.join("project"), executable)
}

fn proven_from(root: &Path, cwd: &Path, executable: &str) -> bool {
    let home = root.to_str().unwrap().to_owned();
    let cwd = cwd.to_str().unwrap().to_owned();
    environment_program(
        executable,
        PathContext {
            home_dir: Some(&home),
            cwd: Some(&cwd),
            ..Default::default()
        },
    )
}

#[cfg(unix)]
#[test]
fn a_marked_environments_own_interpreter_is_proven() {
    let root = root("marked");
    let base = root.join("base/python3.12");
    linked(&root, true, "python", &base);
    assert!(proven(&root, ".venv/bin/python"));
}

#[cfg(unix)]
#[test]
fn a_directory_dressed_as_an_environment_is_not() {
    let root = root("unmarked");
    let base = root.join("base/python3.12");
    linked(&root, false, "python", &base);
    assert!(!proven(&root, ".venv/bin/python"));
}

/// The marker says the directory is an environment. It says nothing about
/// which program a file in its `bin` runs, and the floor judges the command
/// by that file's name, so a name that is not the interpreter's would inherit
/// the verdict of a program on `PATH` it is not.
#[cfg(unix)]
#[test]
fn a_program_that_is_not_the_interpreter_keeps_its_review() {
    let root = root("basename");
    let base = root.join("base/busybox");
    linked(&root, true, "ls", &base);
    assert!(!proven(&root, ".venv/bin/ls"));
}

/// An environment's interpreter is a link to the base one it was built from.
/// A file written at that name resolves to itself, inside the environment the
/// session writes, and proves nothing about what runs.
#[test]
fn a_script_written_into_the_environment_is_not_its_interpreter() {
    let root = root("planted");
    program(&root, true, "python");
    assert!(!proven(&root, ".venv/bin/python"));
}

/// The working directory is where the session writes without review, so an
/// interpreter the link reaches there is the same planted file one step out.
#[cfg(unix)]
#[test]
fn an_interpreter_inside_the_working_directory_is_not_proven() {
    let root = root("worktree");
    let base = root.join("project/tools/python3.12");
    linked(&root, true, "python", &base);
    assert!(!proven(&root, ".venv/bin/python"));
}

#[cfg(unix)]
#[test]
fn a_file_beside_the_environment_is_not_one_of_its_programs() {
    let root = root("beside");
    let base = root.join("base/python3.12");
    linked(&root, true, "python", &base);
    std::os::unix::fs::symlink(&base, root.join("project/.venv/python")).unwrap();
    assert!(!proven(&root, ".venv/python"));
}

#[cfg(unix)]
#[test]
fn a_name_the_environment_does_not_hold_is_not_proven() {
    let root = root("absent");
    let base = root.join("base/python3.12");
    linked(&root, true, "python", &base);
    assert!(!proven(&root, ".venv/bin/python3"));
}

#[cfg(unix)]
#[test]
fn a_parent_component_is_not_a_spelling_this_rule_proves() {
    // Nothing downstream reads the word again, so the rule refuses a spelling
    // whose meaning depends on where the shell starts rather than resolving it.
    let root = root("parent");
    let base = root.join("base/python3.12");
    linked(&root, true, "python", &base);
    assert!(!proven(&root, ".venv/bin/../bin/python"));
}

#[cfg(unix)]
#[test]
fn a_glob_is_not_a_spelling_this_rule_proves() {
    let root = root("glob");
    let base = root.join("base/python3.12");
    linked(&root, true, "python", &base);
    assert!(!proven(&root, ".venv/bin/pyth*n"));
}

/// A virtualenv links its interpreter to the base one it was built from, and
/// the environment's own name for it is the link, not the target.
#[cfg(unix)]
#[test]
fn the_interpreter_link_an_environment_writes_leads_to_its_base() {
    let root = root("linked");
    let base = root.join("base/python3.12");
    linked(&root, true, "python3.12", &base);
    std::os::unix::fs::symlink(&base, root.join("project/.venv/bin/python")).unwrap();
    assert!(proven(&root, ".venv/bin/python"));
    assert!(proven(&root, ".venv/bin/python3.12"));
}

/// `~` is the shell's own name for the real home, and a relative root
/// resolves the spelling against Guard's working directory rather than the
/// command's, so a context without absolute roots proves nothing.
#[cfg(unix)]
#[test]
fn a_context_without_absolute_roots_proves_nothing() {
    let root = root("context");
    let base = root.join("base/python3.12");
    linked(&root, true, "python", &base);
    let cwd = root.join("project").to_str().unwrap().to_owned();
    for home in [None, Some("relative/home")] {
        assert!(!environment_program(
            ".venv/bin/python",
            PathContext {
                home_dir: home,
                cwd: Some(&cwd),
                ..Default::default()
            }
        ));
    }
}

/// The link is the environment's own shape, so only where it lands separates
/// the interpreter it was built from any other program on the machine.
#[cfg(unix)]
#[test]
fn a_link_that_reaches_another_program_is_refused() {
    let root = root("other-program");
    linked(&root, true, "python", &root.join("base/rm"));

    assert!(!proven(&root, ".venv/bin/python"));
}

/// A session writes anywhere in its checkout without a review, so a link that
/// leaves the working directory but stays in the tree still reaches a file
/// this session chose.
#[cfg(unix)]
#[test]
fn a_link_that_reaches_the_checkout_around_the_command_is_refused() {
    let root = root("checkout-reach");
    std::fs::create_dir_all(root.join("project/.git")).unwrap();
    std::fs::create_dir_all(root.join("project/packages/api")).unwrap();
    linked(&root, true, "python", &root.join("project/tools/python"));

    let spelling = root.join("project/.venv/bin/python");
    assert!(!proven_from(
        &root,
        &root.join("project/packages/api"),
        spelling.to_str().unwrap(),
    ));
}

/// The same checkout, with the link landing outside it: this is the ordinary
/// environment a project builds against an interpreter installed elsewhere.
#[cfg(unix)]
#[test]
fn a_link_that_leaves_the_checkout_is_still_the_environments_own() {
    let root = root("checkout-leave");
    std::fs::create_dir_all(root.join("project/.git")).unwrap();
    std::fs::create_dir_all(root.join("project/packages/api")).unwrap();
    linked(&root, true, "python", &root.join("base/python3.12"));

    let spelling = root.join("project/.venv/bin/python");
    assert!(proven_from(
        &root,
        &root.join("project/packages/api"),
        spelling.to_str().unwrap(),
    ));
}
